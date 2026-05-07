"""GeoIP resolver: in-memory + persistent cache, optional MaxMind mmdb,
with ip-api.com batch fallback (free, no API key, ~45 lookups/min)."""

from __future__ import annotations

import json
import queue
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional

try:
    import geoip2.database  # type: ignore
    _HAVE_GEOIP2 = True
except ImportError:
    _HAVE_GEOIP2 = False

try:
    import requests  # type: ignore
    _HAVE_REQUESTS = True
except ImportError:
    _HAVE_REQUESTS = False


@dataclass
class GeoInfo:
    ip: str
    country: str = "Unknown"
    country_code: str = "??"
    city: str = ""
    region: str = ""
    isp: str = ""
    org: str = ""
    asn: str = ""
    lat: float = 0.0
    lon: float = 0.0
    resolved: bool = False


class GeoIPResolver:
    """Thread-safe IP -> GeoInfo resolver with caching.

    Resolution order:
      1. In-memory cache.
      2. Persistent JSON cache (loaded at startup, written periodically).
      3. MaxMind GeoLite2 mmdb (synchronous, offline) when --mmdb is provided.
      4. ip-api.com batch endpoint (asynchronous worker thread).

    For unresolved IPs, ``lookup`` returns a placeholder GeoInfo immediately
    and queues the IP for asynchronous resolution; subsequent calls will
    return the resolved entry once the worker has fetched it.
    """

    API_URL = "http://ip-api.com/batch"
    BATCH_SIZE = 100
    BATCH_INTERVAL = 1.5  # seconds; ip-api free tier ~45 req/min
    SAVE_EVERY = 50       # save persistent cache after N new resolutions

    def __init__(
        self,
        mmdb_path: Optional[str] = None,
        cache_path: Optional[str] = None,
        offline: bool = False,
    ):
        self._cache: Dict[str, GeoInfo] = {}
        self._lock = threading.Lock()
        self._queue: "queue.Queue[str]" = queue.Queue()
        self._stop = threading.Event()
        self._dirty = 0
        self.offline = offline or not _HAVE_REQUESTS
        self.cache_path = Path(cache_path).expanduser() if cache_path else None

        self.reader = None
        if mmdb_path and _HAVE_GEOIP2:
            p = Path(mmdb_path).expanduser()
            if p.exists():
                try:
                    self.reader = geoip2.database.Reader(str(p))
                except Exception:
                    self.reader = None

        self._load_cache()
        self._worker = threading.Thread(
            target=self._run, name="geoip-worker", daemon=True
        )
        self._worker.start()

    # ------------------------------------------------------------------ cache

    def _load_cache(self) -> None:
        if not self.cache_path or not self.cache_path.exists():
            return
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            for ip, info in data.items():
                try:
                    self._cache[ip] = GeoInfo(**info)
                except TypeError:
                    continue
        except Exception:
            pass

    def _save_cache(self) -> None:
        if not self.cache_path:
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            with self._lock:
                snapshot = {
                    ip: asdict(info)
                    for ip, info in self._cache.items()
                    if info.resolved
                }
            tmp = self.cache_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(snapshot), encoding="utf-8")
            tmp.replace(self.cache_path)
        except Exception:
            pass

    # --------------------------------------------------------------- public API

    def lookup(self, ip: str) -> Optional[GeoInfo]:
        if not ip:
            return None
        with self._lock:
            cached = self._cache.get(ip)
            if cached is not None:
                return cached

        if self.reader is not None:
            info = self._mmdb_lookup(ip)
            if info is not None:
                with self._lock:
                    self._cache[ip] = info
                    self._dirty += 1
                self._maybe_save()
                return info

        placeholder = GeoInfo(ip=ip, country="Resolving…", country_code="??")
        with self._lock:
            self._cache[ip] = placeholder
        if not self.offline:
            self._queue.put(ip)
        return placeholder

    def stop(self) -> None:
        self._stop.set()
        self._save_cache()
        if self.reader is not None:
            try:
                self.reader.close()
            except Exception:
                pass

    # ------------------------------------------------------------- resolution

    def _mmdb_lookup(self, ip: str) -> Optional[GeoInfo]:
        try:
            r = self.reader.city(ip)  # type: ignore[union-attr]
        except Exception:
            return None
        try:
            region = r.subdivisions.most_specific.name or "" if r.subdivisions else ""
        except Exception:
            region = ""
        return GeoInfo(
            ip=ip,
            country=r.country.name or "Unknown",
            country_code=r.country.iso_code or "??",
            city=r.city.name or "",
            region=region,
            lat=float(r.location.latitude or 0.0),
            lon=float(r.location.longitude or 0.0),
            resolved=True,
        )

    def _run(self) -> None:
        if self.offline:
            return
        while not self._stop.is_set():
            try:
                first = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            batch: List[str] = [first]
            while len(batch) < self.BATCH_SIZE:
                try:
                    batch.append(self._queue.get_nowait())
                except queue.Empty:
                    break
            self._resolve_batch(batch)
            # Pace the worker so we stay under ip-api.com free-tier limits.
            self._stop.wait(self.BATCH_INTERVAL)

    def _resolve_batch(self, ips: List[str]) -> None:
        if not ips:
            return
        unique = list(dict.fromkeys(ips))
        payload = [
            {
                "query": ip,
                "fields": "status,country,countryCode,regionName,city,"
                          "isp,org,as,lat,lon,query",
            }
            for ip in unique
        ]
        try:
            resp = requests.post(self.API_URL, json=payload, timeout=15)
        except Exception:
            return
        if resp.status_code != 200:
            return
        try:
            results = resp.json()
        except Exception:
            return

        with self._lock:
            for item in results:
                ip = item.get("query")
                if not ip:
                    continue
                if item.get("status") != "success":
                    self._cache[ip] = GeoInfo(
                        ip=ip, country="Unknown", country_code="??", resolved=True
                    )
                    self._dirty += 1
                    continue
                self._cache[ip] = GeoInfo(
                    ip=ip,
                    country=item.get("country") or "Unknown",
                    country_code=item.get("countryCode") or "??",
                    city=item.get("city") or "",
                    region=item.get("regionName") or "",
                    isp=item.get("isp") or "",
                    org=item.get("org") or "",
                    asn=item.get("as") or "",
                    lat=float(item.get("lat") or 0.0),
                    lon=float(item.get("lon") or 0.0),
                    resolved=True,
                )
                self._dirty += 1
        self._maybe_save()

    def _maybe_save(self) -> None:
        if self._dirty >= self.SAVE_EVERY:
            self._dirty = 0
            self._save_cache()
