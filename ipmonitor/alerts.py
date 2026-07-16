"""Simple, configurable alerting for suspicious traffic patterns.

Rules supported out of the box:
  * ``block_countries``  — packets to/from a listed ISO country code.
  * ``block_ports``      — connections to a listed destination port.
  * ``new_country``      — first packet ever seen to/from a country.
  * ``rate_bytes``       — throughput crosses configurable threshold.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Deque, Iterable, List, Optional


@dataclass
class Alert:
    ts: float
    severity: str   # "info" | "warn" | "crit"
    rule: str
    message: str


class AlertEngine:
    _DEDUP_WINDOW = 5.0

    def __init__(
        self,
        block_countries: Optional[Iterable[str]] = None,
        block_ports: Optional[Iterable[int]] = None,
        rate_bytes_per_sec: Optional[float] = None,
        notify_new_country: bool = True,
        maxlen: int = 250,
    ):
        self.block_countries = {c.upper() for c in (block_countries or ())}
        self.block_ports = {int(p) for p in (block_ports or ())}
        self.rate_bytes_per_sec = float(rate_bytes_per_sec) if rate_bytes_per_sec else None
        self.notify_new_country = notify_new_country
        self._seen_countries: set = set()
        self._alerts: Deque[Alert] = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._last_rate_ts = 0.0

    # ------------------------------------------------------------ evaluation

    def evaluate_packet(self, pkt, src_geo, dst_geo) -> None:
        ts = pkt.ts
        for direction, geo in (("origen", src_geo), ("destino", dst_geo)):
            if geo is None or getattr(geo, "country_code", "??") == "??":
                continue
            cc = geo.country_code.upper()
            country = geo.country or cc
            if cc in self.block_countries:
                self._push(
                    ts, "crit", "block_country",
                    f"Bloqueado por país: {country} ({cc}) — {pkt.src} → {pkt.dst}",
                )
            elif self.notify_new_country and cc not in self._seen_countries:
                self._seen_countries.add(cc)
                self._push(
                    ts, "info", "new_country",
                    f"Nuevo país en {direction}: {country} ({cc})",
                )
            else:
                self._seen_countries.add(cc)
        if pkt.dport and pkt.dport in self.block_ports:
            self._push(
                ts, "warn", "block_port",
                f"Puerto vigilado {pkt.dport}: {pkt.src} → {pkt.dst}",
            )

    def evaluate_rate(self, bps: float) -> None:
        if not self.rate_bytes_per_sec:
            return
        now = time.time()
        if bps <= self.rate_bytes_per_sec:
            return
        if now - self._last_rate_ts < 10:
            return
        self._last_rate_ts = now
        self._push(
            now, "warn", "rate_spike",
            f"Ancho de banda {int(bps):,} B/s supera umbral "
            f"{int(self.rate_bytes_per_sec):,} B/s",
        )

    # ------------------------------------------------------------ accessors

    def recent(self, n: int = 8) -> List[Alert]:
        with self._lock:
            return list(self._alerts)[:n]

    def all(self) -> List[Alert]:
        with self._lock:
            return list(self._alerts)

    def _push(self, ts: float, severity: str, rule: str, message: str) -> None:
        with self._lock:
            for a in list(self._alerts)[:10]:
                if (a.rule == rule and a.message == message
                        and ts - a.ts < self._DEDUP_WINDOW):
                    return
            self._alerts.appendleft(
                Alert(ts=ts, severity=severity, rule=rule, message=message)
            )
