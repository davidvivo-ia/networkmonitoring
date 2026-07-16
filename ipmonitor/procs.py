"""Process attribution: which local application produced a given packet.

Uses ``psutil.net_connections`` to snapshot open sockets, keyed by
``(local_ip, local_port, protocol)``. Refreshed periodically on a
background thread so lookups are lock-free-ish and cheap.
"""

from __future__ import annotations

import os
import threading
from typing import Dict, Iterable, Optional, Tuple

try:
    import psutil  # type: ignore

    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False


Key = Tuple[str, int, str]  # (ip, port, proto)


class ProcessMap:
    REFRESH_INTERVAL = 1.5

    def __init__(self, refresh: float = REFRESH_INTERVAL):
        self._lock = threading.Lock()
        self._by_local: Dict[Key, Tuple[int, str]] = {}
        self._by_port: Dict[Tuple[int, str], Tuple[int, str]] = {}
        self._stop = threading.Event()
        self._refresh = max(0.5, refresh)
        self.available = HAVE_PSUTIL
        if HAVE_PSUTIL:
            threading.Thread(
                target=self._run, name="procmap", daemon=True
            ).start()

    # -------------------------------------------------------------- refresh

    def _run(self) -> None:
        self._refresh_now()
        while not self._stop.is_set():
            self._refresh_now()
            self._stop.wait(self._refresh)

    def _refresh_now(self) -> None:
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            return
        except Exception:
            return
        by_local: Dict[Key, Tuple[int, str]] = {}
        by_port: Dict[Tuple[int, str], Tuple[int, str]] = {}
        name_cache: Dict[int, str] = {}
        for c in conns:
            if not c.laddr or not c.pid:
                continue
            proto = "TCP" if c.type == 1 else ("UDP" if c.type == 2 else "?")
            name = name_cache.get(c.pid)
            if name is None:
                try:
                    name = psutil.Process(c.pid).name()
                except Exception:
                    name = f"pid:{c.pid}"
                name_cache[c.pid] = name
            entry = (c.pid, name)
            by_local[(c.laddr.ip, c.laddr.port, proto)] = entry
            by_port.setdefault((c.laddr.port, proto), entry)
        with self._lock:
            self._by_local = by_local
            self._by_port = by_port

    # --------------------------------------------------------------- lookup

    def attribute(
        self,
        src: str,
        sport: int,
        dst: str,
        dport: int,
        proto: str,
        local_ips: Optional[Iterable[str]] = None,
    ) -> Optional[Tuple[int, str]]:
        """Return (pid, process name) if attributable, else None."""
        if not self.available:
            return None
        local = set(local_ips or ())
        candidates = []
        if src in local or not local:
            candidates.append((src, sport))
        if dst in local or not local:
            candidates.append((dst, dport))
        # Also try both endpoints if we don't know local IPs yet.
        if not candidates:
            candidates = [(src, sport), (dst, dport)]
        with self._lock:
            for ip, port in candidates:
                for k in ((ip, port, proto), ("0.0.0.0", port, proto), ("::", port, proto)):
                    hit = self._by_local.get(k)
                    if hit:
                        return hit
            for _, port in candidates:
                hit = self._by_port.get((port, proto))
                if hit:
                    return hit
        return None

    def stop(self) -> None:
        self._stop.set()


def local_interface_ips() -> "set[str]":
    """Best-effort list of IPs bound to this host."""
    ips: "set[str]" = set()
    if HAVE_PSUTIL:
        try:
            for name, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if a.family.name in ("AF_INET", "AF_INET6"):
                        ip = (a.address or "").split("%")[0]
                        if ip:
                            ips.add(ip)
        except Exception:
            pass
    if not ips:
        try:
            import socket
            for res in socket.getaddrinfo(socket.gethostname(), None):
                ips.add(res[4][0])
        except Exception:
            pass
    ips.update({"127.0.0.1", "::1", "0.0.0.0", "::"})
    return ips
