"""IP <-> hostname registry.

Sources (in preference order):
  1. Passive DNS: A/AAAA answers sniffed from DNS responses.
  2. TLS SNI (443 ClientHello).
  3. HTTP Host header.
  4. Reverse DNS lookup (best effort, background thread).

A single IP can accumulate multiple observed hostnames; ``get`` returns the
most trustworthy one (DNS > SNI > HTTP > rDNS), all of them are exposed via
``all_for``.
"""

from __future__ import annotations

import queue
import socket
import threading
from collections import Counter
from typing import Dict, List, Optional, Set


class HostRegistry:
    _SRC_RANK = {"dns": 4, "sni": 3, "http": 2, "rdns": 1}

    def __init__(self, reverse_dns: bool = True, max_pending: int = 2048):
        self._lock = threading.Lock()
        self._by_ip: Dict[str, Dict[str, str]] = {}  # ip -> {source: name}
        self._hostname_hits: Counter = Counter()      # hostname -> packets
        self._hostname_bytes: Counter = Counter()     # hostname -> bytes
        self._pending: "queue.Queue[str]" = queue.Queue(maxsize=max_pending)
        self._queued: Set[str] = set()
        self._reverse_dns = reverse_dns
        self._stop = threading.Event()
        if reverse_dns:
            threading.Thread(target=self._run_rdns, name="rdns", daemon=True).start()

    # -------------------------------------------------------------- feeders

    def observe_dns(self, hostname: str, ip: str) -> None:
        self._observe(ip, hostname, "dns")

    def observe_sni(self, ip: str, sni: str) -> None:
        self._observe(ip, sni, "sni")

    def observe_http(self, ip: str, host: str) -> None:
        self._observe(ip, host, "http")

    def _observe(self, ip: str, name: str, src: str) -> None:
        if not ip or not name:
            return
        name = name.strip().lower()
        with self._lock:
            self._by_ip.setdefault(ip, {})[src] = name

    # --------------------------------------------------------------- queries

    def get(self, ip: str) -> str:
        with self._lock:
            recs = self._by_ip.get(ip)
            if recs:
                for src in ("dns", "sni", "http", "rdns"):
                    if src in recs and recs[src]:
                        return recs[src]
                return ""
        # Nothing known: enqueue rDNS lookup for next time.
        if self._reverse_dns:
            with self._lock:
                if ip not in self._queued:
                    self._queued.add(ip)
                    try:
                        self._pending.put_nowait(ip)
                    except queue.Full:
                        pass
        return ""

    def all_for(self, ip: str) -> List[str]:
        with self._lock:
            recs = self._by_ip.get(ip)
            if not recs:
                return []
            return sorted(
                {v for v in recs.values() if v},
                key=lambda n: -self._SRC_RANK.get(
                    next(k for k, val in recs.items() if val == n), 0
                ),
            )

    def account(self, hostname: str, length: int) -> None:
        if not hostname:
            return
        with self._lock:
            self._hostname_hits[hostname] += 1
            self._hostname_bytes[hostname] += length

    def top_hostnames(self, n: int = 12):
        with self._lock:
            return [
                {"host": h, "packets": p, "bytes": self._hostname_bytes.get(h, 0)}
                for h, p in self._hostname_hits.most_common(n)
            ]

    def snapshot(self):
        with self._lock:
            return {
                "known_ips": len(self._by_ip),
                "known_hosts": len({v for recs in self._by_ip.values()
                                    for v in recs.values() if v}),
                "top": self.top_hostnames(30),
            }

    # ------------------------------------------------------- reverse DNS

    def _run_rdns(self) -> None:
        socket.setdefaulttimeout(2.0)
        while not self._stop.is_set():
            try:
                ip = self._pending.get(timeout=0.5)
            except queue.Empty:
                continue
            name = ""
            try:
                name = socket.gethostbyaddr(ip)[0]
            except Exception:
                name = ""
            if name:
                self._observe(ip, name, "rdns")

    def stop(self) -> None:
        self._stop.set()
