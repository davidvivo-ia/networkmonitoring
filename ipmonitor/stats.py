"""Thread-safe aggregation of packet metadata (totals, rates, top-talkers, geo)."""

from __future__ import annotations

import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Set, Tuple


@dataclass
class PacketRecord:
    ts: float
    src: str
    dst: str
    proto: str
    sport: int
    dport: int
    length: int


@dataclass
class FlowStats:
    packets: int = 0
    bytes: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0


@dataclass
class CountryStats:
    country: str
    country_code: str
    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    unique_ips: Set[str] = field(default_factory=set)


class StatsAggregator:
    """Lock-protected counters for the live dashboard.

    Geolocation is associated with each packet at record-time by the caller
    (so we keep this module independent of the resolver implementation).
    """

    def __init__(self, history_seconds: int = 30, recent_size: int = 200):
        self._lock = threading.Lock()
        self.start_ts = time.time()
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts: Counter = Counter()
        self.protocol_bytes: Counter = Counter()
        self.src_ip_counts: Counter = Counter()
        self.dst_ip_counts: Counter = Counter()
        self.src_ip_bytes: Counter = Counter()
        self.dst_ip_bytes: Counter = Counter()
        self.dst_port_counts: Counter = Counter()
        self.src_port_counts: Counter = Counter()
        self.country_stats: Dict[str, CountryStats] = {}
        self.flows: Dict[Tuple[str, str, str, int], FlowStats] = {}
        self.recent: Deque[PacketRecord] = deque(maxlen=recent_size)
        self.unique_ips: Set[str] = set()
        self._byte_window: Deque[Tuple[float, int]] = deque()
        self._packet_window: Deque[Tuple[float, int]] = deque()
        self.history_seconds = history_seconds

    # ------------------------------------------------------------- recording

    def record(
        self,
        pkt: PacketRecord,
        src_geo: Optional[Any] = None,
        dst_geo: Optional[Any] = None,
    ) -> None:
        with self._lock:
            self.total_packets += 1
            self.total_bytes += pkt.length
            self.protocol_counts[pkt.proto] += 1
            self.protocol_bytes[pkt.proto] += pkt.length

            self.src_ip_counts[pkt.src] += 1
            self.dst_ip_counts[pkt.dst] += 1
            self.src_ip_bytes[pkt.src] += pkt.length
            self.dst_ip_bytes[pkt.dst] += pkt.length
            if pkt.dport:
                self.dst_port_counts[pkt.dport] += 1
            if pkt.sport:
                self.src_port_counts[pkt.sport] += 1

            self.unique_ips.add(pkt.src)
            self.unique_ips.add(pkt.dst)
            self.recent.appendleft(pkt)

            key = (pkt.src, pkt.dst, pkt.proto, pkt.dport)
            f = self.flows.get(key)
            if f is None:
                f = FlowStats(first_seen=pkt.ts)
                self.flows[key] = f
            f.packets += 1
            f.bytes += pkt.length
            f.last_seen = pkt.ts

            if src_geo is not None and getattr(src_geo, "country_code", "??") != "??":
                cs = self.country_stats.setdefault(
                    src_geo.country_code,
                    CountryStats(
                        country=src_geo.country, country_code=src_geo.country_code
                    ),
                )
                cs.packets_in += 1
                cs.bytes_in += pkt.length
                cs.unique_ips.add(pkt.src)
            if dst_geo is not None and getattr(dst_geo, "country_code", "??") != "??":
                cs = self.country_stats.setdefault(
                    dst_geo.country_code,
                    CountryStats(
                        country=dst_geo.country, country_code=dst_geo.country_code
                    ),
                )
                cs.packets_out += 1
                cs.bytes_out += pkt.length
                cs.unique_ips.add(pkt.dst)

            self._byte_window.append((pkt.ts, pkt.length))
            self._packet_window.append((pkt.ts, 1))
            self._trim_windows(pkt.ts)

    def _trim_windows(self, now: float) -> None:
        cutoff = now - self.history_seconds
        while self._byte_window and self._byte_window[0][0] < cutoff:
            self._byte_window.popleft()
        while self._packet_window and self._packet_window[0][0] < cutoff:
            self._packet_window.popleft()

    # --------------------------------------------------------------- queries

    def rates(self) -> Tuple[float, float]:
        now = time.time()
        with self._lock:
            self._trim_windows(now)
            window = max(1.0, min(float(self.history_seconds), now - self.start_ts))
            bps = sum(b for _, b in self._byte_window) / window
            pps = sum(p for _, p in self._packet_window) / window
        return bps, pps

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            countries: List[Dict[str, Any]] = [
                {
                    "country": cs.country,
                    "country_code": cs.country_code,
                    "packets_in": cs.packets_in,
                    "packets_out": cs.packets_out,
                    "bytes_in": cs.bytes_in,
                    "bytes_out": cs.bytes_out,
                    "unique_ips": len(cs.unique_ips),
                    "total_packets": cs.packets_in + cs.packets_out,
                    "total_bytes": cs.bytes_in + cs.bytes_out,
                }
                for cs in self.country_stats.values()
            ]
            return {
                "start_ts": self.start_ts,
                "elapsed": time.time() - self.start_ts,
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "unique_ips": len(self.unique_ips),
                "protocol_counts": dict(self.protocol_counts),
                "protocol_bytes": dict(self.protocol_bytes),
                "top_src": self.src_ip_counts.most_common(20),
                "top_dst": self.dst_ip_counts.most_common(20),
                "top_src_bytes": self.src_ip_bytes.most_common(20),
                "top_dst_bytes": self.dst_ip_bytes.most_common(20),
                "top_dport": self.dst_port_counts.most_common(15),
                "top_sport": self.src_port_counts.most_common(15),
                "countries": countries,
                "flows": [
                    {
                        "src": k[0],
                        "dst": k[1],
                        "proto": k[2],
                        "dport": k[3],
                        "packets": v.packets,
                        "bytes": v.bytes,
                        "first_seen": v.first_seen,
                        "last_seen": v.last_seen,
                    }
                    for k, v in self.flows.items()
                ],
                "recent": list(self.recent),
            }
