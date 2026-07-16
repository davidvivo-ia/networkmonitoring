"""Thread-safe aggregation of packet metadata.

Tracks totals, rates, top-talkers, per-country/continent aggregation, per-ASN
counters, per-hostname and per-process counters, plus a rolling bandwidth
history used to render sparklines.
"""

from __future__ import annotations

import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

from .continents import continent_for


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


@dataclass
class ContinentStats:
    continent: str
    name: str
    emoji: str
    packets: int = 0
    bytes: int = 0
    countries: Set[str] = field(default_factory=set)


class StatsAggregator:
    HISTORY_BUCKET_SECONDS = 1.0
    HISTORY_BUCKETS = 60

    def __init__(self, history_seconds: int = 30, recent_size: int = 300):
        self._lock = threading.Lock()
        self.start_ts = time.time()

        # totals -----------------------------------------------------------
        self.total_packets = 0
        self.total_bytes = 0
        self.dropped_pdu = 0

        # per-protocol -----------------------------------------------------
        self.protocol_counts: Counter = Counter()
        self.protocol_bytes: Counter = Counter()

        # per-endpoint -----------------------------------------------------
        self.src_ip_counts: Counter = Counter()
        self.dst_ip_counts: Counter = Counter()
        self.src_ip_bytes: Counter = Counter()
        self.dst_ip_bytes: Counter = Counter()
        self.dst_port_counts: Counter = Counter()
        self.src_port_counts: Counter = Counter()

        # geo --------------------------------------------------------------
        self.country_stats: Dict[str, CountryStats] = {}
        self.continent_stats: Dict[str, ContinentStats] = {}
        self.asn_counts: Counter = Counter()
        self.asn_bytes: Counter = Counter()

        # l7 / apps --------------------------------------------------------
        self.hostname_counts: Counter = Counter()
        self.hostname_bytes: Counter = Counter()
        self.process_counts: Counter = Counter()
        self.process_bytes: Counter = Counter()

        # flows + recent ---------------------------------------------------
        self.flows: Dict[Tuple[str, str, str, int], FlowStats] = {}
        self.recent: Deque[Dict[str, Any]] = deque(maxlen=recent_size)
        self.unique_ips: Set[str] = set()

        # rolling windows --------------------------------------------------
        self.history_seconds = history_seconds
        self._byte_window: Deque[Tuple[float, int]] = deque()
        self._packet_window: Deque[Tuple[float, int]] = deque()

        # sparkline history: bucketized per second -------------------------
        self._history_bytes: Deque[int] = deque(maxlen=self.HISTORY_BUCKETS)
        self._history_packets: Deque[int] = deque(maxlen=self.HISTORY_BUCKETS)
        self._history_bucket_ts: float = 0.0

    # ----------------------------------------------------------- recording

    def record(
        self,
        pkt: PacketRecord,
        src_geo: Optional[Any] = None,
        dst_geo: Optional[Any] = None,
        hostname: Optional[str] = None,
        process: Optional[Tuple[int, str]] = None,
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

            key = (pkt.src, pkt.dst, pkt.proto, pkt.dport)
            f = self.flows.get(key)
            if f is None:
                f = FlowStats(first_seen=pkt.ts)
                self.flows[key] = f
            f.packets += 1
            f.bytes += pkt.length
            f.last_seen = pkt.ts

            self._account_geo(pkt, src_geo, dst_geo)

            if hostname:
                self.hostname_counts[hostname] += 1
                self.hostname_bytes[hostname] += pkt.length

            if process:
                pid, pname = process
                key_p = f"{pname} [{pid}]"
                self.process_counts[key_p] += 1
                self.process_bytes[key_p] += pkt.length

            self.recent.appendleft({
                "ts": pkt.ts, "src": pkt.src, "dst": pkt.dst,
                "proto": pkt.proto, "sport": pkt.sport, "dport": pkt.dport,
                "length": pkt.length,
                "hostname": hostname or "",
                "process": process[1] if process else "",
                "cc_src": getattr(src_geo, "country_code", "") if src_geo else "",
                "cc_dst": getattr(dst_geo, "country_code", "") if dst_geo else "",
            })

            self._byte_window.append((pkt.ts, pkt.length))
            self._packet_window.append((pkt.ts, 1))
            self._trim_windows(pkt.ts)
            self._push_history(pkt.ts, pkt.length)

    # --------------------------------------------------------- geo helpers

    def _account_geo(self, pkt, src_geo, dst_geo) -> None:
        for geo, is_dst in ((src_geo, False), (dst_geo, True)):
            if geo is None or getattr(geo, "country_code", "??") == "??":
                continue
            cc = geo.country_code
            cs = self.country_stats.setdefault(
                cc, CountryStats(country=geo.country, country_code=cc)
            )
            if is_dst:
                cs.packets_out += 1
                cs.bytes_out += pkt.length
                cs.unique_ips.add(pkt.dst)
            else:
                cs.packets_in += 1
                cs.bytes_in += pkt.length
                cs.unique_ips.add(pkt.src)

            cont, cname, emoji = continent_for(cc)
            ct = self.continent_stats.setdefault(
                cont, ContinentStats(continent=cont, name=cname, emoji=emoji)
            )
            ct.packets += 1
            ct.bytes += pkt.length
            ct.countries.add(cc)

            asn = getattr(geo, "asn", "") or ""
            if asn:
                self.asn_counts[asn] += 1
                self.asn_bytes[asn] += pkt.length

    def _trim_windows(self, now: float) -> None:
        cutoff = now - self.history_seconds
        while self._byte_window and self._byte_window[0][0] < cutoff:
            self._byte_window.popleft()
        while self._packet_window and self._packet_window[0][0] < cutoff:
            self._packet_window.popleft()

    def _push_history(self, now: float, length: int) -> None:
        bucket = int(now // self.HISTORY_BUCKET_SECONDS)
        if self._history_bucket_ts == 0.0:
            self._history_bucket_ts = bucket
            self._history_bytes.append(0)
            self._history_packets.append(0)
        while self._history_bucket_ts < bucket:
            self._history_bucket_ts += 1
            self._history_bytes.append(0)
            self._history_packets.append(0)
        self._history_bytes[-1] += length
        self._history_packets[-1] += 1

    # ----------------------------------------------------------- accessors

    def rates(self) -> Tuple[float, float]:
        now = time.time()
        with self._lock:
            self._trim_windows(now)
            window = max(1.0, min(float(self.history_seconds), now - self.start_ts))
            bps = sum(b for _, b in self._byte_window) / window
            pps = sum(p for _, p in self._packet_window) / window
        return bps, pps

    def history(self) -> Tuple[List[int], List[int]]:
        with self._lock:
            return list(self._history_bytes), list(self._history_packets)

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
            continents = [
                {
                    "continent": ct.continent, "name": ct.name, "emoji": ct.emoji,
                    "packets": ct.packets, "bytes": ct.bytes,
                    "countries": len(ct.countries),
                }
                for ct in self.continent_stats.values()
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
                "top_hosts": self.hostname_bytes.most_common(15),
                "top_hosts_pkts": self.hostname_counts.most_common(15),
                "top_asn": self.asn_bytes.most_common(10),
                "top_procs_bytes": self.process_bytes.most_common(12),
                "top_procs_pkts": self.process_counts.most_common(12),
                "countries": countries,
                "continents": continents,
                "flows": [
                    {
                        "src": k[0], "dst": k[1], "proto": k[2], "dport": k[3],
                        "packets": v.packets, "bytes": v.bytes,
                        "first_seen": v.first_seen, "last_seen": v.last_seen,
                    }
                    for k, v in self.flows.items()
                ],
                "recent": list(self.recent),
            }
