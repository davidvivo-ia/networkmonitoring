"""Live packet capture engine built on scapy's AsyncSniffer."""

from __future__ import annotations

import time
from typing import Callable, List, Optional, Tuple

from .stats import PacketRecord

try:
    from scapy.all import AsyncSniffer, ICMP, IP, IPv6, TCP, UDP  # type: ignore

    _HAVE_SCAPY = True
except BaseException:  # pragma: no cover
    _HAVE_SCAPY = False


HAVE_SCAPY = _HAVE_SCAPY

_PROTO_MAP = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6",
    47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF",
    103: "PIM", 132: "SCTP",
}

PacketCallback = Callable[[PacketRecord, "object"], None]


class CaptureEngine:
    """AsyncSniffer wrapper emitting (record, raw_pkt) to each consumer."""

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        on_packet: Optional[PacketCallback] = None,
        promisc: bool = True,
    ):
        if not HAVE_SCAPY:
            raise RuntimeError(
                "scapy is not installed. Install with: pip install scapy"
            )
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.on_packet = on_packet
        self.promisc = promisc
        self._sniffer: Optional["AsyncSniffer"] = None  # type: ignore[name-defined]

    # ------------------------------------------------------------------ run

    def _parse(self, pkt) -> Optional[PacketRecord]:
        try:
            ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
        except Exception:
            ts = time.time()
        try:
            length = len(pkt)
        except Exception:
            length = 0
        try:
            if IP in pkt:
                ip = pkt[IP]
                src, dst = ip.src, ip.dst
                proto_num = int(ip.proto)
            elif IPv6 in pkt:
                ip = pkt[IPv6]
                src, dst = ip.src, ip.dst
                proto_num = int(ip.nh)
            else:
                return None
        except Exception:
            return None

        sport = dport = 0
        try:
            if TCP in pkt:
                proto = "TCP"
                sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
            elif UDP in pkt:
                proto = "UDP"
                sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
            elif ICMP in pkt:
                proto = "ICMP"
            else:
                proto = _PROTO_MAP.get(proto_num, f"IP/{proto_num}")
        except Exception:
            proto = "?"

        return PacketRecord(
            ts=ts, src=src, dst=dst, proto=proto,
            sport=sport, dport=dport, length=length,
        )

    def _handle(self, pkt) -> None:  # pragma: no cover (needs live capture)
        rec = self._parse(pkt)
        if rec is None or self.on_packet is None:
            return
        try:
            self.on_packet(rec, pkt)
        except Exception:
            return

    def start(self) -> None:
        kwargs = {"prn": self._handle, "store": False}
        if self.interface:
            kwargs["iface"] = self.interface
        if self.bpf_filter:
            kwargs["filter"] = self.bpf_filter
        # AsyncSniffer accepts promisc on POSIX; Windows/Npcap default is fine.
        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None

    # ----------------------------------------------------------- introspection

    @staticmethod
    def list_interfaces() -> List[str]:
        if not HAVE_SCAPY:
            return []
        try:
            from scapy.arch import get_if_list  # type: ignore
            return list(get_if_list())
        except Exception:
            return []

    @staticmethod
    def list_interfaces_detailed() -> List[dict]:
        if not HAVE_SCAPY:
            return []
        import sys
        if sys.platform == "win32":
            try:
                from scapy.arch.windows import get_windows_if_list  # type: ignore
                out = []
                for d in get_windows_if_list():
                    out.append({
                        "name": d.get("name") or d.get("description") or "",
                        "description": d.get("description") or "",
                        "ips": d.get("ips") or [],
                        "mac": d.get("mac") or "",
                        "guid": d.get("guid") or "",
                    })
                return out
            except Exception:
                pass
        try:
            from scapy.config import conf  # type: ignore
            out = []
            for nic in getattr(conf, "ifaces", {}).values():
                ips = []
                for attr in ("ips", "ip", "ip4"):
                    val = getattr(nic, attr, None)
                    if isinstance(val, list):
                        ips.extend(str(v) for v in val)
                    elif isinstance(val, str) and val:
                        ips.append(val)
                out.append({
                    "name": getattr(nic, "name", "") or getattr(nic, "network_name", ""),
                    "description": getattr(nic, "description", "") or "",
                    "ips": ips,
                    "mac": getattr(nic, "mac", "") or "",
                    "guid": getattr(nic, "guid", "") or "",
                })
            if out:
                return out
        except Exception:
            pass
        return [{"name": n, "description": "", "ips": [], "mac": "", "guid": ""}
                for n in CaptureEngine.list_interfaces()]
