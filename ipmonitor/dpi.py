"""Best-effort L7 extraction: TLS SNI (443), HTTP Host, DNS A/AAAA answers.

All parsing is defensive: on any exception we simply return an empty dict.
The goal is *hints* for the UI, never a correctness-critical path.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple


def extract(pkt: Any, proto: str, dport: int, sport: int) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    raw = _payload(pkt)

    if raw and proto == "TCP":
        if dport == 443:
            sni = _parse_tls_sni(raw)
            if sni:
                out["sni"] = sni
        if dport in (80, 8000, 8080, 8888):
            host = _parse_http_host(raw)
            if host:
                out["http_host"] = host

    pairs = _parse_dns_answers(pkt) if (proto == "UDP" and (sport == 53 or dport == 53)) else []
    if pairs:
        out["dns_pairs"] = pairs
    return out


def _payload(pkt: Any) -> bytes:
    try:
        from scapy.all import Raw  # type: ignore
    except BaseException:
        return b""
    try:
        if Raw in pkt:
            return bytes(pkt[Raw].load)
    except Exception:
        pass
    return b""


def _parse_tls_sni(data: bytes) -> str:
    """Parse the SNI from a TLS ClientHello record (RFC 6066 §3).

    Layout:
      TLSPlaintext:  type(1)=0x16 | version(2) | length(2) | fragment
      Handshake:     type(1)=0x01 (ClientHello) | length(3) | body
      ClientHello:   client_version(2) | random(32) | sid_len(1)+sid |
                     cs_len(2)+cs | cm_len(1)+cm | ext_len(2)+extensions
      SNI ext (0x0000): ext_len(2) | list_len(2) | name_type(1) | name_len(2) | name
    """
    try:
        if len(data) < 43 or data[0] != 0x16 or data[5] != 0x01:
            return ""
        p = 9              # skip TLSPlaintext + handshake header
        p += 2 + 32        # client_version + random
        if p >= len(data):
            return ""
        p += 1 + data[p]                                     # session_id
        cs_len = int.from_bytes(data[p:p + 2], "big"); p += 2 + cs_len
        if p >= len(data):
            return ""
        p += 1 + data[p]                                     # compression_methods
        if p + 2 > len(data):
            return ""
        ext_total = int.from_bytes(data[p:p + 2], "big"); p += 2
        end = min(len(data), p + ext_total)
        while p + 4 <= end:
            et = int.from_bytes(data[p:p + 2], "big"); p += 2
            el = int.from_bytes(data[p:p + 2], "big"); p += 2
            if et == 0x0000 and p + 5 <= end:
                # SNI extension: list_len(2) + name_type(1) + name_len(2) + name
                sp = p + 2
                nt = data[sp]; sp += 1
                nl = int.from_bytes(data[sp:sp + 2], "big"); sp += 2
                if nt == 0 and sp + nl <= end:
                    return data[sp:sp + nl].decode("ascii", errors="replace")
                return ""
            p += el
    except Exception:
        return ""
    return ""


def _parse_http_host(data: bytes) -> str:
    """Best-effort HTTP/1.x Host: header extraction."""
    try:
        head = data[:32].upper()
        if not any(head.startswith(m) for m in (
            b"GET ", b"POST", b"HEAD", b"PUT ", b"OPTI", b"DELE", b"PATC", b"CONN"
        )):
            return ""
        low = data.lower()
        idx = low.find(b"\r\nhost:")
        if idx == -1:
            return ""
        idx += len(b"\r\nhost:")
        end = data.find(b"\r\n", idx)
        if end == -1:
            end = len(data)
        return data[idx:end].strip().decode("ascii", errors="replace")
    except Exception:
        return ""


def _parse_dns_answers(pkt: Any) -> List[Tuple[str, str]]:
    """Return list of (hostname, ip) from A/AAAA answers in a DNS response."""
    try:
        from scapy.layers.dns import DNS, DNSRR  # type: ignore
    except BaseException:
        return []
    try:
        if DNS not in pkt:
            return []
        dns = pkt[DNS]
        if int(getattr(dns, "qr", 0)) != 1 or int(getattr(dns, "ancount", 0)) <= 0:
            return []
    except Exception:
        return []
    pairs: List[Tuple[str, str]] = []
    try:
        an = dns.an
        for _ in range(int(dns.ancount)):
            if an is None:
                break
            try:
                if isinstance(an, DNSRR) and int(an.type) in (1, 28):
                    name = an.rrname.decode("ascii", errors="replace").rstrip(".") \
                        if isinstance(an.rrname, (bytes, bytearray)) else str(an.rrname).rstrip(".")
                    rdata = an.rdata
                    ip = rdata if isinstance(rdata, str) else str(rdata)
                    if name and ip:
                        pairs.append((name, ip))
            except Exception:
                pass
            an = getattr(an, "payload", None)
    except Exception:
        pass
    return pairs
