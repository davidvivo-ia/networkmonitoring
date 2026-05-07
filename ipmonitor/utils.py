"""Helpers: private-IP detection, byte/rate formatting, country flags, ports."""

from __future__ import annotations

import ipaddress
from typing import Optional

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
]


def is_private_ip(ip: str) -> bool:
    if not ip:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(addr in net for net in _PRIVATE_NETS)


def format_bytes(n: float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return f"{n:,.1f} {unit}"
        n /= 1024.0
    return f"{n:,.1f} PB"


def format_rate(bps: float) -> str:
    return format_bytes(bps) + "/s"


def country_flag(country_code: Optional[str]) -> str:
    if not country_code or len(country_code) != 2:
        return "\U0001F3F3️"
    cc = country_code.upper()
    if not cc.isalpha():
        return "\U0001F3F3️"
    base = 0x1F1E6
    return chr(base + ord(cc[0]) - ord("A")) + chr(base + ord(cc[1]) - ord("A"))


_PORT_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
    110: "pop3", 119: "nntp", 123: "ntp", 143: "imap", 161: "snmp",
    179: "bgp", 194: "irc", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 514: "syslog", 587: "submission", 631: "ipp",
    636: "ldaps", 853: "dns-tls", 873: "rsync", 993: "imaps",
    995: "pop3s", 1080: "socks", 1194: "openvpn", 1433: "mssql",
    1521: "oracle", 1701: "l2tp", 1723: "pptp", 1812: "radius",
    1900: "ssdp", 2049: "nfs", 2082: "cpanel", 2222: "ssh-alt",
    3128: "http-proxy", 3306: "mysql", 3389: "rdp", 3478: "stun",
    4500: "ipsec-nat", 5000: "upnp", 5060: "sip", 5061: "sips",
    5222: "xmpp", 5228: "google-fcm", 5353: "mdns", 5432: "postgres",
    5683: "coap", 5900: "vnc", 6379: "redis", 6443: "k8s-api",
    6667: "irc", 8080: "http-alt", 8443: "https-alt", 8883: "mqtt-tls",
    9000: "sonarqube", 9090: "prometheus", 9092: "kafka",
    9200: "elasticsearch", 11211: "memcached", 19302: "stun",
    27017: "mongodb", 51820: "wireguard",
}


def service_name(port: int) -> str:
    if not port:
        return "-"
    return _PORT_SERVICES.get(port, "")
