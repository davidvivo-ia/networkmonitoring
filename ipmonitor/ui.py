"""Rich-based live TUI dashboard for the IP packet monitor."""

from __future__ import annotations

import threading
import time
from datetime import datetime
from typing import Optional

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .geoip import GeoIPResolver
from .stats import StatsAggregator
from .utils import (
    country_flag,
    format_bytes,
    format_rate,
    is_private_ip,
    service_name,
)


class Dashboard:
    """Renders the live monitor UI using rich.Live."""

    def __init__(
        self,
        stats: StatsAggregator,
        geoip: GeoIPResolver,
        interface: str = "default",
        bpf_filter: Optional[str] = None,
        refresh_hz: float = 4.0,
    ):
        self.stats = stats
        self.geoip = geoip
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.refresh = max(0.1, 1.0 / refresh_hz)
        self.console = Console()
        self._stop = threading.Event()

    # --------------------------------------------------------------- layout

    def _build_layout(self) -> Layout:
        root = Layout(name="root")
        root.split_column(
            Layout(name="header", size=3),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=14),
        )
        root["body"].split_row(
            Layout(name="left", ratio=1),
            Layout(name="middle", ratio=1),
            Layout(name="right", ratio=1),
        )
        root["left"].split_column(
            Layout(name="summary", size=12),
            Layout(name="protocols", ratio=1),
        )
        root["middle"].split_column(Layout(name="countries"))
        root["right"].split_column(
            Layout(name="top_dst", ratio=3),
            Layout(name="top_ports", ratio=2),
        )
        return root

    # ------------------------------------------------------------- subviews

    def _header(self) -> Panel:
        title = Text(" 🛰  IP PACKET MONITOR ", style="bold white on blue")
        flt = self.bpf_filter or "<none>"
        sub = Text(
            f"iface: {self.interface}   filter: {flt}   "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            style="cyan",
        )
        return Panel(
            Align.center(Group(title, sub)),
            border_style="blue",
            box=box.HEAVY,
        )

    def _summary(self, snap) -> Panel:
        bps, pps = self.stats.rates()
        elapsed = int(snap["elapsed"])
        h, rem = divmod(elapsed, 3600)
        m, s = divmod(rem, 60)
        t = Table.grid(padding=(0, 1))
        t.add_column(justify="right", style="bold cyan", no_wrap=True)
        t.add_column(style="white")
        t.add_row("Uptime", f"{h:02d}:{m:02d}:{s:02d}")
        t.add_row("Packets", f"[bold yellow]{snap['total_packets']:,}[/]")
        t.add_row("Bytes", f"[bold yellow]{format_bytes(snap['total_bytes'])}[/]")
        t.add_row(
            "Throughput",
            f"[bold green]{format_rate(bps)}[/]  "
            f"[dim]({pps:,.1f} pkt/s)[/]",
        )
        t.add_row("Unique IPs", f"{snap['unique_ips']:,}")
        t.add_row("Countries", str(len(snap["countries"])))
        t.add_row("Flows", f"{len(snap['flows']):,}")
        return Panel(t, title="[bold]📊 Resumen[/]", border_style="cyan", box=box.ROUNDED)

    def _protocols(self, snap) -> Panel:
        total = snap["total_packets"] or 1
        t = Table(box=box.SIMPLE_HEAVY, expand=True, show_edge=False, pad_edge=False)
        t.add_column("Proto", style="bold magenta")
        t.add_column("Pkts", justify="right")
        t.add_column("Bytes", justify="right")
        t.add_column("Share", justify="right")
        protos = sorted(
            snap["protocol_counts"].items(), key=lambda x: x[1], reverse=True
        )
        for proto, count in protos[:10]:
            pct = 100 * count / total
            bar = self._bar(pct)
            t.add_row(
                proto,
                f"{count:,}",
                format_bytes(snap["protocol_bytes"].get(proto, 0)),
                f"{bar} {pct:5.1f}%",
            )
        return Panel(
            t, title="[bold]🔌 Protocolos[/]", border_style="magenta", box=box.ROUNDED
        )

    def _countries(self, snap) -> Panel:
        countries = sorted(
            snap["countries"], key=lambda c: c["total_bytes"], reverse=True
        )[:18]
        t = Table(box=box.SIMPLE_HEAVY, expand=True, show_edge=False, pad_edge=False)
        t.add_column("", width=2)
        t.add_column("País", style="bold")
        t.add_column("In", justify="right", style="green")
        t.add_column("Out", justify="right", style="yellow")
        t.add_column("Bytes", justify="right", style="cyan")
        t.add_column("IPs", justify="right")
        if not countries:
            t.add_row("", "[dim]Resolviendo geolocalización…[/]", "", "", "", "")
        for c in countries:
            flag = country_flag(c["country_code"])
            name = (c["country"] or c["country_code"])[:18]
            t.add_row(
                flag,
                f"{name} [dim]({c['country_code']})[/]",
                f"{c['packets_in']:,}",
                f"{c['packets_out']:,}",
                format_bytes(c["total_bytes"]),
                str(c["unique_ips"]),
            )
        return Panel(
            t, title="[bold]🌍 Países (origen / destino)[/]",
            border_style="green", box=box.ROUNDED,
        )

    def _top_dst(self, snap) -> Panel:
        t = Table(box=box.SIMPLE_HEAVY, expand=True, show_edge=False, pad_edge=False)
        t.add_column("", width=2)
        t.add_column("IP destino", style="bold")
        t.add_column("País", style="cyan", no_wrap=True)
        t.add_column("Bytes", justify="right")
        t.add_column("Pkts", justify="right")
        for ip, count in snap["top_dst"][:14]:
            if is_private_ip(ip):
                flag, country, cc = "🏠", "Local/LAN", "—"
            else:
                geo = self.geoip.lookup(ip)
                flag = country_flag(geo.country_code) if geo and geo.country_code != "??" else "🏳"
                country = (geo.country if geo else "?")[:14]
                cc = geo.country_code if geo else "??"
            byts = format_bytes(
                next((b for i, b in snap["top_dst_bytes"] if i == ip), 0)
            )
            t.add_row(flag, ip, f"{country} [dim]{cc}[/]", byts, f"{count:,}")
        return Panel(
            t, title="[bold]🎯 Top destinos[/]",
            border_style="yellow", box=box.ROUNDED,
        )

    def _top_ports(self, snap) -> Panel:
        t = Table(box=box.SIMPLE_HEAVY, expand=True, show_edge=False, pad_edge=False)
        t.add_column("Port", style="bold", justify="right")
        t.add_column("Servicio", style="cyan")
        t.add_column("Pkts", justify="right")
        for port, count in snap["top_dport"][:12]:
            t.add_row(str(port), service_name(port) or "—", f"{count:,}")
        if not snap["top_dport"]:
            t.add_row("", "[dim]sin tráfico aún[/]", "")
        return Panel(
            t, title="[bold]🚪 Top puertos destino[/]",
            border_style="bright_blue", box=box.ROUNDED,
        )

    def _live_packets(self, snap) -> Panel:
        t = Table(box=box.SIMPLE, expand=True, show_edge=False, pad_edge=False)
        t.add_column("Hora", style="dim", width=12, no_wrap=True)
        t.add_column("Proto", width=5)
        t.add_column("Origen", style="green", no_wrap=True)
        t.add_column("", width=1, justify="center")
        t.add_column("Destino", style="yellow", no_wrap=True)
        t.add_column("dport", justify="right", width=6)
        t.add_column("svc", style="cyan", width=10)
        t.add_column("len", justify="right", width=10)
        t.add_column("país", width=14, no_wrap=True)
        for pkt in list(snap["recent"])[:10]:
            tm = datetime.fromtimestamp(pkt.ts).strftime("%H:%M:%S.%f")[:-3]
            if is_private_ip(pkt.dst):
                cc, country, flag = "—", "LAN", "🏠"
            else:
                geo = self.geoip.lookup(pkt.dst)
                cc = geo.country_code if geo else "??"
                country = (geo.country if geo else "?")
                flag = country_flag(cc) if cc != "??" else "🏳"
            svc = service_name(pkt.dport) if pkt.dport else "—"
            t.add_row(
                tm, pkt.proto, pkt.src, "→", pkt.dst,
                str(pkt.dport) if pkt.dport else "—",
                svc or "—",
                format_bytes(pkt.length),
                f"{flag} {country[:10]}",
            )
        return Panel(
            t, title="[bold]📡 Paquetes en vivo[/]",
            border_style="white", box=box.ROUNDED,
        )

    # ----------------------------------------------------------------- util

    @staticmethod
    def _bar(pct: float, width: int = 10) -> str:
        filled = int(round(pct / 100 * width))
        filled = max(0, min(width, filled))
        return "█" * filled + "·" * (width - filled)

    # --------------------------------------------------------------- render

    def render(self) -> Layout:
        snap = self.stats.snapshot()
        layout = self._build_layout()
        layout["header"].update(self._header())
        layout["summary"].update(self._summary(snap))
        layout["protocols"].update(self._protocols(snap))
        layout["countries"].update(self._countries(snap))
        layout["top_dst"].update(self._top_dst(snap))
        layout["top_ports"].update(self._top_ports(snap))
        layout["footer"].update(self._live_packets(snap))
        return layout

    def run(self) -> None:
        with Live(
            self.render(),
            console=self.console,
            refresh_per_second=max(1, int(1 / self.refresh)),
            screen=True,
        ) as live:
            while not self._stop.is_set():
                try:
                    live.update(self.render())
                    time.sleep(self.refresh)
                except KeyboardInterrupt:
                    break

    def stop(self) -> None:
        self._stop.set()
