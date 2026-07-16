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

from .alerts import AlertEngine
from .geoip import GeoIPResolver
from .hosts import HostRegistry
from .procs import ProcessMap
from .sparkline import sparkline
from .stats import StatsAggregator
from .utils import (
    country_flag,
    format_bytes,
    format_rate,
    is_private_ip,
    service_name,
)


_SEV_STYLE = {"info": "cyan", "warn": "yellow", "crit": "bold red"}


class Dashboard:
    """Renders the live monitor UI using rich.Live."""

    def __init__(
        self,
        stats: StatsAggregator,
        geoip: GeoIPResolver,
        hosts: Optional[HostRegistry] = None,
        procs: Optional[ProcessMap] = None,
        alerts: Optional[AlertEngine] = None,
        interface: str = "default",
        bpf_filter: Optional[str] = None,
        pcap_path: Optional[str] = None,
        refresh_hz: float = 4.0,
    ):
        self.stats = stats
        self.geoip = geoip
        self.hosts = hosts
        self.procs = procs
        self.alerts = alerts
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.pcap_path = pcap_path
        self.refresh = max(0.1, 1.0 / refresh_hz)
        self.console = Console()
        self._stop = threading.Event()

    # --------------------------------------------------------------- layout

    def _build_layout(self) -> Layout:
        root = Layout(name="root")
        root.split_column(
            Layout(name="header", size=3),
            Layout(name="body", ratio=1),
            Layout(name="alerts", size=8),
            Layout(name="footer", size=14),
        )
        root["body"].split_row(
            Layout(name="left", ratio=1),
            Layout(name="middle", ratio=1),
            Layout(name="right", ratio=1),
        )
        root["left"].split_column(
            Layout(name="summary", size=14),
            Layout(name="protocols", ratio=2),
            Layout(name="continents", size=10),
        )
        root["middle"].split_column(
            Layout(name="countries", ratio=3),
            Layout(name="asn", size=8),
        )
        root["right"].split_column(
            Layout(name="hosts", ratio=2),
            Layout(name="procs", ratio=2),
            Layout(name="top_ports", size=8),
        )
        return root

    # -------------------------------------------------------------- header

    def _header(self) -> Panel:
        title = Text(" 🛰  IP PACKET MONITOR ", style="bold white on blue")
        parts = [
            f"iface: {self.interface}",
            f"filter: {self.bpf_filter or '<none>'}",
        ]
        if self.pcap_path:
            parts.append(f"pcap: {self.pcap_path}")
        if self.procs and self.procs.available:
            parts.append("proc: on")
        parts.append(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        sub = Text("   ".join(parts), style="cyan")
        return Panel(
            Align.center(Group(title, sub)),
            border_style="blue",
            box=box.HEAVY,
        )

    # ------------------------------------------------------------- summary

    def _summary(self, snap) -> Panel:
        bps, pps = self.stats.rates()
        history_bytes, _ = self.stats.history()
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
        spark = sparkline(history_bytes or [0], width=26)
        t.add_row("60 s trend", f"[green]{spark}[/]")
        return Panel(t, title="[bold]📊 Resumen[/]", border_style="cyan", box=box.ROUNDED)

    # ------------------------------------------------------------ protocols

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

    # ----------------------------------------------------------- continents

    def _continents(self, snap) -> Panel:
        conts = sorted(snap["continents"], key=lambda c: c["bytes"], reverse=True)
        t = Table(box=box.SIMPLE, expand=True, show_edge=False, pad_edge=False)
        t.add_column("", width=2)
        t.add_column("Continente", style="bold")
        t.add_column("Pkts", justify="right")
        t.add_column("Bytes", justify="right")
        t.add_column("CC", justify="right")
        for c in conts:
            t.add_row(
                c["emoji"], c["name"], f"{c['packets']:,}",
                format_bytes(c["bytes"]), str(c["countries"]),
            )
        if not conts:
            t.add_row("", "[dim]sin datos aún[/]", "", "", "")
        return Panel(
            t, title="[bold]🗺 Continentes[/]",
            border_style="bright_cyan", box=box.ROUNDED,
        )

    # ------------------------------------------------------------ countries

    def _countries(self, snap) -> Panel:
        countries = sorted(
            snap["countries"], key=lambda c: c["total_bytes"], reverse=True
        )[:22]
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
            t, title="[bold]🌍 Países[/]",
            border_style="green", box=box.ROUNDED,
        )

    # ----------------------------------------------------------------- asn

    def _asn(self, snap) -> Panel:
        t = Table(box=box.SIMPLE, expand=True, show_edge=False, pad_edge=False)
        t.add_column("Organización / ASN", style="bold")
        t.add_column("Bytes", justify="right")
        for asn, byts in snap["top_asn"]:
            t.add_row(str(asn)[:36] or "-", format_bytes(byts))
        if not snap["top_asn"]:
            t.add_row("[dim]sin ASN aún[/]", "")
        return Panel(
            t, title="[bold]🏢 Top organizaciones[/]",
            border_style="bright_magenta", box=box.ROUNDED,
        )

    # ----------------------------------------------------------- hostnames

    def _hosts(self, snap) -> Panel:
        t = Table(box=box.SIMPLE_HEAVY, expand=True, show_edge=False, pad_edge=False)
        t.add_column("Dominio", style="bold cyan")
        t.add_column("Pkts", justify="right")
        t.add_column("Bytes", justify="right")
        rows = snap["top_hosts"][:12]
        pkt_map = dict(snap["top_hosts_pkts"])
        for host, byts in rows:
            t.add_row(host[:40], f"{pkt_map.get(host, 0):,}", format_bytes(byts))
        if not rows:
            t.add_row("[dim]sin dominios detectados (DNS/SNI)…[/]", "", "")
        return Panel(
            t, title="[bold]🌐 Top dominios[/]",
            border_style="yellow", box=box.ROUNDED,
        )

    # ----------------------------------------------------------- processes

    def _processes(self, snap) -> Panel:
        t = Table(box=box.SIMPLE_HEAVY, expand=True, show_edge=False, pad_edge=False)
        t.add_column("Proceso", style="bold")
        t.add_column("Pkts", justify="right")
        t.add_column("Bytes", justify="right")
        rows = snap["top_procs_bytes"][:10]
        pkt_map = dict(snap["top_procs_pkts"])
        for proc, byts in rows:
            t.add_row(proc[:36], f"{pkt_map.get(proc, 0):,}", format_bytes(byts))
        if not rows:
            note = "[dim]psutil no disponible[/]" if not (
                self.procs and self.procs.available
            ) else "[dim]sin atribución aún…[/]"
            t.add_row(note, "", "")
        return Panel(
            t, title="[bold]🧠 Procesos que usan la red[/]",
            border_style="bright_yellow", box=box.ROUNDED,
        )

    # --------------------------------------------------------------- ports

    def _top_ports(self, snap) -> Panel:
        t = Table(box=box.SIMPLE, expand=True, show_edge=False, pad_edge=False)
        t.add_column("Port", style="bold", justify="right")
        t.add_column("Servicio", style="cyan")
        t.add_column("Pkts", justify="right")
        for port, count in snap["top_dport"][:10]:
            t.add_row(str(port), service_name(port) or "—", f"{count:,}")
        if not snap["top_dport"]:
            t.add_row("", "[dim]sin tráfico aún[/]", "")
        return Panel(
            t, title="[bold]🚪 Top puertos destino[/]",
            border_style="bright_blue", box=box.ROUNDED,
        )

    # --------------------------------------------------------------- alerts

    def _alerts_panel(self) -> Panel:
        t = Table(box=box.SIMPLE, expand=True, show_edge=False, pad_edge=False)
        t.add_column("Hora", style="dim", width=8)
        t.add_column("Regla", width=14)
        t.add_column("Mensaje", overflow="fold")
        if self.alerts:
            rows = self.alerts.recent(6)
            for a in rows:
                tm = datetime.fromtimestamp(a.ts).strftime("%H:%M:%S")
                sev = _SEV_STYLE.get(a.severity, "white")
                t.add_row(
                    tm,
                    f"[{sev}]{a.rule}[/]",
                    f"[{sev}]{a.message}[/]",
                )
            if not rows:
                t.add_row("", "[dim]sin alertas[/]", "")
        else:
            t.add_row("", "[dim]alertas desactivadas[/]", "")
        return Panel(
            t, title="[bold]🚨 Alertas[/]",
            border_style="red", box=box.ROUNDED,
        )

    # --------------------------------------------------------- live packets

    def _live_packets(self, snap) -> Panel:
        t = Table(box=box.SIMPLE, expand=True, show_edge=False, pad_edge=False)
        t.add_column("Hora", style="dim", width=12, no_wrap=True)
        t.add_column("Proto", width=5)
        t.add_column("Origen", style="green", no_wrap=True)
        t.add_column("", width=1, justify="center")
        t.add_column("Destino", style="yellow", no_wrap=True)
        t.add_column("Puerto", justify="right", width=6)
        t.add_column("Servicio", style="cyan", width=10)
        t.add_column("Dominio", style="bright_cyan", overflow="ellipsis")
        t.add_column("Proceso", style="bright_yellow", overflow="ellipsis")
        t.add_column("Len", justify="right", width=10)
        t.add_column("País", width=6, no_wrap=True)
        for pkt in list(snap["recent"])[:10]:
            tm = datetime.fromtimestamp(pkt["ts"]).strftime("%H:%M:%S.%f")[:-3]
            cc_dst = pkt.get("cc_dst") or ""
            if is_private_ip(pkt["dst"]):
                flag = "🏠"
            else:
                flag = country_flag(cc_dst) if cc_dst else "🏳"
            svc = service_name(pkt["dport"]) if pkt["dport"] else "—"
            t.add_row(
                tm, pkt["proto"], pkt["src"], "→", pkt["dst"],
                str(pkt["dport"]) if pkt["dport"] else "—",
                svc or "—",
                (pkt.get("hostname") or "")[:24],
                (pkt.get("process") or "")[:16],
                format_bytes(pkt["length"]),
                f"{flag} {cc_dst}",
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
        layout["continents"].update(self._continents(snap))
        layout["countries"].update(self._countries(snap))
        layout["asn"].update(self._asn(snap))
        layout["hosts"].update(self._hosts(snap))
        layout["procs"].update(self._processes(snap))
        layout["top_ports"].update(self._top_ports(snap))
        layout["alerts"].update(self._alerts_panel())
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
