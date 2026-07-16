"""Export helpers and end-of-session summary."""

from __future__ import annotations

import csv
import json
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from rich import box
from rich.console import Console
from rich.table import Table

from .stats import StatsAggregator
from .utils import country_flag, format_bytes

if TYPE_CHECKING:
    from .alerts import AlertEngine
    from .geoip import GeoIPResolver
    from .hosts import HostRegistry


class Exporter:
    def __init__(
        self,
        stats: StatsAggregator,
        geoip: "GeoIPResolver",
        hosts: Optional["HostRegistry"] = None,
        alerts: Optional["AlertEngine"] = None,
    ):
        self.stats = stats
        self.geoip = geoip
        self.hosts = hosts
        self.alerts = alerts

    # -------------------------------------------------------- serialisation

    def to_json(self, path: str) -> None:
        snap = self.stats.snapshot()
        snap["generated_at"] = time.time()
        if self.hosts is not None:
            snap["hostnames"] = self.hosts.snapshot()
        if self.alerts is not None:
            snap["alerts"] = [
                asdict(a) if is_dataclass(a) else a for a in self.alerts.all()
            ]
        Path(path).expanduser().write_text(
            json.dumps(snap, indent=2, default=str), encoding="utf-8"
        )

    def to_csv(self, path: str) -> None:
        snap = self.stats.snapshot()
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow([
                "country_code", "country", "packets_in", "packets_out",
                "bytes_in", "bytes_out", "unique_ips",
            ])
            rows = sorted(
                snap["countries"], key=lambda x: x["total_bytes"], reverse=True
            )
            for c in rows:
                w.writerow([
                    c["country_code"], c["country"], c["packets_in"],
                    c["packets_out"], c["bytes_in"], c["bytes_out"],
                    c["unique_ips"],
                ])

    # ------------------------------------------------------------- summary

    def print_summary(self, console: Console) -> None:
        snap = self.stats.snapshot()
        console.rule("[bold cyan]Resumen de la sesión")
        console.print(
            f"Capturados [bold yellow]{snap['total_packets']:,}[/] paquetes "
            f"({format_bytes(snap['total_bytes'])}) en "
            f"[bold]{snap['elapsed']:.1f}s[/]  •  "
            f"[bold]{snap['unique_ips']:,}[/] IPs únicas\n"
        )

        countries = sorted(
            snap["countries"], key=lambda x: x["total_bytes"], reverse=True
        )[:30]
        if countries:
            t = Table(title="Top países por tráfico", box=box.SIMPLE_HEAVY)
            t.add_column("")
            t.add_column("País")
            t.add_column("CC")
            t.add_column("Pkts In", justify="right")
            t.add_column("Pkts Out", justify="right")
            t.add_column("Bytes In", justify="right")
            t.add_column("Bytes Out", justify="right")
            t.add_column("IPs", justify="right")
            for c in countries:
                t.add_row(
                    country_flag(c["country_code"]),
                    c["country"] or "Unknown",
                    c["country_code"],
                    f"{c['packets_in']:,}",
                    f"{c['packets_out']:,}",
                    format_bytes(c["bytes_in"]),
                    format_bytes(c["bytes_out"]),
                    str(c["unique_ips"]),
                )
            console.print(t)

        if snap.get("top_hosts"):
            t = Table(title="Top dominios", box=box.SIMPLE)
            t.add_column("Dominio")
            t.add_column("Bytes", justify="right")
            for host, byts in snap["top_hosts"][:20]:
                t.add_row(host, format_bytes(byts))
            console.print(t)

        if snap.get("top_procs_bytes"):
            t = Table(title="Top procesos", box=box.SIMPLE)
            t.add_column("Proceso")
            t.add_column("Bytes", justify="right")
            for proc, byts in snap["top_procs_bytes"][:15]:
                t.add_row(proc, format_bytes(byts))
            console.print(t)

        protos = sorted(
            snap["protocol_counts"].items(), key=lambda x: x[1], reverse=True
        )
        if protos:
            t = Table(title="Protocolos", box=box.SIMPLE)
            t.add_column("Proto")
            t.add_column("Pkts", justify="right")
            t.add_column("Bytes", justify="right")
            for proto, count in protos:
                t.add_row(
                    proto, f"{count:,}",
                    format_bytes(snap["protocol_bytes"].get(proto, 0)),
                )
            console.print(t)

        if self.alerts is not None:
            alerts_all = self.alerts.all()
            if alerts_all:
                t = Table(title="Alertas", box=box.SIMPLE)
                t.add_column("Regla")
                t.add_column("Sev")
                t.add_column("Mensaje")
                for a in alerts_all[:30]:
                    t.add_row(a.rule, a.severity, a.message)
                console.print(t)
