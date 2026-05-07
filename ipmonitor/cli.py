"""Command-line entry point for ipmonitor."""

from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Optional, Sequence

from rich.console import Console

from . import __version__
from .capture import CaptureEngine, HAVE_SCAPY
from .exporter import Exporter
from .geoip import GeoIPResolver
from .stats import PacketRecord, StatsAggregator
from .ui import Dashboard
from .utils import country_flag, is_private_ip


DEFAULT_CACHE = str(Path.home() / ".cache" / "ipmonitor" / "geoip.json")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ipmonitor",
        description=(
            "Monitor profesional de paquetes IP en tiempo real con "
            "geolocalización por país y dashboard TUI."
        ),
        epilog=(
            "Ejemplos:\n"
            "  sudo -E python -m ipmonitor\n"
            "  sudo -E python -m ipmonitor -i eth0 -f 'tcp or udp'\n"
            "  sudo -E python -m ipmonitor --no-ui --duration 30 "
            "--export-json sesion.json\n"
            "  python -m ipmonitor --list-interfaces\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "-i", "--interface",
        help="Interfaz a capturar (por defecto: la elegida por scapy)",
    )
    p.add_argument(
        "-f", "--filter", dest="bpf",
        help="Filtro BPF (ej. 'tcp or udp', 'not port 22', 'host 8.8.8.8')",
    )
    p.add_argument(
        "--list-interfaces", action="store_true",
        help="Lista interfaces disponibles y sale",
    )
    p.add_argument(
        "--mmdb",
        help="Ruta a GeoLite2-City.mmdb para resolución offline",
    )
    p.add_argument(
        "--cache", default=DEFAULT_CACHE,
        help=f"Fichero de caché GeoIP persistente (def: {DEFAULT_CACHE})",
    )
    p.add_argument(
        "--offline", action="store_true",
        help="Desactiva la API ip-api.com (sólo cache + mmdb)",
    )
    p.add_argument(
        "--no-ui", action="store_true",
        help="Sin dashboard TUI; imprime una línea por paquete",
    )
    p.add_argument(
        "--export-json", metavar="PATH",
        help="Escribe un informe JSON al salir",
    )
    p.add_argument(
        "--export-csv", metavar="PATH",
        help="Escribe un CSV (resumen por país) al salir",
    )
    p.add_argument(
        "--duration", type=int, default=0,
        help="Detiene la captura tras N segundos (0 = hasta Ctrl+C)",
    )
    p.add_argument(
        "--refresh", type=float, default=4.0,
        help="Refrescos por segundo del dashboard (def: 4)",
    )
    p.add_argument(
        "--version", action="version", version=f"ipmonitor {__version__}",
    )
    return p


def _print_packet_line(console: Console, pkt: PacketRecord, sgeo, dgeo) -> None:
    sflag = country_flag(sgeo.country_code) if sgeo else "🏠"
    dflag = country_flag(dgeo.country_code) if dgeo else "🏠"
    console.print(
        f"[dim]{time.strftime('%H:%M:%S', time.localtime(pkt.ts))}[/] "
        f"[bold]{pkt.proto:<4}[/] "
        f"{sflag} [green]{pkt.src:>15}[/] → "
        f"{dflag} [yellow]{pkt.dst:<15}[/] "
        f"[cyan]:{pkt.dport:<5}[/] "
        f"len=[bold]{pkt.length}[/]"
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()

    if not HAVE_SCAPY:
        console.print(
            "[bold red]scapy no está instalado.[/] "
            "Instala con: [cyan]pip install scapy[/]"
        )
        return 2

    if args.list_interfaces:
        ifs = CaptureEngine.list_interfaces()
        if not ifs:
            console.print("[yellow]No se pudieron listar interfaces.[/]")
            return 1
        console.print("[bold]Interfaces disponibles:[/]")
        for i in ifs:
            console.print(f"  • {i}")
        return 0

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        console.print(
            "[yellow]Aviso:[/] la captura suele requerir root. "
            "Ejecuta como [cyan]sudo -E python -m ipmonitor[/] "
            "o concede [cyan]CAP_NET_RAW[/] al binario de python."
        )

    geoip = GeoIPResolver(
        mmdb_path=args.mmdb, cache_path=args.cache, offline=args.offline,
    )
    stats = StatsAggregator()

    def on_packet(pkt: PacketRecord) -> None:
        sgeo = None if is_private_ip(pkt.src) else geoip.lookup(pkt.src)
        dgeo = None if is_private_ip(pkt.dst) else geoip.lookup(pkt.dst)
        stats.record(pkt, sgeo, dgeo)
        if args.no_ui:
            _print_packet_line(console, pkt, sgeo, dgeo)

    engine = CaptureEngine(
        interface=args.interface, bpf_filter=args.bpf, on_packet=on_packet,
    )

    stop_event = threading.Event()
    dashboard: Optional[Dashboard] = None

    def shutdown(signum=None, frame=None):
        stop_event.set()
        try:
            engine.stop()
        except Exception:
            pass
        if dashboard is not None:
            dashboard.stop()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        engine.start()
    except PermissionError:
        console.print(
            "[bold red]Permiso denegado al abrir la interfaz.[/] "
            "Ejecuta como root."
        )
        return 1
    except Exception as e:
        console.print(f"[bold red]Error iniciando la captura:[/] {e}")
        return 1

    iface = args.interface or "default"
    if args.duration:
        def _stopper():
            stop_event.wait(args.duration)
            shutdown()
        threading.Thread(target=_stopper, daemon=True).start()

    try:
        if args.no_ui:
            console.print(
                f"[bold green]Capturando en {iface}[/] "
                f"(filtro={args.bpf or 'ninguno'}). Pulsa Ctrl+C para parar.\n"
            )
            while not stop_event.is_set():
                time.sleep(0.5)
        else:
            dashboard = Dashboard(
                stats, geoip,
                interface=iface,
                bpf_filter=args.bpf,
                refresh_hz=args.refresh,
            )
            dashboard.run()
    finally:
        try:
            engine.stop()
        except Exception:
            pass
        geoip.stop()

        exporter = Exporter(stats, geoip)
        if args.export_json:
            try:
                exporter.to_json(args.export_json)
                console.print(f"[green]✓[/] Informe JSON → {args.export_json}")
            except Exception as e:
                console.print(f"[red]Error JSON:[/] {e}")
        if args.export_csv:
            try:
                exporter.to_csv(args.export_csv)
                console.print(f"[green]✓[/] CSV → {args.export_csv}")
            except Exception as e:
                console.print(f"[red]Error CSV:[/] {e}")
        exporter.print_summary(console)

    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
