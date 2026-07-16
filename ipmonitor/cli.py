"""Command-line entry point for ipmonitor."""

from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from rich.console import Console

from . import __version__
from .alerts import AlertEngine
from .capture import CaptureEngine, HAVE_SCAPY
from .config import load as load_config
from .dpi import extract as dpi_extract
from .exporter import Exporter
from .geoip import GeoIPResolver
from .hosts import HostRegistry
from .procs import ProcessMap, local_interface_ips
from .stats import PacketRecord, StatsAggregator
from .ui import Dashboard
from .utils import country_flag, is_private_ip


def _default_cache_path() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA")
        root = Path(base) if base else Path.home() / "AppData" / "Local"
        return root / "ipmonitor" / "geoip.json"
    return Path.home() / ".cache" / "ipmonitor" / "geoip.json"


def _is_admin() -> bool:
    if sys.platform == "win32":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0  # type: ignore[attr-defined]
    return False


DEFAULT_CACHE = str(_default_cache_path())


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ipmonitor",
        description=(
            "Monitor profesional de paquetes IP en tiempo real con "
            "geolocalización, dominios (DNS/SNI/HTTP), atribución de procesos "
            "y alertas configurables."
        ),
        epilog=(
            "Ejemplos (Windows / PowerShell como Administrador):\n"
            "  python -m ipmonitor --list-interfaces\n"
            "  python -m ipmonitor -i \"Wi-Fi\" -f \"tcp or udp\"\n"
            "  python -m ipmonitor --pcap sesion.pcap --alert-country RU,KP\n"
            "  python -m ipmonitor --no-ui --duration 30 --export-json out.json\n"
            "  .\\run.ps1                 # lanzador con auto-elevación UAC\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # capture
    p.add_argument("-i", "--interface",
                   help="Interfaz a capturar (por defecto: la elegida por scapy)")
    p.add_argument("-f", "--filter", dest="bpf",
                   help="Filtro BPF (ej. 'tcp or udp', 'not port 22', 'host 8.8.8.8')")
    p.add_argument("--list-interfaces", action="store_true",
                   help="Lista interfaces disponibles y sale")

    # geoip
    p.add_argument("--mmdb", help="Ruta a GeoLite2-City.mmdb para resolución offline")
    p.add_argument("--cache", default=DEFAULT_CACHE,
                   help=f"Fichero de caché GeoIP persistente (def: {DEFAULT_CACHE})")
    p.add_argument("--offline", action="store_true",
                   help="Desactiva ip-api.com (solo cache + mmdb)")

    # dpi / hosts / procs
    p.add_argument("--no-dpi", action="store_true",
                   help="Desactiva DPI (DNS/SNI/HTTP Host)")
    p.add_argument("--no-rdns", action="store_true",
                   help="Desactiva reverse DNS en background")
    p.add_argument("--no-procs", action="store_true",
                   help="Desactiva atribución de procesos (psutil)")

    # alerts
    p.add_argument("--alert-country", default="",
                   help="Códigos ISO separados por comas (ej. 'RU,KP,IR')")
    p.add_argument("--alert-port", default="",
                   help="Puertos vigilados separados por comas (ej. '23,3389')")
    p.add_argument("--alert-rate", type=float, default=0.0,
                   help="Umbral bytes/s para alertar picos de tráfico")
    p.add_argument("--no-new-country-alert", action="store_true",
                   help="Silencia las alertas informativas 'nuevo país'")

    # output
    p.add_argument("--no-ui", action="store_true",
                   help="Sin dashboard TUI; imprime una línea por paquete")
    p.add_argument("--pcap", metavar="PATH",
                   help="Vuelca todos los paquetes capturados a un fichero pcap")
    p.add_argument("--export-json", metavar="PATH", help="Informe JSON al salir")
    p.add_argument("--export-csv", metavar="PATH",
                   help="CSV (resumen por país) al salir")

    # session control
    p.add_argument("--duration", type=int, default=0,
                   help="Detiene la captura tras N segundos (0 = hasta Ctrl+C)")
    p.add_argument("--refresh", type=float, default=4.0,
                   help="Refrescos por segundo del dashboard (def: 4)")

    # misc
    p.add_argument("--config", help="Ruta a fichero TOML de configuración")
    p.add_argument("--version", action="version",
                   version=f"ipmonitor {__version__}")
    return p


def _apply_config_defaults(
    args: argparse.Namespace, cfg: Dict[str, Any]
) -> None:
    defaults = cfg.get("defaults") or {}
    for key in ("interface", "bpf", "mmdb", "cache", "pcap"):
        if not getattr(args, key, None) and defaults.get(key):
            setattr(args, key, defaults[key])
    for flag in ("offline", "no_dpi", "no_rdns", "no_procs", "no_ui"):
        if defaults.get(flag) and not getattr(args, flag, False):
            setattr(args, flag, True)

    alerts = cfg.get("alerts") or {}
    if not args.alert_country and alerts.get("block_countries"):
        args.alert_country = ",".join(alerts["block_countries"])
    if not args.alert_port and alerts.get("block_ports"):
        args.alert_port = ",".join(str(p) for p in alerts["block_ports"])
    if not args.alert_rate and alerts.get("rate_bytes_per_sec"):
        args.alert_rate = float(alerts["rate_bytes_per_sec"])
    if alerts.get("silence_new_country") and not args.no_new_country_alert:
        args.no_new_country_alert = True

    ui = cfg.get("ui") or {}
    if ui.get("refresh") and args.refresh == 4.0:
        args.refresh = float(ui["refresh"])


def _print_packet_line(console: Console, pkt: PacketRecord, sgeo, dgeo,
                       hostname: str, process: Optional[str]) -> None:
    sflag = country_flag(sgeo.country_code) if sgeo else "🏠"
    dflag = country_flag(dgeo.country_code) if dgeo else "🏠"
    tm = time.strftime("%H:%M:%S", time.localtime(pkt.ts))
    host = f" [{hostname}]" if hostname else ""
    proc = f" ({process})" if process else ""
    console.print(
        f"[dim]{tm}[/] [bold]{pkt.proto:<4}[/] "
        f"{sflag} [green]{pkt.src:>15}[/] → "
        f"{dflag} [yellow]{pkt.dst:<15}[/] "
        f"[cyan]:{pkt.dport:<5}[/] "
        f"len=[bold]{pkt.length}[/]{host}{proc}"
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

    cfg = load_config(args.config)
    _apply_config_defaults(args, cfg)

    if args.list_interfaces:
        details = CaptureEngine.list_interfaces_detailed()
        if not details:
            console.print(
                "[yellow]No se pudieron listar interfaces.[/] "
                "En Windows necesitas [cyan]Npcap[/] "
                "(https://npcap.com)."
            )
            return 1
        console.print("[bold]Interfaces disponibles:[/]")
        for d in details:
            name = d.get("name") or d.get("guid") or "?"
            desc = d.get("description") or ""
            ips = ", ".join(d.get("ips") or []) or "-"
            mac = d.get("mac") or ""
            console.print(
                f"  • [bold cyan]{name}[/]  [dim]{desc}[/]\n"
                f"      ips: {ips}   mac: {mac or '-'}"
            )
        return 0

    if not _is_admin():
        if sys.platform == "win32":
            console.print(
                "[yellow]Aviso:[/] la captura requiere [bold]Administrador[/]. "
                "Abre PowerShell como Administrador o ejecuta [cyan].\\run.ps1[/] "
                "(eleva por UAC). También necesitas [cyan]Npcap[/] instalado "
                "(https://npcap.com)."
            )
        else:
            console.print(
                "[yellow]Aviso:[/] la captura suele requerir root. "
                "Ejecuta como [cyan]sudo -E python -m ipmonitor[/] "
                "o concede [cyan]CAP_NET_RAW[/] al binario de python."
            )

    # ---- wiring subsystems ---------------------------------------------
    geoip = GeoIPResolver(
        mmdb_path=args.mmdb, cache_path=args.cache, offline=args.offline,
    )
    stats = StatsAggregator()
    hosts = None if args.no_dpi and args.no_rdns else HostRegistry(
        reverse_dns=not args.no_rdns
    )
    procs = None if args.no_procs else ProcessMap()
    local_ips = local_interface_ips()

    alert_countries = [c.strip().upper() for c in args.alert_country.split(",") if c.strip()]
    alert_ports = [int(p.strip()) for p in args.alert_port.split(",") if p.strip().isdigit()]
    alerts = AlertEngine(
        block_countries=alert_countries,
        block_ports=alert_ports,
        rate_bytes_per_sec=args.alert_rate or None,
        notify_new_country=not args.no_new_country_alert,
    )

    pcap = None
    if args.pcap:
        try:
            from .pcap import PcapDumper
            pcap = PcapDumper(args.pcap)
            console.print(f"[green]✓[/] PCAP → {args.pcap}")
        except Exception as e:
            console.print(f"[red]No se pudo abrir pcap:[/] {e}")

    # ---- packet pipeline -----------------------------------------------
    def on_packet(pkt: PacketRecord, raw) -> None:
        sgeo = None if is_private_ip(pkt.src) else geoip.lookup(pkt.src)
        dgeo = None if is_private_ip(pkt.dst) else geoip.lookup(pkt.dst)

        hostname = ""
        if not args.no_dpi and hosts is not None:
            extras = dpi_extract(raw, pkt.proto, pkt.dport, pkt.sport)
            if "sni" in extras:
                hosts.observe_sni(pkt.dst, extras["sni"])
            if "http_host" in extras:
                hosts.observe_http(pkt.dst, extras["http_host"])
            for name, ip in extras.get("dns_pairs", []) or []:
                hosts.observe_dns(name, ip)
            if not is_private_ip(pkt.dst):
                hostname = hosts.get(pkt.dst)
                if hostname:
                    hosts.account(hostname, pkt.length)

        process = None
        if procs is not None and procs.available:
            process = procs.attribute(
                pkt.src, pkt.sport, pkt.dst, pkt.dport, pkt.proto,
                local_ips=local_ips,
            )

        stats.record(pkt, sgeo, dgeo, hostname=hostname, process=process)
        alerts.evaluate_packet(pkt, sgeo, dgeo)

        if pcap is not None:
            pcap.write(raw)

        if args.no_ui:
            _print_packet_line(
                console, pkt, sgeo, dgeo, hostname,
                process[1] if process else None,
            )

    engine = CaptureEngine(
        interface=args.interface, bpf_filter=args.bpf, on_packet=on_packet,
    )

    # ---- shutdown handling ---------------------------------------------
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
    if hasattr(signal, "SIGBREAK"):
        try:
            signal.signal(signal.SIGBREAK, shutdown)  # type: ignore[attr-defined]
        except Exception:
            pass
    if sys.platform != "win32":
        try:
            signal.signal(signal.SIGTERM, shutdown)
        except (ValueError, OSError):
            pass

    try:
        engine.start()
    except PermissionError:
        console.print(
            "[bold red]Permiso denegado al abrir la interfaz.[/] "
            "Ejecuta como Administrador (Windows) o root (Linux)."
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

    # rate-alert supervisor -----------------------------------------------
    def _rate_supervisor():
        while not stop_event.is_set():
            time.sleep(2)
            try:
                bps, _ = stats.rates()
                alerts.evaluate_rate(bps)
            except Exception:
                pass
    threading.Thread(target=_rate_supervisor, daemon=True).start()

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
                stats, geoip, hosts=hosts, procs=procs, alerts=alerts,
                interface=iface, bpf_filter=args.bpf,
                pcap_path=args.pcap, refresh_hz=args.refresh,
            )
            dashboard.run()
    finally:
        try: engine.stop()
        except Exception: pass
        geoip.stop()
        if hosts is not None:
            hosts.stop()
        if procs is not None:
            procs.stop()
        if pcap is not None:
            pcap.close()

        exporter = Exporter(stats, geoip, hosts=hosts, alerts=alerts)
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
