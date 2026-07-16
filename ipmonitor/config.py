"""TOML configuration loader.

Search order:
  1. Path provided via ``--config``.
  2. ``./ipmonitor.toml``.
  3. ``$XDG_CONFIG_HOME/ipmonitor.toml`` or ``~/.config/ipmonitor.toml``.
  4. ``%APPDATA%/ipmonitor/ipmonitor.toml`` (Windows).

The parsed dictionary has string keys matching the CLI flags:

    [defaults]
    interface = "Wi-Fi"
    filter = "tcp or udp"
    offline = false

    [alerts]
    block_countries = ["RU", "KP"]
    block_ports = [23, 3389]
    rate_bytes_per_sec = 10485760

    [ui]
    refresh = 4
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

_TOML_LOADER = None
try:
    if sys.version_info >= (3, 11):
        import tomllib as _toml  # type: ignore
        _TOML_LOADER = _toml.loads
    else:  # pragma: no cover
        import tomli as _toml  # type: ignore
        _TOML_LOADER = _toml.loads
except ImportError:
    _TOML_LOADER = None


def default_search_paths() -> list:
    paths = [Path.cwd() / "ipmonitor.toml"]
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            paths.append(Path(appdata) / "ipmonitor" / "ipmonitor.toml")
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME")
        base = Path(xdg) if xdg else Path.home() / ".config"
        paths.append(base / "ipmonitor.toml")
    return paths


def load(explicit: Optional[str] = None) -> Dict[str, Any]:
    if _TOML_LOADER is None:
        return {}
    candidates = [Path(explicit)] if explicit else default_search_paths()
    for p in candidates:
        try:
            if p and p.exists():
                return _TOML_LOADER(p.read_text(encoding="utf-8"))
        except Exception:
            continue
    return {}
