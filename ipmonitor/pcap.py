"""Thin, thread-safe wrapper around scapy's PcapWriter."""

from __future__ import annotations

import threading
from typing import Any, Optional


class PcapDumper:
    def __init__(self, path: str):
        from scapy.utils import PcapWriter  # type: ignore

        self._writer: Optional[Any] = PcapWriter(path, append=False, sync=True)
        self._lock = threading.Lock()
        self.path = path

    def write(self, pkt: Any) -> None:
        w = self._writer
        if w is None:
            return
        try:
            with self._lock:
                w.write(pkt)
        except Exception:
            pass

    def close(self) -> None:
        with self._lock:
            w, self._writer = self._writer, None
        if w is not None:
            try:
                w.close()
            except Exception:
                pass
