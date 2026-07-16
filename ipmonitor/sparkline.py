"""Unicode-block sparkline helper."""

from __future__ import annotations

from typing import Iterable, Sequence

_BARS = "▁▂▃▄▅▆▇█"


def sparkline(values: Sequence[float], width: int = 24) -> str:
    """Render ``values`` as a fixed-width Unicode sparkline.

    Buckets are averaged when ``len(values) > width``, padded with the
    lowest bar when shorter.
    """
    if width <= 0:
        return ""
    if not values:
        return "·" * width

    n = len(values)
    if n < width:
        # Right-pad with the earliest value so the trend "starts" from the left.
        pad = [values[0]] * (width - n)
        buckets = list(pad) + list(values)
    else:
        step = n / width
        buckets = []
        for i in range(width):
            a = int(i * step)
            b = max(a + 1, int((i + 1) * step))
            chunk = values[a:b] or (0.0,)
            buckets.append(sum(chunk) / len(chunk))

    top = max(buckets)
    if top <= 0:
        return _BARS[0] * width
    span = len(_BARS) - 1
    return "".join(
        _BARS[min(span, int((v / top) * span))]
        for v in buckets
    )
