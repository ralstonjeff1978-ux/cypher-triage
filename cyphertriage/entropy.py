"""Shannon entropy: whole-file and a sliding-window map.

High entropy alone is not proof of packing (compressed resources, .NET, and
installers are legitimately high), so this module only *measures* — the verdict
logic that interprets it lives in triage, and the honest capacity framing lives
in the byte-attribution model. Pure stdlib.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import List


def shannon(data: bytes) -> float:
    """Shannon entropy of `data` in bits/byte, range [0.0, 8.0]."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


@dataclass(frozen=True)
class EntropyBlock:
    offset: int
    size: int
    entropy: float


def sliding_window(data: bytes, window: int = 4096, step: int = 0) -> List[EntropyBlock]:
    """Entropy per window across the file. `step` defaults to `window` (non-overlapping)."""
    if step <= 0:
        step = window
    blocks: List[EntropyBlock] = []
    if not data:
        return blocks
    for off in range(0, len(data), step):
        chunk = data[off:off + window]
        if not chunk:
            break
        blocks.append(EntropyBlock(off, len(chunk), shannon(chunk)))
    return blocks


def max_block(blocks: List[EntropyBlock]) -> float:
    return max((b.entropy for b in blocks), default=0.0)
