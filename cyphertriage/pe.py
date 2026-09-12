"""Minimal, bounds-checked PE structure parser (stdlib `struct` only).

Phase 0 needs just enough to locate the section table and compute the OVERLAY —
the bytes after the last section's raw data, which is the classic place a dropper
hides a second stage/config/appended file. That single number is the seed of the
byte-attribution / residual-capacity model (the moat): "N bytes live outside any
declared PE structure."

This intentionally does NOT use LIEF/pefile (that is a later phase, and full
untrusted parsing belongs in the cypher-scope sandbox). It only *reads* offsets;
it never executes or resolves anything. Every field access is bounds-checked so a
crafted/truncated file yields a partial result instead of a crash.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class Section:
    name: str
    raw_offset: int
    raw_size: int

    @property
    def raw_end(self) -> int:
        return self.raw_offset + self.raw_size


@dataclass
class PELayout:
    ok: bool
    total_size: int
    e_lfanew: int = 0
    num_sections: int = 0
    sections: List[Section] = field(default_factory=list)
    end_of_sections: int = 0     # highest raw_end across sections
    overlay_offset: int = 0      # == end_of_sections (start of overlay, if any)
    overlay_size: int = 0        # bytes after the last section
    error: Optional[str] = None


def parse(data: bytes) -> PELayout:
    n = len(data)
    lay = PELayout(ok=False, total_size=n)

    if n < 0x40 or data[:2] != b"MZ":
        lay.error = "not an MZ image"
        return lay

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    lay.e_lfanew = e_lfanew
    if not (0 < e_lfanew <= n - 24):
        lay.error = "e_lfanew out of range"
        return lay
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        lay.error = "PE signature missing"
        return lay

    coff = e_lfanew + 4
    # COFF header: Machine(2) NumberOfSections(2) TimeDateStamp(4) PtrSym(4)
    #              NumSym(4) SizeOfOptionalHeader(2) Characteristics(2)
    if coff + 20 > n:
        lay.error = "truncated COFF header"
        return lay
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    size_opt = struct.unpack_from("<H", data, coff + 16)[0]
    lay.num_sections = num_sections

    # Sanity clamp: PE spec effectively caps sections at 96; anything wild = malformed.
    if num_sections == 0 or num_sections > 96:
        lay.error = "implausible section count"
        return lay

    sec_table = coff + 20 + size_opt
    SECTION_HDR = 40
    if sec_table + num_sections * SECTION_HDR > n:
        lay.error = "section table extends past EOF"
        return lay

    end_of_sections = 0
    for i in range(num_sections):
        base = sec_table + i * SECTION_HDR
        raw_name = data[base:base + 8].rstrip(b"\x00")
        try:
            name = raw_name.decode("ascii", "replace")
        except Exception:
            name = repr(raw_name)
        # SizeOfRawData at +16, PointerToRawData at +20 (each uint32)
        raw_size = struct.unpack_from("<I", data, base + 16)[0]
        raw_off = struct.unpack_from("<I", data, base + 20)[0]
        # Ignore sections whose declared raw range falls outside the file.
        if raw_off and raw_off <= n:
            sec = Section(name, raw_off, raw_size)
            lay.sections.append(sec)
            end = min(sec.raw_end, n)  # clamp: declared size may overrun a truncated file
            end_of_sections = max(end_of_sections, end)

    lay.end_of_sections = end_of_sections
    if 0 < end_of_sections < n:
        lay.overlay_offset = end_of_sections
        lay.overlay_size = n - end_of_sections
    lay.ok = True
    return lay
