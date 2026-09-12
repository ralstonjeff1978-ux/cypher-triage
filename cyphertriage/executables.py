"""Deep executable parsing via LIEF (PE/ELF/Mach-O) + pefile (imphash).

This supersedes the Phase-0 stdlib `pe.py` overlay math with LIEF's authoritative
parse when the library is available, and it sharpens the byte-attribution model:
headers, each section, and the overlay are attributed, and what's left over (or
suspiciously high-entropy) becomes a named residual-capacity channel.

LIEF/pefile have CVE histories, so in production this runs inside cypher-scope's
sandbox. Here it degrades gracefully: if a library is missing, the caller falls
back to the dependency-free `pe.py`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

try:
    import lief
    _HAVE_LIEF = True
except Exception:
    _HAVE_LIEF = False

try:
    import pefile
    _HAVE_PEFILE = True
except Exception:
    _HAVE_PEFILE = False

# Sections at/above this entropy are flagged as a possible packed/encrypted payload
# region. Deliberately conservative (compressed resources/.NET run ~7.0+ legitimately),
# so this is a capacity channel to be *ruled out*, never a standalone verdict.
_HIGH_ENTROPY = 7.4


@dataclass
class SectionInfo:
    name: str
    offset: int
    raw_size: int
    virtual_size: int
    entropy: float


@dataclass
class ExeInfo:
    ok: bool
    fmt: str = "unknown"          # "PE" | "ELF" | "MachO"
    arch: str = ""
    entrypoint: int = 0
    sections: List[SectionInfo] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    imphash: Optional[str] = None
    overlay_offset: int = 0
    overlay_size: int = 0
    # Authenticode signature (the cert table lives after the last section, so LIEF
    # counts it as overlay — we must NOT treat a legitimate signature as a payload).
    signed: bool = False
    sig_offset: int = 0
    sig_size: int = 0
    # Overlay that is NOT the signature — the genuine residual channel.
    residual_overlay_offset: int = 0
    residual_overlay_size: int = 0
    # Offset of a validated embedded PE inside the residual overlay, if any.
    embedded_pe_offset: Optional[int] = None
    error: Optional[str] = None


def available() -> bool:
    return _HAVE_LIEF


def parse(data: bytes) -> ExeInfo:
    if not _HAVE_LIEF:
        return ExeInfo(ok=False, error="lief not available")
    try:
        b = lief.parse(list(data))
    except Exception as e:  # LIEF should not raise, but never let it crash triage
        return ExeInfo(ok=False, error="lief parse error: %s" % e)
    if b is None:
        return ExeInfo(ok=False, error="not a recognised executable")

    fmt = str(getattr(b, "format", "")).split(".")[-1]  # FORMATS.PE -> "PE"
    info = ExeInfo(ok=True, fmt=fmt)
    try:
        info.entrypoint = int(b.entrypoint)
    except Exception:
        pass

    for s in getattr(b, "sections", []) or []:
        try:
            info.sections.append(SectionInfo(
                name=str(s.name),
                offset=int(getattr(s, "offset", 0)),
                raw_size=int(getattr(s, "size", 0)),
                virtual_size=int(getattr(s, "virtual_size", 0)),
                entropy=float(getattr(s, "entropy", 0.0)),
            ))
        except Exception:
            continue

    # Imports (names differ a little per format; be defensive)
    try:
        if fmt == "PE":
            info.imports = [str(i.name) for i in getattr(b, "imports", []) if getattr(i, "name", None)]
        else:
            info.imports = [str(x) for x in getattr(b, "imported_functions", [])][:200]
    except Exception:
        pass

    # Overlay (bytes after the last section) — LIEF computes this authoritatively.
    try:
        overlay = bytes(b.overlay)
        if overlay:
            info.overlay_size = len(overlay)
            info.overlay_offset = len(data) - len(overlay)
    except Exception:
        pass

    # Authenticode: the certificate table is legitimately appended after the last
    # section, so LIEF reports it as overlay. Attribute it as structural and
    # subtract it, so we never flag a signed binary as "carrying a payload".
    if fmt == "PE":
        try:
            if getattr(b, "has_signatures", False):
                info.signed = True
            dd = b.data_directory(lief.PE.DataDirectory.TYPES.CERTIFICATE_TABLE)
            if dd and int(dd.size) > 0:
                info.sig_offset = int(dd.rva)   # for the cert table, rva is a file offset
                info.sig_size = int(dd.size)
        except Exception:
            pass

    # Residual overlay = overlay bytes that are NOT the signature.
    if info.overlay_size > 0:
        n = len(data)
        ov_lo, ov_hi = info.overlay_offset, n
        if info.sig_size > 0:
            sig_lo, sig_hi = info.sig_offset, info.sig_offset + info.sig_size
            inter = max(0, min(ov_hi, sig_hi) - max(ov_lo, sig_lo))
        else:
            inter = 0
        info.residual_overlay_size = info.overlay_size - inter
        info.residual_overlay_offset = ov_lo
        # Only look for an embedded PE in the genuine residual region.
        if info.residual_overlay_size > 0:
            info.embedded_pe_offset = find_embedded_pe(data, ov_lo, ov_hi, skip_signature=(info.sig_offset, info.sig_size))

    # imphash (PE only) via pefile — the reference implementation.
    if fmt == "PE" and _HAVE_PEFILE:
        try:
            pe = pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )
            info.imphash = pe.get_imphash() or None
        except Exception:
            info.imphash = None

    return info


def high_entropy_sections(info: ExeInfo) -> List[SectionInfo]:
    return [s for s in info.sections if s.entropy >= _HIGH_ENTROPY and s.raw_size > 0]


def find_embedded_pe(data: bytes, start: int, end: int,
                     skip_signature=(0, 0)) -> Optional[int]:
    """Find a *validated* embedded PE image in data[start:end].

    Unlike a loose "MZ"+"PE" string match (which false-positives on resource
    tables and string pools), this requires a real DOS header whose e_lfanew
    points to a valid "PE\\x00\\x00" signature. Bytes inside the Authenticode
    signature blob are skipped.
    """
    sig_lo, sig_size = skip_signature
    sig_hi = sig_lo + sig_size
    n = len(data)
    i = max(start, 0)
    end = min(end, n)
    while i < end:
        j = data.find(b"MZ", i, end)
        if j < 0:
            return None
        if sig_size and sig_lo <= j < sig_hi:   # inside the signature — skip
            i = sig_hi
            continue
        if j + 0x40 <= n:
            e_lfanew = int.from_bytes(data[j + 0x3C:j + 0x40], "little")
            p = j + e_lfanew
            if 0 < e_lfanew < (n - j) and p + 4 <= n and data[p:p + 4] == b"PE\x00\x00":
                return j
        i = j + 2
    return None
