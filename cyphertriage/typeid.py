"""Content-based type identification for executables (magic-byte level).

Deliberately minimal and dependency-free: enough to route a sample to the right
parser and to catch an extension that lies about the content. Deeper parsing
(LIEF/pefile) is a later phase and runs in the sandbox.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TypeId:
    kind: str            # "PE", "ELF", "MachO", "DOTNET", "unknown"
    media_type: str      # a MIME-ish label for the report
    detail: str = ""


def identify(data: bytes) -> TypeId:
    if len(data) >= 2 and data[:2] == b"MZ":
        # Could be DOS/PE. Confirm the PE signature via e_lfanew.
        if len(data) >= 0x40:
            e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
            if 0 < e_lfanew < len(data) - 4 and data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
                return TypeId("PE", "application/vnd.microsoft.portable-executable", "PE signature at e_lfanew")
        return TypeId("PE", "application/x-dosexec", "MZ header, PE signature not confirmed")
    if data[:4] == b"\x7fELF":
        return TypeId("ELF", "application/x-elf", "ELF magic")
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return TypeId("MachO", "application/x-mach-binary", "Mach-O magic")
    if data[:4] == b"\xca\xfe\xba\xbe":
        return TypeId("MachO", "application/x-mach-binary", "Mach-O universal (fat) binary")
    return TypeId("unknown", "application/octet-stream", "")
