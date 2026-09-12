"""YARA-X scanning — a curated bundled ruleset plus optional user rules.

YARA is an integration, not a reinvention: the engine is VirusTotal's yara-x. Our
value is the curated rules + mapping matches into the unified report with ATT&CK
metadata. Degrades gracefully when yara-x is not installed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

try:
    import yara_x
    _HAVE_YARA = True
except Exception:
    _HAVE_YARA = False

# A small, honest starter set. Real coverage comes from bundling community rule
# packs later; these demonstrate the mapping and catch a few real signals.
# NOTE: embedded-PE detection is done in executables.find_embedded_pe(), which
# validates a real DOS/PE header in the genuine residual overlay only — a loose
# "MZ"+"PE" YARA string match false-positives on resource tables and string pools
# in every large binary, so it is deliberately NOT a bundled rule here.
_BUNDLED_RULES = r"""
rule upx_packer {
    meta:
        description = "UPX packer section markers present"
        attck = "T1027.002"  // Software Packing
        severity = "notable"
    strings:
        $u1 = "UPX0"
        $u2 = "UPX1"
        $u3 = "UPX!"
    condition:
        2 of them
}

rule suspicious_powershell_download {
    meta:
        description = "PowerShell download-and-exec pattern in strings"
        attck = "T1059.001"
        severity = "suspicious"
    strings:
        $a = "DownloadString" nocase
        $b = "IEX" nocase
        $c = "FromBase64String" nocase
    condition:
        2 of them
}
"""


@dataclass
class YaraMatch:
    rule: str
    description: str
    attck: Optional[str]
    severity: str


def available() -> bool:
    return _HAVE_YARA


def _meta_get(rule, key: str) -> Optional[str]:
    """yara-x exposes rule metadata as an iterable of (key, value) pairs."""
    try:
        for k, v in rule.metadata:
            if k == key:
                return str(v)
    except Exception:
        pass
    return None


def scan(data: bytes, user_rules_source: Optional[str] = None) -> List[YaraMatch]:
    if not _HAVE_YARA:
        return []
    source = _BUNDLED_RULES + ("\n" + user_rules_source if user_rules_source else "")
    try:
        rules = yara_x.compile(source)
        scanner = yara_x.Scanner(rules)
        results = scanner.scan(data)
    except Exception:
        return []

    matches: List[YaraMatch] = []
    for r in getattr(results, "matching_rules", []) or []:
        matches.append(YaraMatch(
            rule=r.identifier,
            description=_meta_get(r, "description") or r.identifier,
            attck=_meta_get(r, "attck"),
            severity=(_meta_get(r, "severity") or "notable").lower(),
        ))
    return matches
