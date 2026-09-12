"""Triage orchestrator (Phase 0 + Phase 1).

Ties the primitives into cypher-scope's real result model
(`cypherscope.findings.ScanResult`): same Severity / Confidence / Verdict, the
same CapacityEstimate "residual bound" contract, and the same "never say clean"
honesty. Every capability degrades gracefully — a missing library is reported in
`detectors_unavailable`, never silently dropped.

Phase 0: type-id, hashes, entropy, PE overlay (stdlib).
Phase 1: LIEF/pefile deep parse (imphash, sections, imports, authoritative
overlay), fuzzy hashing (ppdeep/TLSH), high-entropy section channels, YARA-X.
Next: capa->ATT&CK, VirusTotal hash lookup, and the cross-domain cypher-scope
stego/injection pass — all inside cypher-scope's sandbox.
"""
from __future__ import annotations

import os
import tempfile
from . import _compat  # noqa: F401  (ensures cypherscope is importable)
from . import typeid, hashes, entropy, pe, executables, yara_scan, intel, crossdomain

from cypherscope.findings import ScanResult, Finding, Severity, Confidence

_SEV = {
    "info": Severity.INFO,
    "notable": Severity.NOTABLE,
    "suspicious": Severity.SUSPICIOUS,
    "dangerous": Severity.DANGEROUS,
}


def _add_overlay(result: ScanResult, offset: int, size: int, detector: str) -> None:
    result.add(Finding(
        category="structure.overlay",
        summary=f"{size} bytes of overlay follow the last section "
                f"(outside any declared executable structure)",
        severity=Severity.SUSPICIOUS,
        confidence=Confidence.HIGH,
        detector=detector,
        location=f"offset 0x{offset:X}",
        remediation="Recursively triage the overlay; a dropper often hides "
                    "stage-2/config/an appended file here.",
        detail={"overlay_offset": offset, "overlay_size": size},
    ))
    result.capacity.add(
        name="exe.overlay",
        bits=size * 8,
        reason="bytes after the last section belong to no executable structure",
        closed_by="recursive triage of the overlay",
    )


def triage_bytes(data: bytes, filename: str = "sample.bin") -> ScanResult:
    h = hashes.file_hashes(data)
    tid = typeid.identify(data)

    result = ScanResult(
        filename=filename,
        size_bytes=len(data),
        sha256=h["sha256"],
        media_type=tid.media_type,
    )
    result.detail_hashes = dict(h)
    result.detectors_run.append("hashes")

    # Fuzzy hashes (similarity/clustering fuel).
    fz = hashes.fuzzy(data)
    result.detail_fuzzy = {"ssdeep": fz, "tlsh": hashes.tlsh_hash(data)}
    if fz:
        result.detectors_run.append("fuzzy_hash")

    # VirusTotal hash-only enrichment. Offline by default (no VT_API_KEY -> skipped
    # and reported unavailable, never treated as clean). Never uploads the file.
    vt = intel.vt_lookup(h["sha256"])
    if vt.available:
        result.detectors_run.append("virustotal")
        if vt.status == "malicious":
            result.add(Finding(
                category="intel.virustotal",
                summary=f"VirusTotal: {vt.positives}/{vt.total} engines flag this file's hash",
                severity=Severity.DANGEROUS, confidence=Confidence.HIGH, detector="virustotal",
                detail={"positives": vt.positives, "total": vt.total},
            ))
        elif vt.status == "unknown":
            result.add(Finding(
                category="intel.virustotal",
                summary="VirusTotal has not seen this hash before",
                severity=Severity.NOTABLE, confidence=Confidence.LOW, detector="virustotal",
            ))

    # Entropy map (measurement only).
    blocks = entropy.sliding_window(data)
    result.detectors_run.append("entropy")
    result.detail_entropy = {
        "whole_file": round(entropy.shannon(data), 3),
        "max_block": round(entropy.max_block(blocks), 3),
        "blocks": len(blocks),
    }

    is_exe = tid.kind in ("PE", "ELF", "MachO")
    if is_exe:
        if executables.available():
            info = executables.parse(data)
            result.detectors_run.append("lief_deep_parse")
            if info.ok:
                if info.imphash:
                    result.detail_hashes["imphash"] = info.imphash
                result.detail_exe = {
                    "format": info.fmt,
                    "entrypoint": info.entrypoint,
                    "imports": len(info.imports),
                    "sections": [
                        {"name": s.name, "offset": s.offset, "raw_size": s.raw_size,
                         "entropy": round(s.entropy, 3)} for s in info.sections
                    ],
                }
                # Authenticode signature = structural, expected — NOT a payload.
                if info.signed or info.sig_size > 0:
                    result.add(Finding(
                        category="structure.authenticode",
                        summary=f"Authenticode signature present ({info.sig_size} bytes)",
                        severity=Severity.NOTABLE,
                        confidence=Confidence.CONFIRMED,
                        detector="lief_deep_parse",
                        location=f"offset 0x{info.sig_offset:X}",
                        remediation="Verify the certificate chain to confirm the signer.",
                        detail={"sig_offset": info.sig_offset, "sig_size": info.sig_size},
                    ))
                # A validated embedded PE in the residual overlay is the real signal.
                if info.embedded_pe_offset is not None:
                    result.add(Finding(
                        category="structure.embedded_pe",
                        summary=f"A valid embedded PE image begins in the overlay at "
                                f"offset 0x{info.embedded_pe_offset:X}",
                        severity=Severity.SUSPICIOUS,
                        confidence=Confidence.HIGH,
                        detector="lief_deep_parse",
                        location=f"offset 0x{info.embedded_pe_offset:X}",
                        remediation="Carve and recursively triage the embedded image.",
                        detail={"embedded_pe_offset": info.embedded_pe_offset},
                    ))
                # Only overlay that is NOT the signature counts as a residual channel.
                if info.residual_overlay_size > 0:
                    _add_overlay(result, info.residual_overlay_offset,
                                 info.residual_overlay_size, "lief_deep_parse")
                for s in executables.high_entropy_sections(info):
                    result.add(Finding(
                        category="structure.high_entropy_section",
                        summary=f"section {s.name!r} has entropy {s.entropy:.2f} "
                                f"({s.raw_size} bytes) — may be packed/encrypted",
                        severity=Severity.NOTABLE,
                        confidence=Confidence.LOW,
                        detector="lief_deep_parse",
                        location=f"offset 0x{s.offset:X}",
                        remediation="Unpack/emulate (capa/FLOSS or dynamic) to rule out a payload.",
                        detail={"section": s.name, "entropy": round(s.entropy, 3),
                                "raw_size": s.raw_size},
                    ))
                    result.capacity.add(
                        name=f"section.{s.name}.high_entropy",
                        bits=s.raw_size * 8,
                        reason="high-entropy section could hold a packed/encrypted payload",
                        closed_by="unpack/emulate the section (capa/FLOSS/dynamic)",
                    )
            else:
                _fallback_pe(result, data, tid)
        else:
            _fallback_pe(result, data, tid)

    # YARA-X (curated bundled rules).
    if yara_scan.available():
        result.detectors_run.append("yara")
        for m in yara_scan.scan(data):
            result.add(Finding(
                category=f"yara.{m.rule}",
                summary=m.description + (f" [ATT&CK {m.attck}]" if m.attck else ""),
                severity=_SEV.get(m.severity, Severity.NOTABLE),
                confidence=Confidence.MEDIUM,
                detector="yara",
                detail={"rule": m.rule, "attck": m.attck},
            ))

    # Cross-domain pass (the moat): cypher-scope's stego / injection / render-diff
    # engine over the same sample, folded into one result. Failure-isolated.
    xdomain_ran = False
    if crossdomain.available():
        tmp = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix="_sample") as fh:
                fh.write(data)
                tmp = fh.name
            crossdomain.run(tmp, result, filename=filename)
            result.detectors_run.append("crossdomain")
            xdomain_ran = True
        except Exception as exc:  # never let the cross-domain pass break triage
            result.errors.append(f"crossdomain: {type(exc).__name__}: {exc}")
        finally:
            if tmp and os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass

    # Honesty: what has NOT run yet, so a partial scan never looks complete.
    unavailable = ["capa"]
    if not xdomain_ran:
        unavailable += ["cypherscope_stego", "cypherscope_injection"]
    if "virustotal" not in result.detectors_run:
        unavailable.append("virustotal")   # no key / offline — not "clean"
    if not executables.available():
        unavailable.append("lief_deep_parse")
    if not yara_scan.available():
        unavailable.append("yara")
    if not hashes._HAVE_TLSH:
        unavailable.append("tlsh")
    result.detectors_unavailable.extend(unavailable)
    return result


def _fallback_pe(result: ScanResult, data: bytes, tid) -> None:
    """Dependency-free PE overlay detection when LIEF is unavailable."""
    if tid.kind != "PE":
        return
    lay = pe.parse(data)
    result.detectors_run.append("pe_structure")
    if lay.ok and lay.overlay_size > 0:
        _add_overlay(result, lay.overlay_offset, lay.overlay_size, "pe_structure")


def triage_file(path: str) -> ScanResult:
    with open(path, "rb") as f:
        data = f.read()
    return triage_bytes(data, filename=os.path.basename(path))
