"""Phase 0 tests for Cypher Triage — real inputs, verified against ground truth."""
import hashlib
import struct
import sys
from pathlib import Path

# Make the package importable when running pytest from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cyphertriage import triage_bytes
from cyphertriage import typeid, entropy, pe
from cypherscope.findings import Verdict, Severity


def make_min_pe(overlay: bytes = b"") -> bytes:
    """Construct a minimal but structurally valid PE with an optional overlay."""
    e_lfanew = 0x40
    dos = b"MZ" + b"\x00" * (0x3C - 2) + struct.pack("<I", e_lfanew)  # 0x40 bytes
    pe_sig = b"PE\x00\x00"
    # COFF: Machine, NumberOfSections=1, TimeDateStamp, PtrSym, NumSym, SizeOptHdr=0, Chars
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0, 0)
    section_data = b"\x90" * 16
    raw_off = 0x80  # dos(0x40)+pe_sig(4)+coff(20)+sec(40) = 0x80
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text", 0x10, 0x1000, len(section_data), raw_off, 0, 0, 0, 0, 0x60000020,
    )
    blob = dos + pe_sig + coff + section
    assert len(blob) == raw_off, f"header layout off: {len(blob):#x} != {raw_off:#x}"
    return blob + section_data + overlay


# ── type identification ──────────────────────────────────────────────────────
def test_typeid_pe():
    assert typeid.identify(make_min_pe()).kind == "PE"

def test_typeid_elf():
    assert typeid.identify(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32).kind == "ELF"

def test_typeid_macho():
    assert typeid.identify(b"\xcf\xfa\xed\xfe" + b"\x00" * 32).kind == "MachO"

def test_typeid_unknown_text():
    assert typeid.identify(b"just some text\n" * 10).kind == "unknown"


# ── hashes ───────────────────────────────────────────────────────────────────
def test_sha256_matches_ground_truth():
    data = b"the quick brown fox" * 100
    r = triage_bytes(data, "fox.bin")
    assert r.sha256 == hashlib.sha256(data).hexdigest()
    assert r.detail_hashes["md5"] == hashlib.md5(data).hexdigest()


# ── entropy ──────────────────────────────────────────────────────────────────
def test_entropy_bounds():
    assert entropy.shannon(b"\x00" * 4096) == 0.0            # zero information
    high = entropy.shannon(bytes(range(256)) * 16)
    assert 7.99 <= high <= 8.0                                # uniform ~ 8 bits/byte


# ── PE overlay = the byte-attribution seed (the moat) ────────────────────────
def test_pe_overlay_detected_with_exact_size():
    overlay = b"SECOND_STAGE_PAYLOAD_" * 5
    data = make_min_pe(overlay)
    lay = pe.parse(data)
    assert lay.ok and lay.overlay_size == len(overlay)

    r = triage_bytes(data, "dropper.exe")
    overlay_findings = [f for f in r.findings if f.category == "structure.overlay"]
    assert len(overlay_findings) == 1
    assert overlay_findings[0].severity == Severity.SUSPICIOUS
    assert overlay_findings[0].detail["overlay_size"] == len(overlay)
    # Residual-capacity channel is recorded with the exact byte count.
    chans = [c for c in r.capacity.channels if c.name == "exe.overlay"]
    assert len(chans) == 1 and chans[0].bits // 8 == len(overlay)
    assert r.verdict == Verdict.SUSPICIOUS

def test_clean_pe_has_no_overlay_and_reads_clean():
    r = triage_bytes(make_min_pe(b""), "clean.exe")
    assert not [f for f in r.findings if f.category == "structure.overlay"]
    # No malware-side alarm. (The cross-domain pass may add benign NOTABLE context
    # such as "unknown_type" on a synthetic stub PE, so allow NO_INDICATORS/NOTABLE.)
    assert r.verdict in (Verdict.NO_INDICATORS, Verdict.NOTABLE)

def test_never_dumps_payload_bytes():
    # The overlay content must not be echoed back in any finding (triage, not leak).
    secret = b"DO_NOT_ECHO_THIS_SECRET_PAYLOAD"
    r = triage_bytes(make_min_pe(secret), "x.exe")
    blob = repr(r.findings).encode()
    assert secret not in blob


# ── honesty: never looks complete when detectors are missing ─────────────────
def test_detectors_unavailable_is_surfaced():
    # capa + VirusTotal are not wired yet, so they must always be surfaced as
    # not-run regardless of which optional libs happen to be installed.
    r = triage_bytes(make_min_pe(), "x.exe")
    for missing in ("capa", "virustotal"):
        assert missing in r.detectors_unavailable
