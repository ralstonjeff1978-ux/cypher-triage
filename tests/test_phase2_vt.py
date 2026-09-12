"""Phase 2 tests: VirusTotal hash-only enrichment (mocked — no key, no network)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cyphertriage import intel, triage_bytes
from cypherscope.findings import Severity


def _stats_body(malicious=0, suspicious=0, harmless=50, undetected=20):
    return (200, {"data": {"attributes": {"last_analysis_stats": {
        "malicious": malicious, "suspicious": suspicious,
        "harmless": harmless, "undetected": undetected}}}})


def test_unavailable_without_key(tmp_path):
    r = intel.vt_lookup("a" * 64, api_key=None, cache_dir=str(tmp_path))
    assert r.status == "unavailable"
    assert r.available is False


def test_parses_malicious(monkeypatch, tmp_path):
    monkeypatch.setattr(intel, "_fetch", lambda url, headers: _stats_body(malicious=40, suspicious=3))
    r = intel.vt_lookup("b" * 64, api_key="k", cache_dir=str(tmp_path))
    assert r.status == "malicious"
    assert r.positives == 43 and r.total == 113


def test_unknown_on_404(monkeypatch, tmp_path):
    monkeypatch.setattr(intel, "_fetch", lambda url, headers: (404, {}))
    r = intel.vt_lookup("c" * 64, api_key="k", cache_dir=str(tmp_path))
    assert r.status == "unknown"


def test_cache_prevents_second_query(monkeypatch, tmp_path):
    calls = {"n": 0}
    def fake(url, headers):
        calls["n"] += 1
        return _stats_body(malicious=1)
    monkeypatch.setattr(intel, "_fetch", fake)
    sha = "d" * 64
    intel.vt_lookup(sha, api_key="k", cache_dir=str(tmp_path))
    r2 = intel.vt_lookup(sha, api_key="k", cache_dir=str(tmp_path))
    assert calls["n"] == 1 and r2.cached is True   # served from cache, no re-query


def test_hash_only_never_uploads(monkeypatch, tmp_path):
    seen = {}
    def fake(url, headers):
        seen["url"] = url
        return _stats_body(harmless=70)
    monkeypatch.setattr(intel, "_fetch", fake)
    sha = "e" * 64
    intel.vt_lookup(sha, api_key="k", cache_dir=str(tmp_path))
    # The only request is a GET of /files/{hash}; the file itself is never sent.
    assert seen["url"] == intel._VT_FILE_URL + sha


def test_triage_offline_marks_vt_unavailable(monkeypatch, tmp_path):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.setenv("CYPHERTRIAGE_VT_CACHE", str(tmp_path))
    r = triage_bytes(b"hello world" * 20, "x.txt")
    assert "virustotal" in r.detectors_unavailable
    assert "virustotal" not in r.detectors_run


def test_triage_flags_malicious_hash(monkeypatch, tmp_path):
    monkeypatch.setenv("VT_API_KEY", "k")
    monkeypatch.setenv("CYPHERTRIAGE_VT_CACHE", str(tmp_path))
    monkeypatch.setattr(intel, "_fetch", lambda url, headers: _stats_body(malicious=55))
    r = triage_bytes(b"suspicious content" * 10, "x.bin")
    vt = [f for f in r.findings if f.category == "intel.virustotal"]
    assert vt and vt[0].severity == Severity.DANGEROUS
    assert "virustotal" in r.detectors_run
