"""VirusTotal enrichment — hash-only, cached, offline-capable.

This is an INTEGRATION, not a reinvention. Safety rules, enforced here:
  - HASH ONLY. We look up sha256 via GET /files/{hash}. We NEVER upload the file
    (uploading shares potentially sensitive customer data). There is no code path
    that POSTs a file.
  - Cached on disk, so a re-scan never re-queries (respects the 500/day, 4/min
    public-API limits).
  - Offline-capable: no API key -> reported "unavailable", never silently treated
    as clean. cypher-scope's "never say clean" honesty carries over.

Set VT_API_KEY to enable. The single network seam is `_fetch`, which tests
monkeypatch so the suite needs no key and makes no real request.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

_VT_FILE_URL = "https://www.virustotal.com/api/v3/files/"  # + sha256 (GET only)


@dataclass
class VTResult:
    status: str          # "malicious" | "unknown" | "clean" | "unavailable"
    positives: int = 0
    total: int = 0
    cached: bool = False
    error: Optional[str] = None

    @property
    def available(self) -> bool:
        return self.status != "unavailable"


def _fetch(url: str, headers: dict) -> Tuple[int, dict]:
    """The only network call. GET JSON. Returns (http_status, body). Tests patch this."""
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, {}


def _cache_path(cache_dir: Path, sha256: str) -> Path:
    return cache_dir / f"{sha256}.json"


def vt_lookup(sha256: str, api_key: Optional[str] = None,
              cache_dir: Optional[str] = None) -> VTResult:
    """Hash-only VirusTotal reputation lookup. Never uploads. Offline-safe."""
    api_key = api_key if api_key is not None else os.environ.get("VT_API_KEY")
    cdir = Path(cache_dir) if cache_dir else Path(os.environ.get("CYPHERTRIAGE_VT_CACHE", ".vt_cache"))

    # Cache first — a re-scan must not re-query.
    cpath = _cache_path(cdir, sha256)
    if cpath.exists():
        try:
            d = json.loads(cpath.read_text(encoding="utf-8"))
            return VTResult(status=d["status"], positives=d.get("positives", 0),
                            total=d.get("total", 0), cached=True)
        except Exception:
            pass

    if not api_key:
        return VTResult(status="unavailable", error="no VT_API_KEY (hash lookup disabled)")

    code, body = _fetch(_VT_FILE_URL + sha256, {"x-apikey": api_key, "Accept": "application/json"})
    if code == 404:
        result = VTResult(status="unknown")   # VT has never seen this hash
    elif code == 200:
        stats = (body.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) or {})
        positives = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values()) if stats else 0
        result = VTResult(status="malicious" if positives > 0 else "clean",
                          positives=positives, total=total)
    else:
        return VTResult(status="unavailable", error=f"VT HTTP {code}")

    # Cache the (successful) verdict.
    try:
        cdir.mkdir(parents=True, exist_ok=True)
        cpath.write_text(json.dumps({"status": result.status, "positives": result.positives,
                                     "total": result.total, "ts": time.time()}), encoding="utf-8")
    except Exception:
        pass
    return result
