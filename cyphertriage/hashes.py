"""Cryptographic file hashes (stdlib only).

Fuzzy hashes (ssdeep via ppdeep, TLSH) and imphash (via pefile/LIEF) arrive in a
later phase; they are integrations, not reinventions. This module stays pure
stdlib so it always works offline with no build pain.
"""
from __future__ import annotations

import hashlib
from typing import Dict, Optional

try:
    import ppdeep  # pure-python ssdeep (CTPH fuzzy hash)
    _HAVE_PPDEEP = True
except Exception:
    _HAVE_PPDEEP = False

try:
    import tlsh  # locality-sensitive hash (needs a C build; optional)
    _HAVE_TLSH = True
except Exception:
    _HAVE_TLSH = False

_ALGOS = ("md5", "sha1", "sha256", "sha512")


def file_hashes(data: bytes) -> Dict[str, str]:
    """Return the standard crypto hashes of `data` as hex strings."""
    return {name: hashlib.new(name, data).hexdigest() for name in _ALGOS}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fuzzy(data: bytes) -> Optional[str]:
    """Context-triggered piecewise (ssdeep-style) fuzzy hash, or None if unavailable."""
    if not _HAVE_PPDEEP:
        return None
    try:
        return ppdeep.hash(data)
    except Exception:
        return None


def fuzzy_compare(a: str, b: str) -> Optional[int]:
    """Similarity 0-100 between two fuzzy hashes, or None if unavailable."""
    if not _HAVE_PPDEEP or not a or not b:
        return None
    try:
        return int(ppdeep.compare(a, b))
    except Exception:
        return None


def tlsh_hash(data: bytes) -> Optional[str]:
    """TLSH locality-sensitive hash, or None if the optional lib is absent."""
    if not _HAVE_TLSH:
        return None
    try:
        h = tlsh.hash(data)
        return h if h and h != "TNULL" else None
    except Exception:
        return None
