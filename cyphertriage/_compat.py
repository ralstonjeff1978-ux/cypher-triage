"""Locate the cypher-scope package (`cypherscope`) so this sibling can reuse its
data model, sandbox, and report layers without duplicating them.

cypher-scope is not yet pip-installable (no build backend in its pyproject), so we
add its source directory to sys.path. Order of resolution:
  1. If `cypherscope` already imports, use it.
  2. Else the CYPHERSCOPE_PATH env var, if set.
  3. Else a couple of conventional sibling locations.

This is the ONLY place that knows where cypher-scope lives; everything else just
does `from cypherscope import ...`.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def ensure_cypherscope() -> None:
    try:
        import cypherscope  # noqa: F401
        return
    except ImportError:
        pass

    candidates = []
    env = os.environ.get("CYPHERSCOPE_PATH")
    if env:
        candidates.append(Path(env))
    # sibling of this repo, and a couple of common dev locations
    here = Path(__file__).resolve()
    candidates.append(here.parent.parent.parent / "cypher-scope")
    candidates.append(Path("F:/cypher-scope"))

    for c in candidates:
        if c and (c / "cypherscope" / "__init__.py").exists():
            sys.path.insert(0, str(c))
            return

    raise ImportError(
        "cypher-scope not found. Set CYPHERSCOPE_PATH to its checkout directory "
        "(the folder that contains the 'cypherscope' package)."
    )


ensure_cypherscope()
