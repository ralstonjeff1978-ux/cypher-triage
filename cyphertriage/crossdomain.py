"""Cross-domain pass (Phase 3) — the moat.

Runs cypher-scope's full hidden-content pipeline (byte-attribution, stego,
text-surface / prompt-injection, render-vs-extract, metadata) over the same
sample and folds its findings into the triage result. That is the thing no other
triage tool does: in one pass you get the malware view AND the stego / second-
stage / prompt-injection view — including injection aimed at the AI-assisted
SOC's own model. It requires cypher-scope's whole engine underneath, which is
why a competitor cannot bolt it on.

cypher-scope uses the SAME findings model this package imports, so its findings
and capacity channels merge directly. Failure-isolated by the caller.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from . import _compat  # noqa: F401  (ensures cypherscope importable)


def available() -> bool:
    try:
        import cypherscope.pipeline  # noqa: F401
        return True
    except Exception:
        return False


def run(path: str, result, filename: Optional[str] = None):
    """Run cypher-scope on `path` and merge its findings/capacity into `result`.
    Returns the number of cross-domain findings merged."""
    from cypherscope import pipeline as cs_pipeline

    cs = cs_pipeline.scan(Path(path), filename or result.filename)

    existing = {(f.category, f.summary) for f in result.findings}
    merged = 0
    for f in cs.findings:
        # cypher-scope's own structural/no-parser notes aren't triage signal here.
        if f.category in ("scan.no_parser",):
            continue
        if (f.category, f.summary) not in existing:
            result.findings.append(f)
            existing.add((f.category, f.summary))
            merged += 1

    # Merge residual-capacity channels (hidden-payload bound from the other engine).
    for ch in getattr(cs.capacity, "channels", []):
        result.capacity.channels.append(ch)

    for d in cs.detectors_run:
        tag = f"cypherscope.{d}"
        if tag not in result.detectors_run:
            result.detectors_run.append(tag)

    return merged
