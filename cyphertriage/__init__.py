"""Cypher Triage — blue-team static triage for suspicious files.

A sibling of cypher-scope: it does the standard SOC static-triage job and, by
reusing cypher-scope's byte-accounting + hidden-content engine, reports a
residual-capacity bound for executables and finds stego / second-stage /
prompt-injection payloads hidden inside a sample — in one pass.

Phase 0 (this milestone): type-id, crypto hashes, entropy map, and PE overlay
detection, emitted as cypher-scope's ScanResult.
"""
from .triage import triage_bytes, triage_file

__all__ = ["triage_bytes", "triage_file", "__version__"]
__version__ = "0.0.1"
