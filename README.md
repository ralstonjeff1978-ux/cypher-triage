# Cypher Triage

Blue-team **static triage** for suspicious files — a sibling of
[cypher-scope](https://github.com/ralstonjeff1978-ux/cypher-scope) that reuses its
byte-accounting and hidden-content engine.

It does the standard SOC static-triage job (hashes, type-id, entropy, structure)
and — uniquely — reports a **residual hidden-payload bound** for an executable and,
in the same pass, looks for the stego / second-stage / prompt-injection payloads
hidden *inside* the sample. Nobody else does the second half, because it requires
cypher-scope underneath.

> **Never generates or executes malware.** It reads and classifies only. No LLM in
> the scan path. It never claims a file is "clean" — it reports what ran and what
> it could not see.

## Status
**Phase 0 (current):** type identification (PE/ELF/Mach-O), crypto hashes, entropy
map, and PE **overlay / residual-capacity** detection — emitted as cypher-scope's
`ScanResult`. Fully tested, dependency-free.

**Next (Phase 1):** LIEF/pefile deep parse, YARA-X, capa→ATT&CK, VirusTotal
hash lookup, and the cross-domain cypher-scope stego/injection pass — all inside
cypher-scope's hardened sandbox.

## Layout
- `cyphertriage/typeid.py` — magic-byte type identification
- `cyphertriage/hashes.py` — md5/sha1/sha256/sha512
- `cyphertriage/entropy.py` — Shannon entropy (file + sliding window)
- `cyphertriage/pe.py` — bounds-checked PE structure + overlay parser
- `cyphertriage/triage.py` — orchestrator → `cypherscope.findings.ScanResult`

## Develop
cypher-scope must be importable. Either set `CYPHERSCOPE_PATH` to its checkout,
or keep it as a sibling directory. Then:

```
python -m pytest -q
```

## License
MIT
