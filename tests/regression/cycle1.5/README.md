# Cycle 1.5 regression suite

Permanent automated tests for findings closed during ciguard Pentest Cycle 1.5
(2026-05-03 against v0.11.0). Each file is a self-contained PoC that returns
**exit 0 if the fix held** and **exit 1 if the exploit succeeded** (regression).

## How to run

```sh
cd /path/to/ciguard
python -m pip install -e ".[app,mcp]"
for f in tests/regression/cycle1.5/F-*.py; do
  echo "=== $f ==="
  python "$f" || echo "REGRESSION DETECTED"
done
```

CI runs the same loop on every push (see `.github/workflows/ci.yml`).

## Findings tracked here

| ID      | Title                                              | Severity | Fixed in     |
|---------|----------------------------------------------------|----------|--------------|
| F-9.6.1 | `_safe_md_inline` must strip ASCII NUL + C0 chars  | Low      | v0.11.0-1.5fix |

The Info-level F-9.1.1 finding (permissive ASCII OWS in `X-Hub-Signature-256`
header) is **not** tracked here — disposition is "GitHub issue, optional
hardening" per Cycle 1.5 final report §4.2.

## Convention

- One file per finding ID.
- Filename: `F-<row>.<n>-<kebab-case-summary>.py` (or `.sh` for shell PoCs).
- Exit 0 = fix held; exit 1 = regression. **Inverted** from the Cycle-1
  convention where exit 1 meant "fix held" — Cycle 1.5 standardises on the
  more-conventional "exit 0 = test passed".
- PoC body must produce on-disk evidence is NOT required here (these are CI
  regression tests, not engagement-letter-grade evidence captures); but each
  PoC prints clear PASS/FAIL markers per case so log triage is unambiguous.
