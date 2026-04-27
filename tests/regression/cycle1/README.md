# Cycle 1 regression tests

These four PoC scripts re-exercise the four findings from ciguard's first
self-conducted penetration test (Cycle 1, 2026-04-26 → 2026-04-27, closed in
v0.8.2). They run on every push and PR via [`_checks.yml`](../../../.github/workflows/_checks.yml)
and gate Release publish, so a regression cannot silently re-introduce any
of the bugs.

| Script | Finding | GHSA | Pre-fix exit | Post-fix exit |
|---|---|---|---|---|
| `CYCLE-1-001-symlink-escape.sh` | `discover_pipeline_files` follows symlinks | [GHSA-8cxw-cc62-q28v](https://github.com/Jo-Jo98/ciguard/security/advisories/GHSA-8cxw-cc62-q28v) | 0 (CONFIRMED) | **1 (FAILED)** |
| `CYCLE-1-002-container-root.sh` | Container image runs as root | [GHSA-jrm4-4pcf-4763](https://github.com/Jo-Jo98/ciguard/security/advisories/GHSA-jrm4-4pcf-4763) | 0 (CONFIRMED) | **1 (FAILED)** |
| `CYCLE-1-003-sca-unbounded-read.py` | SCA HTTP unbounded read | [GHSA-xw8c-rrvx-f7xq](https://github.com/Jo-Jo98/ciguard/security/advisories/GHSA-xw8c-rrvx-f7xq) | 0 (CONFIRMED) | **1 (FAILED)** |
| `CYCLE-1-004-missing-security-headers.sh` | Web UI missing defence-in-depth headers | [GHSA-7ww3-xvf5-cxwm](https://github.com/Jo-Jo98/ciguard/security/advisories/GHSA-7ww3-xvf5-cxwm) | 0 (CONFIRMED) | **1 (FAILED)** |

## CI semantics

Each PoC script's exit code encodes the outcome:
- **`exit 0`** → EXPLOIT_CONFIRMED (bug present, security regression)
- **`exit 1`** → EXPLOIT_FAILED (fix in place, working as intended)

The CI wrapper inverts these so the workflow step fails only when a regression
appears. See `_checks.yml::regression-cycle1`.

## Local reproduction

```bash
# Symlink + headers + SCA require ciguard installed
pip install -e ".[mcp]"
./tests/regression/cycle1/CYCLE-1-001-symlink-escape.sh        # expect exit 1
python tests/regression/cycle1/CYCLE-1-003-sca-unbounded-read.py  # expect exit 1
./tests/regression/cycle1/CYCLE-1-004-missing-security-headers.sh # expect exit 1

# Container PoC: build the image locally first, then test it
docker build -t ciguard:dev .
IMAGE=ciguard:dev ./tests/regression/cycle1/CYCLE-1-002-container-root.sh  # expect exit 1
```

## Relationship to vault originals

The four scripts here are the **live regression copies**, version-controlled
with the codebase and free to evolve as ciguard refactors.

The investigative artefacts from the original engagement (verbatim PoCs, lab
output, phase-by-phase walkthrough, retest evidence, full report) live in the
vault at `Project ciguard/Pentest Reports/2026-05-12-cycle-1/` and are frozen
as the historical Cycle 1 record.
