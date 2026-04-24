---
title: "PipeGuard — CI/CD Pipeline Security Auditor"
date: "2026-04-20"
tags:
  - project
  - project/work
status: active
due: 2026-05-31
---

# PipeGuard — CI/CD Pipeline Security Auditor

## Current Status

**As-built Slices 1–5: ✅ Complete**
**Total tests: 133 / 133 passing in ~2s** (was 124; +9 regression + perf tests from Phase A)

**PRD acceptance criteria — all three met:**
- ✅ Criterion 1 (≥90% TP on `bad_pipeline.yml`): **100% recall, 14/14**
- ✅ Criterion 2 (zero FPs on `good_pipeline.yml`): **0 findings, score 100.0 (A)**
- ✅ Criterion 3 (<3 s on 500-job pipeline): **166 ms mean** across 5 runs (synthetic fixture in `tests/test_parser.py::TestPerformance`)

**Phase A surfaced and fixed 4 systematic bugs:**
1. Parser: `!reference` tag support (3 corpus files unblocked)
2. IAM-001: removed `pat` substring (was matching `*_PATH` etc., 17/17 FPs on gitlab-org/gitlab)
3. PIPE-004: tightened deploy heuristic + skipped hidden templates
4. RUN-003: scoped to sensitive jobs only (was firing on every untagged job)

**Outstanding against PRD:**
- User's own GitLab project end-to-end test (`src/scanners/gitlab_native.py` integration)
- Slice 6 (GitHub Actions + Jenkins + SARIF + baseline diffs) — multi-platform expansion, deliberately deferred until GitLab path is proven

See [[PRD]] for the full reconciled scope and task list.
See `tests/corpus_results/SUMMARY.md` and `tests/corpus_results/FIXTURE_VALIDATION.md` for run outputs.

## What's Built

| Component | Status |
|-----------|--------|
| GitLab CI parser | Complete |
| 19 security rules (6 categories) | Complete |
| HTML report (dark theme) | Complete |
| JSON report exporter | Complete |
| PDF report (reportlab, 8 sections) | Complete |
| LLM enrichment (Claude + OpenAI) | Complete |
| Policy engine (7 built-in + custom YAML) | Complete |
| Scanner integrations (Semgrep, Scorecard, GitLab native) | Complete |
| FastAPI web app + drag-drop UI | Complete |
| Docker + docker-compose | Complete |
| Test suite (124 tests) | Complete |

## Built-in Policies

| ID | Policy | Severity |
|----|--------|----------|
| POL-001 | No Direct-to-Production Deploys | Critical |
| POL-002 | All Docker Images Must Be Pinned | High |
| POL-003 | Secret Detection Must Be Present | High |
| POL-004 | Deploy Jobs Must Have Manual Approval | High |
| POL-005 | Production Environment Must Be Protected | Critical |
| POL-006 | Dependency Scanning Must Be Present | Medium |
| POL-007 | All Includes Must Use SHA Pinning | High |

## Risk Scoring Weights (Slice 5)

| Category | Weight |
|----------|--------|
| Pipeline Integrity | 25% |
| Identity & Access | 20% |
| Runner Security | 7.5% |
| Artifact Handling | 7.5% |
| Deployment Governance | 20% |
| Supply Chain | 20% |

Grade bands: A 90-100 / B 80-89 / C 70-79 / D 60-69 / F <60

## Quick Start

```bash
pip install -r requirements.txt

# Web server
uvicorn src.web.app:app --host 0.0.0.0 --port 8080 --reload

# CLI - terminal summary
python src/main.py scan --input tests/fixtures/bad_pipeline.yml

# CLI - HTML report with custom policies
python src/main.py scan --input pipeline.yml --policies policies/ --output report.html

# CLI - PDF report
python src/main.py scan --input pipeline.yml --output report.pdf --format pdf

# Tests
pytest tests/ -v
```

## Slice Roadmap

| Slice | Focus | Status |
|-------|-------|--------|
| 1 | Parser + Rule Engine + HTML Report | ✅ Complete |
| 2 | LLM enrichment (Claude + OpenAI) | ✅ Complete |
| 3 | Web UI + REST API + Docker | ✅ Complete |
| 4 | Policy Engine + Scanner Integrations | ✅ Complete |
| 5 | JSON/PDF Reporting + Risk Scoring | ✅ Complete |
| — | Real-world GitLab validation | Not started |
| — | PRD acceptance criteria verification | Not started |
| 6 | GitHub Actions + Jenkins + SARIF + Baseline | Not started |

## Log

### 2026-04-19 — Sessions 1-2
- Slices 1-3 built: parser, 19 rules, HTML report, LLM layer, web UI
- 52 / 52 tests passing

### 2026-04-20 — Session 3
- Slice 4: Policy engine (src/policy/) + scanner integrations (src/scanners/)
  - 7 built-in policies, Python-native evaluator, YAML loader
  - Semgrep CE, OpenSSF Scorecard, GitLab native JSON
- Slice 5: JSON reporter, 8-section PDF reporter (reportlab)
  - New weighted scoring + A-F grade bands
  - policies/example_org_policies.yml added
- 124 / 124 tests passing

### 2026-04-23 — Session 4 (Reconciliation)
- Tests re-verified after package layout migration: 124 / 124 passing in 3.51s
- PRD reconciled: as-built Slice 2 (LLM) / 4 (Policy) / 5 (Reporters) had silently re-numbered against original PRD scope
- Multi-platform work (GHA + Jenkins + SARIF + baseline) re-scoped as Slice 6 — deliberately deferred until GitLab path is real-world validated
- User has GitLab account ready for real-world validation
- Cosmetic: pydantic UserWarning on `model_used` field (protected `model_` namespace) — added to PRD task list

### 2026-04-23 — Session 5 (Phase A: real-world validation)
- Built `scripts/validate_corpus.py` (20 public GitLab projects, autocached YAML, summary in `tests/corpus_results/`)
- Built `scripts/validate_fixtures.py` (labelled-fixture validator for PRD criteria 1 & 2)
- Surfaced and fixed 4 systematic bugs (see Current Status above) — all with regression tests
- Tests grew 124 → 132. PRD criteria 1 & 2 met end-to-end.
- gitlab-org/gitlab dogfood: was scoring C 78.8 with 17 FP-Criticals → now A 94.6 with 0 Criticals
- Aggregate corpus Critical findings: 76 → 57 (25% drop, all FP removal)
- New folders: `scripts/`, `tests/corpus/` (gitignored), `tests/corpus_results/` (gitignored)

### 2026-04-23 — Session 6 (quick wins)
- **PRD criterion 3 formally met**: synthetic 500-job pipeline fixture + perf test; 166 ms mean across 5 runs (`tests/test_parser.py::TestPerformance`)
- Resolved pydantic UserWarning by adding `model_config['protected_namespaces'] = ()` to `LLMInsights`
- DEP-002 triage: not a coverage gap; rule is correctly narrow. The "env block exists but lacks GitLab UI protection rules" case is fundamentally not statically discoverable from YAML — out-of-scope by nature.
- Tests: 132 → 133. **All three PRD acceptance criteria now met.**
