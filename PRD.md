---
title: "PipeGuard — CI/CD Pipeline Security Auditor PRD"
date: "2026-04-19"
tags:
  - project
  - reference
status: active
due: 2026-05-31
---

# PipeGuard — CI/CD Pipeline Security Auditor

## Overview

PipeGuard is a static analysis tool that audits CI/CD pipeline configuration files for security misconfigurations, supply chain risks, and compliance gaps. It produces prioritised, actionable reports with compliance mappings for ISO 27001, SOC 2, and NIST CSF.

## Problem Statement

**Who is this for?**
Security engineers, DevOps leads, and platform teams in organisations running GitLab CI, GitHub Actions, or Jenkins. Particularly relevant for regulated industries (finance, defence, healthcare) where pipeline security is part of audit scope.

**What problem does it solve?**
CI/CD pipelines are increasingly the highest-value attack surface in software delivery. Common misconfigurations — hardcoded secrets, unpinned images, unprotected deployments, privileged runners — are routinely exploited in supply chain attacks (SolarWinds, Codecov, 3CX). Existing SAST tools scan application code but miss pipeline-level risks. Manual review is slow and inconsistent.

**Why now?**
Software supply chain attacks increased 742% between 2019 and 2022. NIST SSDF and UK NCSC guidance now explicitly requires pipeline security controls. Organisations need automated, auditable evidence of pipeline security posture.

## Success Criteria

- [ ] Correctly identifies ≥90% of known anti-patterns in `bad_pipeline.yml`
- [ ] Zero false positives on `good_pipeline.yml`
- [ ] HTML report renders correctly, self-contained, no CDN
- [ ] Risk score accurately reflects pipeline security posture
- [ ] CLI runs in under 3 seconds for a 500-job pipeline
- [ ] Each finding includes actionable remediation with compliance mapping

## Scope

> **Build strategy:** GitLab CI is the proving ground. We ship and validate the full feature set on GitLab first, then expand to GitHub Actions / Jenkins / SARIF in Slice 6 once the GitLab path is real-world tested.

### Slice 1 — MVP (✅ Complete, 2026-04-19)
- GitLab CI (`.gitlab-ci.yml`) parsing
- 19 deterministic security rules across 6 categories
- HTML report with risk score, findings, compliance mapping
- JSON report output
- CLI interface
- Docker deployment

### Slice 2 — LLM Enrichment (✅ Complete, 2026-04-19)
- Claude + OpenAI provider abstraction
- AI-generated executive summary
- AI-generated action plan
- Optional / graceful degradation if no API key

### Slice 3 — Web UI + REST API + Docker (✅ Complete, 2026-04-19)
- FastAPI app with drag-drop upload
- REST API: `POST /api/scan`, `GET /api/report/{id}`, OpenAPI docs at `/api/docs`
- `docker-compose.yml` with `web`, `cli`, `test` services

### Slice 4 — Policy Engine + Scanner Integrations (✅ Complete, 2026-04-20)
- Python-native policy evaluator + YAML loader (custom org policies)
- 7 built-in policies (POL-001 to POL-007)
- 6 condition types: `no_rule_findings`, `max_findings`, `min_risk_score`, `no_severity`, `min_category_score`, `pipeline_check`
- External scanner integrations: Semgrep CE, OpenSSF Scorecard, GitLab native JSON (all optional)

### Slice 5 — Reporting + Weighted Risk Scoring (✅ Complete, 2026-04-20)
- JSON report (API-ready)
- PDF report (reportlab, 8 sections)
- Weighted A–F scoring across 6 categories with per-category breakdown
- `policies/example_org_policies.yml` reference policy file

### Slice 6 — Multi-Platform Expansion (Planned)
*Originally PRD Slice 2; deferred deliberately so the GitLab path could be validated end-to-end first.*
- GitHub Actions (`.github/workflows/*.yml`) parser
- Jenkins (`Jenkinsfile`) parser
- SARIF output format (for IDE / GitHub Security tab integration)
- Baseline comparison and delta reports

### Deferred (Originally PRD Slice 5)
Not currently planned; revisit once Slice 6 ships and there is real-world usage demanding it.
- Historical tracking and trend analysis
- Scheduled scanning via webhook
- Natural language rule authoring (originally PRD Slice 4)

### Out of Scope
- Runtime pipeline monitoring
- Cloud provider security (AWS IAM, GCP roles)
- Application code SAST
- Container image scanning

## Requirements

### Must Have (Slice 1)

- Parse all GitLab CI YAML constructs: stages, jobs, includes, environments, artifacts, variables, before/after scripts, rules, needs, extends, triggers
- Detect unpinned Docker images (`:latest` or no tag)
- Detect hardcoded secrets in variables
- Detect dangerous shell patterns (`curl | bash`, `eval`, etc.)
- Detect unprotected production deployments
- Detect privileged Docker runner usage
- Detect artifacts without expiry
- Detect missing dependency scanning stages
- Calculate weighted risk score per category and overall
- Map each finding to ISO 27001, SOC 2, NIST CSF controls
- Generate self-contained HTML report
- Generate JSON report
- CLI: `python src/main.py scan --input pipeline.yml --output report.html`

### Should Have (Slice 1)

- Pipeline flow visualisation in HTML report
- Executive summary section
- Remediation roadmap sorted by severity
- Severity filtering in HTML report

### Nice to Have

- Slack/Teams notification integration
- Direct link to GitLab documentation for each rule
- Auto-remediation suggestions as code diffs

## Rule Catalogue

### Pipeline Integrity
| ID | Name | Severity |
|----|------|---------|
| PIPE-001 | Unpinned Docker Images | High |
| PIPE-002 | Unsafe Remote Includes | High |
| PIPE-003 | Dangerous Shell Patterns | Critical |
| PIPE-004 | Unprotected Deploy Jobs | Critical |

### Identity & Access
| ID | Name | Severity |
|----|------|---------|
| IAM-001 | Secrets in Variables | Critical |
| IAM-002 | Unrestricted CI_JOB_TOKEN | Medium |
| IAM-003 | Unmasked Sensitive Variables | Medium |

### Runner Security
| ID | Name | Severity |
|----|------|---------|
| RUN-001 | Shell Executor Indicators | High |
| RUN-002 | Privileged Docker Mode | Critical |
| RUN-003 | Shared Runner Usage | Medium |

### Artifact Handling
| ID | Name | Severity |
|----|------|---------|
| ART-001 | Artifacts Without Expiry | Medium |
| ART-002 | Overly Broad Artifact Paths | Low |
| ART-003 | No Artifact Integrity Validation | Low |

### Deployment Governance
| ID | Name | Severity |
|----|------|---------|
| DEP-001 | Direct-to-Production Without Approval | Critical |
| DEP-002 | Missing Environment Protection | High |
| DEP-003 | No Manual Gate for Production | High |

### Supply Chain
| ID | Name | Severity |
|----|------|---------|
| SC-001 | External Script Execution | Critical |
| SC-002 | Unverified External Includes | High |
| SC-003 | No Dependency Scanning Stage | Medium |

## Risk Scoring Model

Weighted score across 6 categories — each category contributes a percentage of the overall score.

| Category | Weight | Rules |
|----------|--------|-------|
| Pipeline Integrity | 25% | PIPE-001 to PIPE-004 |
| Identity & Access | 20% | IAM-001 to IAM-003 |
| Deployment Governance | 20% | DEP-001 to DEP-003 |
| Supply Chain | 20% | SC-001 to SC-003 |
| Runner Security | 7.5% | RUN-001 to RUN-003 |
| Artifact Handling | 7.5% | ART-001 to ART-003 |

Grade bands:
- A (90–100): Well-secured pipeline
- B (80–89): Good posture, minor issues
- C (70–79): Moderate risk, action recommended
- D (60–69): High risk, immediate action required
- F (<60): Critical risk, do not deploy

> **Note:** This replaces the original simple deduction scheme (start at 100, –25 per Critical, etc.) — the weighted model is what shipped in Slice 5 and is implemented in `src/analyzer/engine.py`.

## Key Links

- [[Project PipeGuard]] — project note
- [[PROJECT-STATE]] — current development state

## Stakeholders

| Role | Person |
|------|--------|
| Owner | JM |
| Developer | JM / Claude |

## Timeline & Milestones

| Milestone | Target Date | Status |
|-----------|-------------|--------|
| Slice 1: Parser + Rules + HTML/JSON + CLI + Docker | 2026-04-19 | ✅ Complete |
| Slice 2: LLM Enrichment | 2026-04-19 | ✅ Complete |
| Slice 3: Web UI + REST API + Docker compose | 2026-04-19 | ✅ Complete |
| Slice 4: Policy Engine + Scanner Integrations | 2026-04-20 | ✅ Complete |
| Slice 5: JSON/PDF Reporters + Weighted Scoring | 2026-04-20 | ✅ Complete |
| Phase A: real-world public GitLab corpus validation (17 projects) | 2026-04-23 | ✅ Complete |
| PRD acceptance criteria 1 & 2 (≥90% TP / 0 FP) | 2026-04-23 | ✅ Met |
| PRD acceptance criterion 3 (<3s on 500-job pipeline) | 2026-04-23 | ✅ Met — 166 ms mean over 5 runs |
| User's own GitLab project end-to-end (`src/scanners/gitlab_native.py`) | TBD | Not started |
| Slice 6: GitHub Actions + Jenkins + SARIF + Baseline | TBD | Not started |

## Budget

| Item | Cost |
|------|------|
| Development (Claude Code) | Time only |
| Infrastructure (if SaaS) | TBD |
| **Total** | TBD |

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| False positives erode trust | High | Test against known-good pipelines |
| YAML schema changes | Medium | Version-specific parsing paths |
| New attack patterns | Medium | Rule update mechanism in Slice 5 |
| Complex anchors/aliases | Low | PyYAML handles natively |

## Log

### 2026-04-19
- PRD created
- Slice 1 scope finalised
- 19 rules defined across 6 categories
- Slices 1–3 built in 2 sessions: parser, 19 rules, HTML report, LLM enrichment, FastAPI web UI
- 52 / 52 tests passing

### 2026-04-20
- Slice 4 built: policy engine (`src/policy/`) with 7 built-in policies, YAML loader, 6 condition types
- Slice 4 built: external scanner integrations (Semgrep CE, OpenSSF Scorecard, GitLab native JSON)
- Slice 5 built: JSON reporter, 8-section PDF reporter (reportlab), weighted A–F scoring
- 124 / 124 tests passing

### 2026-04-23
- Project relocated to standalone repository
- **Tests re-verified post-migration: 124 / 124 passing in 3.51s**
- **PRD reconciled with as-built reality**: original Slice 2 (multi-platform), Slice 4 (AI), and Slice 5 (tracking) numbering had drifted. As-built mapping: Slice 2=LLM, Slice 4=Policy/Scanners, Slice 5=Reporters/Scoring. Multi-platform work re-scoped as Slice 6.
- "GitLab-first" confirmed as deliberate validation strategy (user has GitLab account ready for real-world testing)
- Historical tracking + scheduled webhook scanning explicitly deferred (revisit after Slice 6)

### 2026-04-23 — Phase A: real-world GitLab corpus validation
- Built `scripts/validate_corpus.py` — fetches public `.gitlab-ci.yml` files from 20 seed GitLab projects, runs parser + analyser, writes `tests/corpus_results/SUMMARY.md`
- First run: 14/20 fetched-and-parsed, **3 systematic bugs surfaced**, 1 confirmed strength (perf)
- **Bug 1 — Parser:** GitLab `!reference` tag was unsupported, breaking 3/17 fetched files (gitlab-org/cli, wireshark, freedesktop-sdk). Fixed by extending SafeLoader with a custom constructor in `src/parser/gitlab_parser.py`. After fix: 17/17 parse, 17/17 analyse.
- **Bug 2 — IAM-001:** secret-key regex contained `pat` (Personal Access Token), which matched `*_PATH`/`*_PATTERN`/`*_PATCH` variables — produced 17/17 false-positive Criticals on `gitlab-org/gitlab` alone, causing it to score C 78.8 (correct: A 93.0). Removed `pat` from the pattern (real PATs are caught by `token`/`secret` patterns).
- **Bug 3 — PIPE-004:** deploy-job heuristic used naive substring match on `release`/`publish`/`push`, firing on `*release-build`, `assembleRelease test`, hidden `.template` jobs etc. Tightened heuristic with non-deploy modifier exclusions (`build`, `test`, `lint`, `notify`, etc.) and excluded hidden template jobs from the rule.
- **Bug 4 — RUN-003:** rule fired on every untagged job (10/10 FPs on `good_pipeline.yml`). Restricted to sensitive jobs (deploy / prod-targeting / secret-handling). Updated `good_pipeline.yml` to add explicit `tags:` on its 3 deploy jobs as the canonical example of "well-secured."
- Built `scripts/validate_fixtures.py` — labelled-fixture validator that asserts PRD acceptance criteria 1 & 2 from ground truth.
- **Tests: 124 → 132 (8 new regression tests for the fixes above).**
- **PRD acceptance criteria status:**
  - ✅ Criterion 1 (≥90% TP on `bad_pipeline.yml`): **100% recall, 14/14 expected rules fire**
  - ✅ Criterion 2 (zero FPs on `good_pipeline.yml`): **0 findings, score 100.0 (A)**
  - 🟡 Criterion 3 (CLI <3s on 500-job pipeline): mean 28 ms / max 87 ms across corpus (94-job pipeline). Linear extrapolation: 500 jobs ≈ 460 ms. Effectively met; awaiting a synthetic 500-job fixture for formal closure.
- **gitlab-org/gitlab corpus result post-fixes: A 94.6** (was C 78.8 with the bug). PipeGuard now produces credible findings on its own dogfood target.

## Tasks

- [x] Write PRD
- [x] Build Slice 1 (parser + rules + HTML/JSON + CLI + Docker)
- [x] Build Slice 2 (LLM enrichment)
- [x] Build Slice 3 (Web UI + REST API + Docker compose)
- [x] Build Slice 4 (policy engine + scanner integrations)
- [x] Build Slice 5 (JSON/PDF reporters + weighted scoring)
- [x] Re-verify 124/124 tests post-relocation
- [x] Reconcile PRD with as-built scope
- [x] **Phase A — real-world public GitLab corpus validation** (`scripts/validate_corpus.py`, 17/17 parse-and-analyse)
- [x] **Fix parser: GitLab `!reference` tag now handled** (3/17 corpus parse failures resolved)
- [x] **Fix IAM-001 false positive** on `*_PATH`/`*_PATTERN`/`*_PATCH` variables (`pat` substring removed)
- [x] **Fix PIPE-004 false positives** on build/test/notify jobs and hidden templates
- [x] **Fix RUN-003 noise** — restricted to sensitive jobs only
- [x] **PRD criterion 1 met**: ≥90% TP on `bad_pipeline.yml` (actual: 100% recall, 14/14 rules)
- [x] **PRD criterion 2 met**: zero FPs on `good_pipeline.yml` (score 100.0 A)
- [x] **PRD criterion 3 met**: 500-job synthetic pipeline parse+analyse in 166 ms mean (5 runs, far under 3 s budget). Test in `tests/test_parser.py::TestPerformance`.
- [x] Resolve pydantic UserWarning on `model_used` field (added `model_config['protected_namespaces'] = ()`)
- [x] DEP-002 triage: not a coverage gap. The rule is intentionally narrow (deploy-prod by name AND no env block); `bad_pipeline.yml`'s `deploy_prod` has an env block. The "env block exists but lacks protection rules" case is fundamentally GitLab UI state and not statically discoverable from YAML.
- [ ] Validate against the user's own GitLab project (one bad pipeline run, capture `gl-*-report.json` artifacts to test `src/scanners/gitlab_native.py` end-to-end)
- [ ] Hand-audit remaining real-world Critical findings: graphviz (31), freedesktop-sdk (13), gitlab-org/cli (7), BuildStream (4) — likely legitimate but worth confirming a sample
- [ ] Spot-check why several corpus projects show 0 jobs but 1 finding (their root `.gitlab-ci.yml` is mostly `include:` directives)
- [ ] **Fix POL-003 + SC-003 false negative on `include: template:`** — both fire when pipelines include `Security/Secret-Detection.gitlab-ci.yml` / `Security/Dependency-Scanning.gitlab-ci.yml` because the check inspects job names rather than resolved includes. Surfaced by `tests/fixtures/realworld_demo.gitlab-ci.yml` dry run on 2026-04-24.
- [ ] Slice 6: GitHub Actions parser
- [ ] Slice 6: Jenkins parser
- [ ] Slice 6: SARIF output format
- [ ] Slice 6: Baseline comparison + delta reports
