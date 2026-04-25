# ciguard

[![CI](https://github.com/Jo-Jo98/ciguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Jo-Jo98/ciguard/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/ciguard.svg)](https://pypi.org/project/ciguard/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Static security auditor for CI/CD pipelines. Scans pipeline configuration files for misconfigurations, supply-chain risks, and compliance gaps. Produces prioritised reports with mappings to ISO 27001, SOC 2, and NIST CSF.

**Supported today:** GitLab CI (`.gitlab-ci.yml`) and GitHub Actions (`.github/workflows/*.yml`)
**In development:** Jenkins (Declarative Pipeline), SARIF output

> **New to ciguard?** [USAGE.md](USAGE.md) is a practical walkthrough — who benefits, five-minute integrations for GitLab CI / GitHub Actions / Docker, organisational policy patterns, and what the audit-grade reports actually contain.

## Why

CI/CD pipelines are increasingly the highest-value attack surface in software delivery. Common misconfigurations — hardcoded secrets, unpinned images, unprotected production deployments, privileged runners — are routinely exploited (SolarWinds, Codecov, 3CX). Existing SAST tools scan application code but miss pipeline-level risks. Manual review is slow and inconsistent.

`ciguard` runs in seconds, produces actionable reports with compliance mapping, and is auditable enough for regulated environments.

## Install

```bash
pip install ciguard
```

Or from source:

```bash
git clone https://github.com/Jo-Jo98/ciguard.git
cd ciguard
pip install -e .
```

## Quick start

```bash
# Scan a pipeline (terminal summary)
ciguard scan --input .gitlab-ci.yml

# HTML report
ciguard scan --input .gitlab-ci.yml --output report.html

# JSON report (CI/API consumption)
ciguard scan --input .gitlab-ci.yml --output report.json --format json

# PDF report (audits, executive review)
ciguard scan --input .gitlab-ci.yml --output report.pdf --format pdf

# SARIF report (uploads to GitHub Code Scanning → Security tab)
ciguard scan --input .github/workflows/release.yml --output ciguard.sarif --format sarif

# Apply organisational policies
ciguard scan --input .gitlab-ci.yml --policies policies/ --output report.html

# Scan a GitHub Actions workflow (auto-detected; --platform overrides)
ciguard scan --input .github/workflows/release.yml --output report.html

# AI-enriched executive summary (optional, requires API key)
ANTHROPIC_API_KEY=sk-ant-... ciguard scan --input .gitlab-ci.yml --llm --output report.html
```

Exit codes: `0` clean, `2` critical findings, `1` error.

## Features

- **Two platforms** — GitLab CI (19 rules) and GitHub Actions (12 rules covering supply-chain, IAM, runner, deploy-governance, plus advanced GHA-specific risks: `pull_request_target` misuse, token-theft windows, `secrets: inherit` to unpinned reusable workflows, bare self-hosted runners). Format auto-detected from the YAML; `--platform` override available.
- **31 deterministic security rules** across 6 categories
  (Pipeline Integrity, Identity & Access, Runner Security, Artifact Handling, Deployment Governance, Supply Chain)
- **Policy engine** — 7 built-in organisational policies + custom YAML policies (built-ins are GitLab-specific in v0.2; GHA-aware built-ins on the v0.2.x roadmap)
- **Scanner integrations** — Semgrep CE, OpenSSF Scorecard, GitLab native security artifacts (all optional, graceful when unavailable)
- **AI enrichment** — optional Claude / OpenAI executive summaries and remediation plans
- **Four report formats** — HTML (dark, self-contained, no CDN), JSON (API-ready), PDF (8 sections, audit-grade), SARIF 2.1.0 (uploads to GitHub Code Scanning → Security tab)
- **Web UI** — drag-and-drop upload, live results, downloadable reports
- **REST API** — FastAPI with OpenAPI docs at `/api/docs`
- **Risk scoring** — weighted A–F grade with per-category breakdown
- **Compliance mapping** — ISO 27001, SOC 2, NIST CSF on every finding

## Validated against real-world pipelines

`ciguard` 0.1 has been validated against 17 public GitLab CI files including the
GitLab project itself, Inkscape, Wireshark, Meltano, fdroid, BuildStream, and
Graphviz. PRD acceptance criteria as of v0.1:

- Recall on labelled bad fixture: **100%** (14/14 expected rules fire)
- False positives on labelled good fixture: **0**
- Performance: **166 ms mean** parse + analyse on a synthetic 500-job pipeline (5-run mean)

Regenerate locally with `python scripts/validate_corpus.py` and `python scripts/validate_fixtures.py`.

## Custom policies

Create YAML files in a `policies/` directory:

```yaml
# policies/my_org.yml
policies:
  - id: "ORG-001"
    name: "No Critical Findings"
    description: "Zero critical findings required before merge"
    severity: critical
    condition:
      type: no_severity
      severity: Critical
    remediation: "Resolve all Critical findings before merging"
    tags: [org, gate]
```

Supported condition types: `no_rule_findings`, `max_findings`, `min_risk_score`, `no_severity`, `min_category_score`, `pipeline_check`. See [`policies/example_org_policies.yml`](policies/example_org_policies.yml) for a full example.

## Risk scoring

Weighted score across 6 categories — each contributes a percentage of the overall score:

| Category | Weight |
|----------|--------|
| Pipeline Integrity | 25% |
| Identity & Access | 20% |
| Deployment Governance | 20% |
| Supply Chain | 20% |
| Runner Security | 7.5% |
| Artifact Handling | 7.5% |

**Grades:** A (90–100), B (80–89), C (70–79), D (60–69), F (<60).

## Running with Docker

```bash
# Build
docker compose build

# Web UI on :8080
docker compose up web

# CLI scan
docker compose run --rm cli --input /pipeline/.gitlab-ci.yml --output /reports/report.html
```

## Roadmap

- **v0.1** — GitLab CI parser, 19 rules, policy engine, scanner integrations, HTML/JSON/PDF reports, AI enrichment, web UI
- **v0.2** — GitHub Actions parser + 7 GHA rules (`uses` SHA pinning, `permissions: write-all`, hardcoded env secrets, privileged services, deploy-without-environment, dangerous shell, unpinned containers) + GHA-aware built-in policies (v0.2.1)
- **v0.3** — SARIF 2.1.0 output + 5 advanced GHA rules (`pull_request_target` safety, token-theft detection, `secrets: inherit` trust, self-hosted runner hygiene, missing `permissions:` block)
- **v0.4** — Jenkins (Declarative Pipeline only)
- **v0.5** — Baseline / delta reports, GitHub Actions Marketplace listing

See [PRD.md](PRD.md) for the full reconciled scope and current task list.

## Development

```bash
# Run tests
pytest tests/ -v

# Coverage
pytest tests/ --cov=src/ciguard --cov-report=html

# Validate against the public real-world corpus
python scripts/validate_corpus.py

# Validate the labelled fixtures (PRD acceptance criteria 1 & 2)
python scripts/validate_fixtures.py
```

## Contributing

Issues and PRs welcome. Please run the full test suite and the fixture validator (`python scripts/validate_fixtures.py`) before submitting — both must pass.

## License

Apache 2.0 — see [LICENSE](LICENSE).
