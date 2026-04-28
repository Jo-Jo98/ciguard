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

# Scan an entire repository (auto-discovers every pipeline file under the path)
ciguard scan-repo .
ciguard scan-repo . --fail-on High           # gate CI on aggregate severity
ciguard scan-repo . --output ciguard.json    # write the aggregate JSON

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

- **Three platforms** — GitLab CI (19 rules), GitHub Actions (12 rules covering supply-chain, IAM, runner, deploy-governance, plus advanced GHA-specific risks: `pull_request_target` misuse, token-theft windows, `secrets: inherit` to unpinned reusable workflows, bare self-hosted runners), and Jenkins Declarative Pipelines (6 rules: unpinned docker agents, hardcoded secrets, unconstrained `agent any`, privileged docker args, dangerous shell patterns, dynamic Groovy `script {}` blocks). Format auto-detected by filename / content sniff / YAML shape; `--platform` override available.
- **37 deterministic security rules** across 6 categories
  (Pipeline Integrity, Identity & Access, Runner Security, Artifact Handling, Deployment Governance, Supply Chain)
- **Policy engine** — 17 built-in organisational policies (7 GitLab CI + 6 GitHub Actions + 4 Jenkins) plus custom YAML policies. Each built-in declares the platforms it applies to; the evaluator filters automatically.
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

## MCP server (AI-native integration)

ciguard ships an optional **Model Context Protocol** server that exposes its scanning capabilities as tools any MCP-compatible AI client (Claude Desktop, Claude Code, Cursor, VS Code MCP extensions) can invoke.

```bash
pip install 'ciguard[mcp]'
```

Five tools are registered:

| Tool | Purpose |
|------|---------|
| `ciguard.scan` | Scan a single pipeline file. Returns the full Report. |
| `ciguard.scan_repo` | Walk a directory, discover every pipeline file, scan all. Aggregated severity + per-file summary. |
| `ciguard.explain_rule` | Return canonical metadata for a rule (name / severity / remediation / compliance). |
| `ciguard.diff_baseline` | Run a scan + compute the v0.5 baseline delta. New / resolved / unchanged + score Δ. |
| `ciguard.list_rules` | Enumerate the catalog. Optional `platform` / `severity` filters. |

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "ciguard": {
      "command": "ciguard",
      "args": ["mcp"]
    }
  }
}
```

### Cursor / VS Code MCP extension

```json
{
  "mcp.servers": {
    "ciguard": { "command": "ciguard", "args": ["mcp"] }
  }
}
```

### Why this matters

Unlocks workflows like *"Scan my pipeline and explain the most critical finding"* (model chains `scan` + `explain_rule`), *"Compare current scan against baseline and draft a PR description"* (model chains `scan` + `diff_baseline`), *"Which of my files would benefit from a manual approval gate?"* (model calls `scan_repo` and reasons over the response). ciguard becomes a building block for AI agents, not just a CLI.

### Disabling MCP for managed devices (`CIGUARD_MCP_DISABLED`)

Corporate environments standardising on a centralised MCP gateway can prevent individual devs from running a local ciguard MCP server by setting:

```bash
export CIGUARD_MCP_DISABLED=1
```

When set to `1` / `true` / `yes` / `on` (case-insensitive), `ciguard mcp` exits with a clear policy message and a non-zero exit code before starting the server. Push via MDM (Jamf / Intune), `/etc/environment`, Group Policy, or shell profile to enforce fleet-wide. Unset or any other value → MCP runs normally.

## Suppressing findings (`.ciguardignore`)

Drop a `.ciguardignore` YAML file at your repo root to suppress findings that you've reviewed and accepted. Every entry **must** include a written `reason` — naked rule-id-only disables are rejected by design (auditors need to know *why*).

```yaml
# .ciguardignore
- rule_id: PIPE-001
  location: deploy_prod          # optional — substring match on the finding location
  reason: We pin to digest in the parent template; this image is intentionally tag-tracked.
  expires: 2026-12-31             # optional — emits a warning when the date passes (still suppresses)

- rule_id: SCA-EOL-003
  reason: Internal mirror keeps Python 3.9 alive past upstream EOL until 2026 Q3.
```

Suppressed findings still appear in HTML / PDF / JSON / SARIF reports under a dedicated **Suppressed** section so the audit trail is preserved — they just don't contribute to the risk score or trigger CI failure. Override discovery with `--ignore-file <path>`; disable entirely with `--no-ignore-file`.

## Pre-commit hook

Install ciguard into your `pre-commit` chain to scan pipeline files on every commit:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Jo-Jo98/ciguard
    rev: v0.7.0
    hooks:
      - id: ciguard
```

The hook auto-matches `.gitlab-ci.yml`, `.github/workflows/*.yml`, `Jenkinsfile`, and `*.groovy`. Blocks the commit on Critical / High findings (exit codes `2` / `1`).

## Network egress (corporate / hardened deployments)

Every outbound network call ciguard can make, why it makes it, and how to disable it. Useful for security teams that need to whitelist or air-gap.

| Destination | When | Disable with |
|---|---|---|
| `api.osv.dev` | SCA CVE lookups for GitHub Actions / reusable workflows (rule `SCA-CVE-001`) | `--offline` |
| `endoflife.date` | SCA EOL/EOS lookups for container base images + language runtimes (rules `SCA-EOL-001/002/003`, `SCA-EOS-001`) | `--offline` |
| `api.anthropic.com` / `api.openai.com` | LLM enrichment (executive summary + remediation) — **opt-in only** | omit `--llm` (default) |
| Semgrep registry, OpenSSF Scorecard | External scanner integrations — only run when their binaries are installed and present on PATH | `--no-scanners` (or `CIGUARD_NO_SCANNERS=1`) |

`--offline` covers the SCA path: cache-only reads, no HTTP. `--no-scanners` disables the external-binary lane (Semgrep / Scorecard / GitLab native) entirely. Use both together for a fully hardened, network-free run:

```bash
ciguard scan-repo . --offline --no-scanners
```

LLM enrichment is opt-in via `--llm` and never runs by default. When opted in, ciguard sends rule names, locations, finding descriptions, and compliance mappings (evidence is stripped before send) to the configured provider. Regulated users should pass `--llm-consent` to acknowledge and `--redact-locations` to additionally hash file paths and pipeline names before they reach the LLM (see `ciguard scan --help`).

The `mcp` server reads/writes only the local filesystem (no outbound network). Set `CIGUARD_MCP_ROOT=/path/to/workspace` to refuse paths outside an allowlist — defence-in-depth against adversarial-prompt path-traversal in AI-agent flows.

The web API reads/writes only the local in-memory scan store. Set `CIGUARD_WEB_TOKEN=<random>` to require `Authorization: Bearer <token>` on `/api/scan`, `/api/report/*`, and `/report/*` — required for any non-loopback bind.

## Verifying releases (Sigstore + SBOMs)

From v0.9.2 onwards, every release is signed and attested via [Sigstore](https://www.sigstore.dev/) using GitHub Actions OIDC (no long-lived signing keys). The published GHCR image carries:

- **A keyless Sigstore signature** binding the image digest to the workflow identity (`Jo-Jo98/ciguard/.github/workflows/release.yml@refs/tags/v<X.Y.Z>`).
- **CycloneDX + SPDX SBOMs** as cosign attestations — high-fidelity dependency manifests produced by syft against the actual built layers.

PyPI uploads carry [PEP 740 attestations](https://docs.pypi.org/attestations/) automatically (visible at https://pypi.org/project/ciguard/#files).

### Verify a release

Install [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) once, then:

```bash
# 1. Verify the image signature (binds the GHCR image to *this* workflow + tag)
cosign verify ghcr.io/jo-jo98/ciguard:v0.9.2 \
  --certificate-identity-regexp '^https://github\.com/Jo-Jo98/ciguard/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# 2. Pull and inspect the CycloneDX SBOM attestation
cosign verify-attestation ghcr.io/jo-jo98/ciguard:v0.9.2 \
  --type cyclonedx \
  --certificate-identity-regexp '^https://github\.com/Jo-Jo98/ciguard/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  | jq -r '.payload | @base64d | fromjson | .predicate' > ciguard-cdx.json

# 3. Same for SPDX (regulators / EO 14028 lane prefer this format)
cosign verify-attestation ghcr.io/jo-jo98/ciguard:v0.9.2 \
  --type spdxjson \
  --certificate-identity-regexp '^https://github\.com/Jo-Jo98/ciguard/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  | jq -r '.payload | @base64d | fromjson | .predicate' > ciguard-spdx.json
```

The signature + attestations are also recorded in [Sigstore's public Rekor transparency log](https://search.sigstore.dev/) — anyone can audit them post-hoc, without trusting GitHub or ciguard.

### What this protects against

- **Maintainer-account compromise.** A stolen PyPI / GHCR token cannot republish a wheel/image with a valid signature unless the attacker also compromises the GitHub Actions OIDC chain. PEP 740 attestations on PyPI catch the same.
- **Supply-chain insertion.** Any image not signed by *this* workflow fails verification — downstream consumers running `cosign verify` notice immediately.
- **Audit gaps.** SBOMs answer "what's actually in this image" in two formats SAST / SCA / regulator tools speak natively.

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
