# ciguard

[![CI](https://github.com/Jo-Jo98/ciguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Jo-Jo98/ciguard/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/ciguard.svg)](https://pypi.org/project/ciguard/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**Visualise + audit CI/CD pipeline security — auditor-grade reports from your terminal.**
Read-only · self-hosted · never phones home.

ciguard ingests your pipeline configuration (GitHub Actions, GitLab CI, Jenkins) and produces an interactive HTML map showing every job, every dependency, and every security gate — plus a rule-driven finding set anchored to SLSA / NIST SSDF / OWASP CICD-SEC / CIS / PCI DSS standards. Single-file deliverable, suitable for a contractor handing audit results to a client or an internal security team running quarterly posture reviews.

**Supported parsers:** GitLab CI, GitHub Actions, Jenkins (Declarative + node-Scripted + shared library)
**Output formats:** interactive HTML map *(in development, Slice 14a)*, SARIF 2.1.0, PDF, JSON, HTML
**Integrations:** drop-in CI templates (GitHub Actions / GitLab CI / Jenkins), Model Context Protocol server for AI clients, GitHub App for live PR feedback

> **New to ciguard?** [USAGE.md](USAGE.md) is a practical walkthrough — who benefits, five-minute integrations for GitLab CI / GitHub Actions / Docker, organisational policy patterns, and what the audit-grade reports actually contain.

> **Note on the framing:** ciguard's product framing was repositioned 2026-04-30 from "static security auditor" (a scanner that publishes findings) to "self-hosted audit visualiser" (auditor-grade visual deliverables). The 44-rule scanner is now the *engine* under the visualiser; the visualiser deliverable lands in the v0.11.x slice. The product before that point still works as a scanner — and the engine, parsers, rules, baseline-delta, SCA enrichment, MCP server, and GitHub App framework all carry forward. Everything below this banner describes the engine's current capabilities; the visualiser-as-product framing is what's coming next.

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
- **46 deterministic security rules** across 6 categories
  (Pipeline Integrity, Identity & Access, Runner Security, Artifact Handling, Deployment Governance, Supply Chain),
  including a cross-platform pin-discipline family (`SCA-PIN-001/002/004`) covering digest pinning, mutable-tag detection, and Helm chart version pinning
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

### What ciguard MCP can see (`CIGUARD_MCP_REDACT_LEVEL`)

Every MCP response passes through a redaction layer before reaching the AI client. Three levels — set `CIGUARD_MCP_REDACT_LEVEL` to choose:

| Level | Default? | What the LLM sees |
|---|---|---|
| `full` | ✅ | absolute paths → basename only; finding `evidence` → 8-char SHA-256 fingerprint (`redacted:abc12345`); 256 KB response cap |
| `partial` | | paths relative to `CIGUARD_MCP_ROOT` (or basename); evidence preserved; 1 MB cap |
| `raw` | | passthrough; 10 MB safety cap |

The fingerprint is stable — the same evidence string always hashes to the same value, so an LLM agent can still de-dupe and reference findings without ever seeing the underlying string. Unknown / typo'd values fall back to `full` (fail-safe).

**Per-tool data exposure (at default `full`):**

| Tool | What it returns at `full` (default) | What `raw` adds |
|---|---|---|
| `ciguard.scan` | per-finding rule_id / severity / category / location + fingerprinted evidence; pipeline_name as basename | full evidence strings + absolute paths |
| `ciguard.scan_repo` | per-file score + finding counts; aggregate severity totals; paths as basenames | per-file absolute paths + full per-finding evidence |
| `ciguard.explain_rule` | rule metadata only — no repo data crosses the boundary | (same — no extra surface) |
| `ciguard.diff_baseline` | new/resolved finding lists with fingerprinted evidence; basename paths | full evidence + absolute file/baseline paths |
| `ciguard.list_rules` | rule catalog only — no repo data | (same) |

**Audit trail:** every MCP invocation appends one JSONL record at `~/.ciguard/mcp-audit.jsonl` (override with `CIGUARD_MCP_AUDIT_PATH`, disable with `CIGUARD_MCP_AUDIT_DISABLED=1`). Each record carries `{ts, tool, redact_level, args, response_bytes, had_error}`. The `args` object is redaction-aware — what the audit log captures matches what the response leaked, no more. `tail -f ~/.ciguard/mcp-audit.jsonl` shows the AI agent's tool calls in real time during incident response.

**Workspace allowlist (`CIGUARD_MCP_ROOT`):** when set, every tool that takes a path argument refuses paths outside the allowlist. Defence-in-depth on the path-traversal class. Stays optional — local-dev usage works without it.

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

## Drop-in CI templates

Pre-built workflow files for the three supported platforms live under [`templates/`](templates/). Copy the one that matches your CI and bump the pinned ciguard version when you want to upgrade.

| Platform | Template | Use case |
|---|---|---|
| GitHub Actions | [`templates/github-actions/ciguard-scan.yml`](templates/github-actions/ciguard-scan.yml) | Minimal — scan + JSON artifact, informational |
| GitHub Actions | [`templates/github-actions/ciguard-scan-baseline.yml`](templates/github-actions/ciguard-scan-baseline.yml) | Full v0.5 baseline workflow — diff against `.ciguard/baseline.json`, fail on new High+, SARIF upload to Code Scanning |
| GitHub Actions | [`templates/github-actions/ciguard-scan-repo.yml`](templates/github-actions/ciguard-scan-repo.yml) | Monorepo — auto-discover every pipeline file under the repo root |
| GitLab CI | [`templates/gitlab-ci/ciguard.gitlab-ci.yml`](templates/gitlab-ci/ciguard.gitlab-ci.yml) | Job snippet — drop into your `.gitlab-ci.yml` or `include:` from a remote |
| Jenkins | [`templates/jenkins/Jenkinsfile.ciguard`](templates/jenkins/Jenkinsfile.ciguard) | Declarative stage running ciguard via the official Docker image |

All templates pin ciguard to a specific version (currently `0.9.4`) — never `:latest`. Bump the pin when you want to upgrade; release notes live at [github.com/Jo-Jo98/ciguard/releases](https://github.com/Jo-Jo98/ciguard/releases).

## Running the GitHub App (v0.10.0)

ciguard ships with an optional GitHub App receiver that scans pull requests on every push and posts results back as a Check Run + PR comment. It runs as a small FastAPI service you self-host alongside your CI.

> **v0.10.0 status:** the receiver, JWT broker, async scheduler, Check Run + PR comment, per-installation storage namespacing, and CLI launcher are all shipped. The actual scan-against-real-repo execution is stubbed in v0.10.0 (every Check Run posts a "ciguard receiver wired; scan execution lands in v0.10.1" notice). v0.10.1 will wire the real clone-and-scan path. The stub is honest: deploy v0.10.0 to verify your wiring works end-to-end without yet getting fake findings.

### Install

```sh
pip install 'ciguard[app]'
```

The `[app]` extra adds `PyJWT[crypto]` (~30MB for the `cryptography` dependency). Base `pip install ciguard` stays lean for CI users.

### Register the App

A reviewable manifest lives at [`deploy/app/manifest.yml`](deploy/app/manifest.yml). The permission set is intentionally minimal — `Actions: read`, `Contents: read`, `Pull requests: write`, `Checks: write`, `Metadata: read`. Any future expansion goes through a manifest-diff review, never silently in app code.

To create the App on GitHub:

1. Visit `https://github.com/settings/apps/new` (or your org's Apps page)
2. Use "Create from manifest" and paste the contents of `deploy/app/manifest.yml`
3. After creation, GitHub gives you the App ID, a private key (`.pem`), and a webhook secret
4. Set the webhook URL to your `ciguard app` deployment endpoint (e.g. `https://ciguard.example.com/webhook`)

### Configure

Set these environment variables on the host that runs `ciguard app`:

| Var | Purpose |
|---|---|
| `CIGUARD_APP_ID` | Numeric App ID from GitHub |
| `CIGUARD_APP_PRIVATE_KEY` | PEM bytes inline (production-recommended) |
| `CIGUARD_APP_PRIVATE_KEY_PATH` | Or path to `.pem` on disk (dev-only) |
| `CIGUARD_APP_WEBHOOK_SECRET` | Webhook secret (for HMAC verification) |
| `CIGUARD_APP_STORAGE_ROOT` | Directory for per-installation baselines (default `./var/ciguard-app`) |

The receiver fails-closed at startup if any of these are missing — there's no silent accept-without-verification path.

### Run

```sh
# Loopback (default) — pair with a reverse proxy like nginx / Caddy
ciguard app

# Explicit bind + port
ciguard app --host 0.0.0.0 --port 8000
```

Binding to a non-loopback address prints a warning suggesting reverse-proxy + TLS.

### Security posture

The full threat model is at [`Project ciguard/THREAT_MODEL.md`](https://github.com/Jo-Jo98/ciguard/blob/main/Project%20ciguard/THREAT_MODEL.md) Surface 9. v0.10.0 closes 11 of 13 STRIDE rows in code; the remaining 2 close architecturally (no OAuth callback in the manifest install flow, manifest scope is the minimal permission set). A self-pentest sub-cycle (CYCLE-1.5) runs the full Surface 9 scenarios against the deployed App in an ephemeral DigitalOcean lab before the install link is published more broadly.

Notable in-code defences:

- HMAC-SHA256 over raw body bytes; `hmac.compare_digest`; fail-closed (401) on missing/malformed/mismatched signature.
- JWT signing isolated to `_mint_jwt()`; tokens logged prefix-only (`ghs_a3df…`); 401 from any GitHub call invalidates the cached token.
- Async scheduler with bounded queue + worker pool; idempotency on `(installation_id, head_sha)`; per-`(installation_id, repo)` lock on baseline writes.
- PR-comment markdown sanitisation (4-backtick fences with backtick-run neutralisation; markdown specials escaped on inline values).
- Per-installation storage namespace (`<storage_root>/<installation_id>/<owner>/<repo>/baseline.json`). Reads keyed only by `repo_full_name` raise `TypeError`. Path traversal in repo names rejected at validation; resolved-path-under-root assert as belt-and-braces.

## Infrastructure inventory (`ciguard inventory`)

Audits the *live tooling* a customer runs (Jenkins, GitLab self-host, GitHub Enterprise — more probes coming) for version + EOL status. Distinct from `scan` / `scan-repo`, which audit pipeline *files*.

Each tool is opt-in: ciguard only contacts a tool when the operator provides URL + credentials via env vars. No discovery, no port-scanning.

```bash
export CIGUARD_JENKINS_URL=https://jenkins.example.com
export CIGUARD_JENKINS_USER=audit-readonly
export CIGUARD_JENKINS_TOKEN=<personal API token>

export CIGUARD_GITLAB_URL=https://gitlab.example.com
export CIGUARD_GITLAB_TOKEN=<personal access token, read_api scope>

export CIGUARD_GHE_URL=https://github.example.com
export CIGUARD_GHE_TOKEN=<personal access token>

ciguard inventory                                      # coloured text table
ciguard inventory --format json                        # machine-readable
ciguard inventory --format html --output infra.html    # standalone audit deliverable
ciguard inventory --offline                            # skip endoflife.date (cached only)
ciguard inventory --fail-on end-of-life                # CI gate
```

| Tool | Endpoint | Auth | Required env vars |
|---|---|---|---|
| Jenkins | `/api/json` | HTTP Basic (user + API token) | `CIGUARD_JENKINS_URL` + `_USER` + `_TOKEN` |
| GitLab self-host | `/api/v4/version` | `PRIVATE-TOKEN` header | `CIGUARD_GITLAB_URL` + `_TOKEN` |
| GitHub Enterprise | `/api/v3/meta` | `Authorization: token <PAT>` | `CIGUARD_GHE_URL` + `_TOKEN` |
| Sonatype Nexus | `/service/rest/v1/system/info` (falls back to `/status/check` on 403) | HTTP Basic | `CIGUARD_NEXUS_URL` + `_USER` + `_PASSWORD` |
| JFrog Artifactory | `/api/system/version` (auto-prefixes `/artifactory/` when missing) | bearer token (7.x) OR HTTP Basic (6.x) | `CIGUARD_ARTIFACTORY_URL` + `_TOKEN` OR (`_USER` + `_PASSWORD`) |
| SonarQube | `/api/server/version` (returns plain text) | HTTP Basic, token-as-username | `CIGUARD_SONAR_URL` + `_TOKEN` |
| ArgoCD | `/api/version` | `Authorization: Bearer <JWT>` | `CIGUARD_ARGOCD_URL` + `_TOKEN` |
| Harbor | `/api/v2.0/systeminfo` | HTTP Basic | `CIGUARD_HARBOR_URL` + `_USER` + `_PASSWORD` |

For each configured tool, ciguard reports the detected version + edition + EOL/EOS status (cross-referenced against endoflife.date — same `~/.ciguard/cache/` already used by SCA-EOL rules). Unconfigured tools appear in the report as `unconfigured` and don't generate any network traffic. Probe failures (auth, network, malformed response) land in the entry's `error` field — the runner never crashes on a single probe failure.

Read-only credentials are recommended throughout. The Jenkins probe needs `Overall/Read` at minimum; GitLab probe needs `read_api`; GHE probe needs the default `repo` scope.

## Multi-environment topology (`ciguard topology`)

The cross-pipeline picture: which services exist, which environments they deploy to, which gates separate environment transitions, which secret scopes are shared, which environments can reach which others. Operator-asserted via `ciguard.topology.yml` at the repo root (auto-discovered by walking up from the working directory, like `.ciguardignore`).

```bash
ciguard topology                                          # auto-discover + summarise
ciguard topology --input infra/topology.yml               # explicit path
ciguard topology --format json                            # machine-readable
ciguard topology --format html --output topology.html     # standalone audit deliverable
```

The HTML view is a swimlane grid (services × environments) with promotion-transition arrows showing which gates protect each step, plus secret-scope blast-radius and network-reachability panels. Production-tier columns are highlighted; gateless deploys to production AND gateless transitions into production tier render in a top-of-page red warnings banner so the auditor sees the worst posture issues without scrolling. Print-friendly via `@media print` so it exports cleanly to PDF.

Minimal example:

```yaml
# ciguard.topology.yml
services:
  - id: api
    repo: example/api

environments:
  - id: dev
    tier: development
  - id: staging
    tier: staging
  - id: prod
    tier: production
    network_segment: production

deploy_edges:
  - service: api
    environment: prod
    pipeline: .github/workflows/deploy-prod.yml
    gates: [manual_approval, required_reviewer, branch_protection]

transitions:
  - from: staging
    to: prod
    gates: [manual_approval]

secret_scopes:
  - id: prod-db
    environments: [prod]
    services: [api]

network_segments:
  - id: production
    can_reach: []
```

The text summary calls out auditor-relevant posture: production deploy targets + their gates, gateless promotions (e.g. `dev → prod` with no approval is a red flag), secret-scope blast radius, network reachability between segments. Cross-references resolve at load time — a typo in a service name fails fast with a clear error.

Subsequent Slice 16 sessions will: (a) auto-derive a partial topology from `scan-repo` output (no operator YAML required), (b) cross-check against live GitHub deployment-environments + branch-protection APIs to flag drift between asserted and actual.

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
| `endoflife.date` | SCA EOL/EOS lookups for container base images + language runtimes (rules `SCA-EOL-001/002/003`, `SCA-EOS-001`) AND infrastructure-inventory cycle lookups (`ciguard inventory`) | `--offline` |
| Operator-supplied admin APIs (Jenkins, GitLab self-host, GHE, Nexus, JFrog Artifactory, SonarQube, ArgoCD, Harbor) | `ciguard inventory` only, and only when `CIGUARD_<TOOL>_URL` + auth env vars are set. No discovery; strict env-var gate. | unset the env vars |
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
