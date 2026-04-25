# Changelog

All notable changes to `ciguard` will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.1] — 2026-04-25

### Added
- **Six GitHub Actions built-in policies** (`POL-GHA-001` … `POL-GHA-006`) closing the v0.2.0 gap where GHA scans saw "no built-in policies":
  - `POL-GHA-001` All Action References Must Be SHA-Pinned (Critical via `GHA-SC-002`)
  - `POL-GHA-002` No Hardcoded Secrets in env (Critical via `GHA-IAM-001`)
  - `POL-GHA-003` Workflow Permissions Must Be Least-Privilege (High via `GHA-IAM-004`)
  - `POL-GHA-004` All Container Images Must Be Pinned (High via `GHA-PIPE-001`)
  - `POL-GHA-005` Deploy Jobs Must Declare a GitHub Environment (Critical via `GHA-DEP-001`)
  - `POL-GHA-006` No Privileged Service Containers (Critical via `GHA-RUN-002`)
- **`platforms: List[str]`** field on `PolicyDefinition`. Empty list = applies to all platforms (default for user-supplied custom policies). Built-ins now declare `platforms=["gitlab-ci"]` or `["github-actions"]`. The evaluator filters by `report.platform` before evaluating.
- **Web UI now accepts GitHub Actions workflow uploads.** `/api/scan` uses the `parse_file` auto-detect dispatcher; the response payload includes `platform`. The drag-and-drop UI Just Works for both formats.

### Changed
- `BUILTIN_POLICIES` count: 7 → 13 (7 GitLab + 6 GitHub Actions). Tests updated to count by-platform-applicability rather than the literal length.
- CLI no longer skips built-ins on GHA scans — all 13 are passed to the evaluator and platform filtering is applied internally.

### Internal
- 5 new tests covering the GHA built-ins + platform-filter behaviour. **191/191 total passing** (was 186 in v0.2.0).

## [0.2.0] — 2026-04-25

### Added
- **GitHub Actions support.** `ciguard scan --input .github/workflows/release.yml` now runs end-to-end. Format auto-detection inspects the YAML shape; `--platform gitlab-ci|github-actions|auto` overrides.
- **`Workflow` / `Job` / `Step` pydantic models** in `src/ciguard/models/workflow.py`. Separate from `Pipeline` because GHA's structure (events, matrix, reusable workflows, composite actions, step-level `uses`/`with`) doesn't map cleanly. The `Finding` / `Report` / risk-score / reporter stack is shared across both platforms.
- **Seven GHA security rules** (namespaced `GHA-*`):
  - `GHA-PIPE-001` — Unpinned container or service image
  - `GHA-IAM-001` — Hardcoded secret in workflow / job / step `env`
  - `GHA-IAM-004` — Excessive workflow / job permissions (`permissions: write-all`)
  - `GHA-RUN-002` — Privileged service container (DinD or `options: --privileged`)
  - `GHA-DEP-001` — Likely-deploy job without a GitHub `environment:` block (gates protection rules)
  - `GHA-SC-001` — Dangerous shell pattern in `run:` (`curl | bash`, `eval`, etc.)
  - `GHA-SC-002` — Action / reusable-workflow `uses:` not pinned to a 40-char commit SHA
- **Engine dispatch on input type** — `AnalysisEngine.analyse(target)` accepts either a `Pipeline` or a `Workflow`. Rules from `rules.py` (GitLab) and `gha_rules.py` (GHA) run independently; cross-platform contamination is impossible by construction.
- **`Report.platform` field** (`"gitlab-ci"` | `"github-actions"`) plus `Report.workflow: Optional[Workflow]` for full GHA fidelity. Existing reporters/web/PDF read `report.pipeline` (synthesised on the GHA path so job count + "Target" lines keep working).
- Labelled fixture pair `tests/fixtures/github_actions/{bad,good}_actions.yml` — used to validate PRD acceptance criteria 1 (recall) and 2 (zero FPs) for the GHA platform: bad fixture grades **D** with 9 Critical + 7 High; good fixture scores **100.0 (A)** with **zero findings**.

### Changed
- README + USAGE.md mark GitHub Actions as supported (was "in development"). Roadmap moved to v0.2.x = GHA-aware built-in policies + matrix-aware rules; v0.3 = Jenkins; v0.4 = baseline / delta.
- The 7 built-in policies remain GitLab-specific (`POL-001` etc. reference GitLab rule IDs). For GHA scans the CLI skips built-ins and runs custom user policies only — explicitly noted in the policy step output. GHA-aware built-ins are tracked for v0.2.x.

### Internal
- 19 new GHA rule tests + 29 GHA parser tests (Slice 6 part 1) → **186/186 total passing** (was 138 in v0.1.4).
- ruff, bandit (Medium+), pip-audit, Trivy gates all stay green for v0.2.0.

## [0.1.4] — 2026-04-25

### Changed
- **Minimum supported Python is now 3.10** (was 3.9). Python 3.9 reached EOL in October 2025; every CVE-fixed version of `python-multipart`, `Pillow`, `pytest`, and `python-dotenv` requires ≥3.10. CI matrix is now 3.10 / 3.11 / 3.12 / 3.13.

### Fixed
- Bumped pinned dependencies to versions without known CVEs:
  - `python-multipart` 0.0.20 → 0.0.26 (GHSA-wp53-j4wj-2cfg, GHSA-mj87-hwqh-73pj)
  - `pytest` 8.4.2 → 9.0.3 (GHSA-6w46-j5rx-g56g)
  - `Pillow` (transitive of `reportlab`) pinned ≥12.2.0 (GHSA-cfh3-3jmp-rvhc, GHSA-whj4-6x5x-4v2j)
  - `python-dotenv` (transitive of `uvicorn[standard]`) pinned ≥1.2.2 (GHSA-mf9w-mj56-hr94)

### Added
- **Bandit SAST job** in CI. Fails on Medium+ severity. Two intentional findings annotated with `# nosec`: `yaml.load(...Loader=_GitLabSafeLoader)` (the loader is a SafeLoader subclass), and the dev-only `host="0.0.0.0"` in `web/app.py`.
- **`pip-audit --strict -r requirements.txt`** job in CI. Fails on any known CVE in declared dependencies.
- **Trivy image scan** in the release workflow, gated on the GHCR push. Fails the release on HIGH/CRITICAL OS-package or Python-library CVEs that have an upstream fix (`ignore-unfixed: true`).
- **Dependabot security updates** enabled at the repository level (toggle was off; version updates were already running). Security PRs will now open automatically when a dependency advisory matches.
- **`SECURITY.md`** — vulnerability disclosure policy, supported versions, scope, and current scanning posture.

## [0.1.3] — 2026-04-25

### Fixed
- **POL-003 / SC-003 false-negative on `include: template:`** — pipelines that pulled in GitLab's `Security/SAST.gitlab-ci.yml`, `Security/Secret-Detection.gitlab-ci.yml`, or `Security/Dependency-Scanning.gitlab-ci.yml` via the `include:` block were still flagged as missing scanning, because the rules only inspected job names and script lines. Include directive values are now part of the search corpus, and the regex covers `secret-detection`, `gitleaks`, `trufflehog`, `detect-secrets`, and `gemnasium`.
- **SC-003 false signal on include-only manifests** — root pipelines that contain only `include:` directives (no jobs) parse to zero jobs locally; SC-003 used to fire anyway, even when the included files might run dependency scanning. SC-003 now skips when the pipeline has no jobs (matching ART-003's pattern). 4 corpus projects (`meltano`, `veloren`, `kicad`, `gitlab-org/gitlab-runner`) drop a spurious SC-003 finding as a result.

### Internal
- New `Pipeline.include_text()` helper flattens all `include:` directive values to a single string for keyword matching across rules.
- 5 new regression tests (133 → 138 total). Corpus aggregate Medium count: 225 → 221.

## [0.1.2] — 2026-04-25

### Fixed
- Container image now publishes for both `linux/amd64` and `linux/arm64`. v0.1.1 shipped amd64-only, which broke `docker pull ghcr.io/jo-jo98/ciguard:latest` on Apple Silicon Macs and arm64 servers (AWS Graviton, Ampere, Raspberry Pi) with `no matching manifest for linux/arm64/v8`.

### Internal
- All GitHub Actions are SHA-pinned (supply-chain hygiene; eat-our-own-dogfood — `ciguard` flags exactly this in GitLab CI as PIPE-002 / SC-002).
- Dependabot configured for github-actions, pip (grouped runtime + dev), and docker base image with weekly cadence.
- ruff now enforced in CI (was advisory in 0.1.1); 30 baseline issues resolved.
- Required-reviewer protection rule on the `pypi` GitHub environment — release publishes to PyPI now wait for one-click approval.

## [0.1.1] — 2026-04-24

### Fixed
- Container image build for GHCR — repository name is now correctly lower-cased so `ghcr.io/jo-jo98/ciguard:v0.1.1` and `:latest` actually publish on tag.

## [0.1.0] — 2026-04-24

Initial public release. Slice 1 (GitLab CI):

### Added
- GitLab CI (`.gitlab-ci.yml`) parser with support for `!reference` tags, anchors, includes, environments
- 19 deterministic security rules across 6 categories (Pipeline Integrity, Identity & Access, Runner Security, Artifact Handling, Deployment Governance, Supply Chain)
- Policy engine — 7 built-in organisational policies plus custom YAML policies (6 condition types)
- HTML report (dark, self-contained, no CDN dependency)
- JSON report (API-ready)
- PDF report (8 sections, audit-grade, via reportlab)
- Weighted A–F risk score with per-category breakdown
- Compliance mapping per finding: ISO 27001, SOC 2, NIST CSF
- LLM enrichment (Anthropic Claude + OpenAI, optional, graceful degradation)
- FastAPI web UI with drag-drop upload + REST API
- Scanner integrations: Semgrep CE, OpenSSF Scorecard, GitLab native security artifacts
- CLI: `ciguard scan --input <file> [--output ...] [--format ...] [--policies ...] [--llm]`
- Docker image (web UI on :8080) and `docker compose` services for web/cli/test

### Validated
- Recall: 100% (14/14) on labelled bad fixture
- False positives: 0 on labelled good fixture
- Performance: 166 ms mean parse + analyse on a synthetic 500-job pipeline
- 17 public real-world GitLab CI files across the corpus, all parsing cleanly
