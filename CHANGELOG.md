# Changelog

All notable changes to `ciguard` will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
