# Using ciguard — A Practical Guide

This guide is for anyone evaluating or rolling out `ciguard`. It covers **why you'd use it, who benefits, how to integrate it in five minutes, and what you get back.**

If you just want install + commands, the [README](README.md) is shorter. If you want to understand whether `ciguard` is worth the time, read on.

---

## The problem

CI/CD pipelines have quietly become one of the highest-value attack surfaces in software delivery. The job runner has access to:

- production deploy credentials,
- container registries and signing keys,
- cloud provider IAM, and
- every line of source code in the repository.

When that surface is misconfigured — hardcoded secrets in YAML, unpinned `image: node:latest`, privileged docker-in-docker, deploy jobs without manual gates — the cost of being wrong is direct. **SolarWinds (2020), Codecov (2021), and 3CX (2023) were all pipeline-level compromises.** None of them were caught by application-layer SAST.

The gap is uncomfortable: existing security tooling looks at *application code* (Bandit, Semgrep, Snyk) or *running infrastructure* (Wiz, Prisma). Almost nothing looks at the YAML that *connects* them. Manual review is slow, inconsistent, and bored reviewers miss the same patterns the breach reports keep listing.

`ciguard` fills that gap. It's a **deterministic static analyser for pipeline configuration files** — same idea as ESLint or `terraform validate`, but for `.gitlab-ci.yml` (with GitHub Actions and Jenkins on the roadmap).

---

## What you get back

Three things every time you run a scan:

1. **A risk score and grade** (A–F, weighted across six categories) — useful for tracking pipeline security over time, and for the "how secure is our build?" conversation with leadership.
2. **A list of specific findings** — each one with a rule ID, severity, location (file + job), evidence, and concrete remediation. Not "you have a vulnerability"; "line 14 of `deploy_prod` runs `curl | bash` against an unpinned URL — replace with a checksummed installer."
3. **Compliance mapping on every finding** — ISO 27001, SOC 2, NIST CSF references. This is the part that turns a security tool into an audit deliverable. Auditors recognise the control IDs; engineers don't have to translate.

Output formats: **terminal summary, HTML report, JSON (for CI/API), PDF (for auditors and execs)**.

```bash
# What this looks like:
$ ciguard scan --input .gitlab-ci.yml
Risk Score: 40.7/100  Grade: F
11 Critical · 6 High · 13 Medium · 3 Low
Top Findings:
  [Crit] IAM-001  Hardcoded Secret in Variable  (global.variables)
  [Crit] PIPE-003 Dangerous Shell Pattern       (build)
  [Crit] DEP-001  Direct-to-Production Without Approval  (deploy_prod)
  ...
```

Exit codes are CI-friendly: `0` clean, `2` Critical findings, `1` error.

---

## Who benefits

### The individual engineer
**Use case:** "I'm about to push a change to `.gitlab-ci.yml` and I want to know if I just introduced a problem."

```bash
pip install ciguard
ciguard scan --input .gitlab-ci.yml
```

That's it. Three seconds. You see the findings before the reviewer does.

### The platform / DevOps team
**Use case:** "Every pipeline change should be gated on Critical findings, the same way we gate on tests passing."

Add a `ciguard` job to CI (full snippets in *Implementation patterns* below). Critical findings exit 2 and fail the build. Lower-severity findings show up as warnings in the report artifact. The team's pipeline security baseline becomes enforceable instead of aspirational.

### The security team
**Use case:** "I need visibility into pipeline-level risk across N repositories without becoming a manual review bottleneck."

Run `ciguard` in a scheduled workflow against every repo, drop the JSON outputs into your existing aggregation (Splunk, ELK, GRC platform). Pivot on rule IDs to find systemic issues — e.g. "every team's deploy job is missing `environment:` blocks; let's update the template once."

### The compliance / audit lead
**Use case:** "I need evidence that pipeline configurations meet our control framework — and I need it in a format that closes audit findings, not opens new ones."

Run `ciguard scan --output report.pdf --format pdf`. The PDF has eight sections including the compliance-mapping appendix (ISO 27001 / SOC 2 / NIST CSF). Hand it to the auditor with a date stamp. The PDF is reproducible from the same input — auditors can rerun it.

### The fractional / consulting CISO
**Use case:** "I'm scoping a security uplift for a new client and I need to baseline their pipeline posture in one afternoon."

Clone their repos, batch-scan, ship a single PDF deliverable per client. The compliance mapping does the framework translation for you. Consistent output across clients makes year-on-year comparisons trivial.

### The vendor / product team selling to regulated buyers
**Use case:** "Our enterprise prospects ask 'how do you secure your build pipeline?' and we don't have a confident answer."

A `ciguard` report — kept in the security pack with SOC 2, pen test summary, etc. — is a one-line answer to that question. Re-run on every release; show the trend.

---

## Implementation patterns

The five-minute integrations. Pick one.

### 1. Pre-push local check

```bash
pip install ciguard

# Add a git pre-push hook
cat > .git/hooks/pre-push << 'EOF'
#!/usr/bin/env bash
set -e
if [ -f .gitlab-ci.yml ]; then
  ciguard scan --input .gitlab-ci.yml
fi
EOF
chmod +x .git/hooks/pre-push
```

Now every `git push` runs the scan first. Critical findings → push aborts.

### 2. GitLab CI gate

```yaml
# .gitlab-ci.yml
ciguard:
  stage: test
  image: ghcr.io/jo-jo98/ciguard:latest
  script:
    - ciguard scan --input .gitlab-ci.yml --output report.html
    - ciguard scan --input .gitlab-ci.yml --output report.json --format json
  artifacts:
    when: always
    paths: [report.html]
    reports:
      # Surface findings in MR widget
      junit: report.json
  allow_failure: false
```

Critical findings → exit 2 → job fails → MR blocked. The HTML lives as a downloadable artifact for reviewers.

### 3. GitHub Actions gate (scans the workflow itself)

`ciguard` 0.2 supports GitHub Actions workflows directly — point it at any
`.github/workflows/*.yml` file:

```yaml
# .github/workflows/ciguard.yml
name: ciguard
on: [pull_request, push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install ciguard
      # Scan any GitLab CI or GHA workflow file in the repo. ciguard
      # auto-detects the platform from the YAML shape; pass --platform
      # gitlab-ci or github-actions to override.
      - run: ciguard scan --input .github/workflows/release.yml --output report.html
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: ciguard-report
          path: report.html
```

Critical findings → exit 2 → step fails → PR blocked. The HTML lives as a
downloadable artifact for reviewers.

A typical first-scan failure on an existing repo is `GHA-SC-002` (action
references not pinned to a 40-char commit SHA). Dependabot can keep those
SHAs current automatically — see [SECURITY.md](SECURITY.md) for ciguard's
own setup.

### 4. Container-only — no Python install needed

```bash
docker run --rm \
  -v "$PWD:/work" \
  ghcr.io/jo-jo98/ciguard:latest \
  ciguard scan --input /work/.gitlab-ci.yml --output /work/report.html
```

Multi-arch image — works on both Apple Silicon Macs and standard amd64 servers without any dance.

### 5. Web UI for ad-hoc scans

```bash
docker run --rm -p 8080:8080 ghcr.io/jo-jo98/ciguard:latest
# open http://localhost:8080
```

Drag-and-drop a YAML file, get a live report. Useful for show-and-tell, one-off audits, or non-CLI users.

---

## Going further: organisational policies

The 19 built-in rules cover universal misconfigurations. For org-specific requirements ("we never deploy on Fridays," "all images must come from our internal registry," "every prod deploy job must have at least two reviewers"), drop YAML policy files in a folder:

```yaml
# policies/internal-registry-only.yml
id: ORG-001
name: "Images must come from internal registry"
description: "All container images must be pulled from registry.example.com"
severity: high
condition:
  type: image_prefix
  prefix: "registry.example.com/"
remediation: "Replace public image refs with the internal mirror."
```

```bash
ciguard scan --input .gitlab-ci.yml --policies ./policies/ --output report.html
```

Seven built-in policies ship with the tool (no-direct-prod, must-have-secret-scanning, must-have-dep-scanning, etc.); custom policies stack on top.

---

## What this is *not*

Honest scoping helps:

- **Not a runtime tool.** `ciguard` reads YAML — it does not observe your runners, monitor traffic, or scan running containers. Pair it with a runtime tool (Falco, Datadog) for full coverage.
- **Not an application SAST tool.** Bandit, Semgrep, and friends scan your application code. `ciguard` scans the *pipeline configuration that builds and deploys your application*. They are complementary, not alternatives.
- **Not a secret rotator.** It detects hardcoded secrets, names them, and tells you to remove them. Rotation is on you (or your secret manager).
- **GitLab CI and GitHub Actions today.** Jenkins (Declarative) and SARIF output are scoped for v0.3. The two supported platforms have different rule depth: GitLab CI ships 19 rules + 7 built-in policies, GitHub Actions ships 7 rules (the highest-value supply-chain / IAM / runner / deploy-governance checks); GHA-specific built-in policies and additional matrix-aware rules are on the v0.2.x roadmap.

---

## Why this matters

A pipeline scan takes ~150ms. The cost of running `ciguard` on every commit is rounding error. The cost of *not* running it is the next CI/CD breach in the news cycle.

Every finding it reports has been a real-world breach pattern. Every fix it suggests is one your security team would have asked for, six months later, after the post-mortem. The "shift left" cliché is rarely cheap; here it actually is.

---

## Get started

```bash
pip install ciguard
ciguard scan --input .gitlab-ci.yml --output report.html
open report.html
```

Three commands, three minutes. If the grade is F, you have an honest baseline. If it's A, you have a defensible audit artifact. Either way you know more than you did when you started.

- **Project home:** https://github.com/Jo-Jo98/ciguard
- **PyPI:** https://pypi.org/project/ciguard/ (`pip install ciguard`)
- **Container:** `ghcr.io/jo-jo98/ciguard:latest` (multi-arch)
- **Issues / questions:** https://github.com/Jo-Jo98/ciguard/issues
- **Security disclosures:** see [SECURITY.md](SECURITY.md)
