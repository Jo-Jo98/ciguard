"""
GitHub Actions security rules.

These mirror the GitLab CI rules in `rules.py` but operate on the
`Workflow` model. Rule IDs are namespaced with a `GHA-` prefix so report
consumers can pivot on platform without ambiguity.

Mapping to GitLab analogues (each row is the same threat in both worlds):

    GHA-PIPE-001  Unpinned container image                 (cf. PIPE-001)
    GHA-IAM-001   Hardcoded secret in env                  (cf. IAM-001)
    GHA-IAM-004   Excessive workflow / job permissions     (GHA-only)
    GHA-RUN-002   Privileged service container             (cf. RUN-002)
    GHA-DEP-001   Deploy job missing GitHub environment    (cf. DEP-001 / PIPE-004)
    GHA-SC-001    Dangerous shell pattern in `run:`        (cf. PIPE-003 / SC-001)
    GHA-SC-002    Action / reusable workflow not SHA-pinned (cf. SC-002)
"""
from __future__ import annotations

import re
from typing import Callable, List

from ..models.pipeline import (
    Category,
    ComplianceMapping,
    Finding,
    Severity,
)
from ..models.workflow import Job, Workflow
from .rules import (
    _DANGEROUS_PATTERNS,
    _SECRET_KEY_RE,
    _SECRET_VALUE_RE,
    _finding_id,
    _image_is_pinned,
)

GHARuleFunc = Callable[[Workflow], List[Finding]]


# ---------------------------------------------------------------------------
# GHA-PIPE-001 — Unpinned container image
# ---------------------------------------------------------------------------

def rule_gha_pipe_001(wf: Workflow) -> List[Finding]:
    """GHA-PIPE-001: Job container or service container without a pinned image."""
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.12.5.1", "A.14.2.2"],
        soc2=["CC8.1", "CC7.1"],
        nist=["PR.IP-1", "ID.RA-1"],
    )

    for job in wf.jobs:
        # Job-level container
        img = job.container_image()
        if img and not _image_is_pinned(img):
            findings.append(Finding(
                id=_finding_id("GHA-PIPE-001"),
                rule_id="GHA-PIPE-001",
                name="Unpinned Container Image",
                description=(
                    f"Job `{job.id}` runs in container `{img}` which is not "
                    "pinned to an immutable digest. The runtime environment "
                    "can change silently between runs."
                ),
                severity=Severity.HIGH,
                category=Category.PIPELINE_INTEGRITY,
                location=job.id,
                evidence=f"container: {img}",
                remediation=(
                    "Pin to a digest: `container: ghcr.io/org/image@sha256:<digest>`. "
                    "Bare or `:latest` tags allow upstream changes to alter the build."
                ),
                compliance=compliance,
            ))

        # Service containers
        for svc_name, svc in job.services.items():
            svc_img = svc.get("image") if isinstance(svc, dict) else None
            if svc_img and not _image_is_pinned(svc_img):
                findings.append(Finding(
                    id=_finding_id("GHA-PIPE-001"),
                    rule_id="GHA-PIPE-001",
                    name="Unpinned Service Container Image",
                    description=(
                        f"Service `{svc_name}` in job `{job.id}` uses image "
                        f"`{svc_img}` which is not pinned to an immutable digest."
                    ),
                    severity=Severity.HIGH,
                    category=Category.PIPELINE_INTEGRITY,
                    location=f"{job.id}.services.{svc_name}",
                    evidence=f"image: {svc_img}",
                    remediation=(
                        "Pin service images to a SHA digest or remove the service "
                        "if it is not required."
                    ),
                    compliance=compliance,
                ))

    return findings


# ---------------------------------------------------------------------------
# GHA-IAM-001 — Hardcoded secret in env (workflow / job / step)
# ---------------------------------------------------------------------------

def rule_gha_iam_001(wf: Workflow) -> List[Finding]:
    """GHA-IAM-001: Hardcoded secret in any `env:` block."""
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.9.4.3", "A.10.1.1"],
        soc2=["CC6.1", "CC6.7"],
        nist=["PR.AC-1", "PR.DS-5"],
    )

    def check(env: dict, location: str) -> None:
        for key, value in (env or {}).items():
            if not value:
                continue
            v = str(value)
            if _SECRET_KEY_RE.search(key) and _SECRET_VALUE_RE.match(v):
                masked = v[:4] + "****" if len(v) > 4 else "****"
                findings.append(Finding(
                    id=_finding_id("GHA-IAM-001"),
                    rule_id="GHA-IAM-001",
                    name="Hardcoded Secret in env",
                    description=(
                        f"`{key}` in `env:` at `{location}` looks like a hardcoded "
                        "secret. Workflow YAML is committed to source control and "
                        "visible in workflow run logs."
                    ),
                    severity=Severity.CRITICAL,
                    category=Category.IDENTITY_ACCESS,
                    location=location,
                    evidence=f"{key}: {masked}",
                    remediation=(
                        f"Remove the literal value. Store as an encrypted secret "
                        f"(`Settings > Secrets and variables > Actions`) and "
                        f"reference as `${{{{ secrets.{key} }}}}`. Rotate the "
                        "exposed credential immediately."
                    ),
                    compliance=compliance,
                ))

    check(wf.env, "env")
    for job in wf.jobs:
        check(job.env, f"jobs.{job.id}.env")
        for i, step in enumerate(job.steps):
            check(step.env, f"jobs.{job.id}.steps[{i}].env")

    return findings


# ---------------------------------------------------------------------------
# GHA-IAM-004 — Excessive workflow / job permissions
# ---------------------------------------------------------------------------

def rule_gha_iam_004(wf: Workflow) -> List[Finding]:
    """GHA-IAM-004: `permissions: write-all` (workflow or job level).

    GitHub's recommendation is least-privilege: every workflow should declare
    `permissions:` explicitly with the narrowest set needed. `write-all` (or
    no `permissions:` block when the repo default is permissive) hands every
    step in the workflow a broadly-scoped GITHUB_TOKEN — a risk if a single
    `uses:` action is compromised.
    """
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.9.2.3", "A.9.4.1"],
        soc2=["CC6.1", "CC6.3"],
        nist=["PR.AC-4", "PR.AC-6"],
    )

    def is_excessive(perms) -> bool:
        if isinstance(perms, str):
            return perms.strip().lower() == "write-all"
        return False

    if is_excessive(wf.permissions):
        findings.append(Finding(
            id=_finding_id("GHA-IAM-004"),
            rule_id="GHA-IAM-004",
            name="Excessive Workflow Permissions",
            description=(
                "Workflow declares `permissions: write-all`, granting every job "
                "and every step write access to all GITHUB_TOKEN scopes "
                "(contents, packages, deployments, security-events, etc.). A "
                "compromised dependency in any `uses:` would inherit this."
            ),
            severity=Severity.HIGH,
            category=Category.IDENTITY_ACCESS,
            location="permissions",
            evidence="permissions: write-all",
            remediation=(
                "Replace with a least-privilege mapping, e.g.:\n"
                "  permissions:\n"
                "    contents: read\n"
                "Elevate per-job only where strictly required."
            ),
            compliance=compliance,
        ))

    for job in wf.jobs:
        if is_excessive(job.permissions):
            findings.append(Finding(
                id=_finding_id("GHA-IAM-004"),
                rule_id="GHA-IAM-004",
                name="Excessive Job Permissions",
                description=(
                    f"Job `{job.id}` declares `permissions: write-all`. The "
                    "GITHUB_TOKEN injected into this job has write to every "
                    "scope, including ones unrelated to the job's purpose."
                ),
                severity=Severity.HIGH,
                category=Category.IDENTITY_ACCESS,
                location=f"jobs.{job.id}.permissions",
                evidence="permissions: write-all",
                remediation="Declare an explicit least-privilege permissions mapping for this job.",
                compliance=compliance,
            ))

    return findings


# ---------------------------------------------------------------------------
# GHA-RUN-002 — Privileged service container
# ---------------------------------------------------------------------------

def rule_gha_run_002(wf: Workflow) -> List[Finding]:
    """GHA-RUN-002: Service container running with --privileged or as DinD."""
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.13.1.3", "A.14.2.5"],
        soc2=["CC6.6", "CC7.1"],
        nist=["PR.PT-3", "PR.AC-4"],
    )

    privileged_re = re.compile(r"--privileged", re.I)
    dind_re = re.compile(r"docker:.*dind", re.I)

    for job in wf.jobs:
        # Service-level options (`options: --privileged`)
        for svc_name, svc in job.services.items():
            options = svc.get("options", "") if isinstance(svc, dict) else ""
            image = svc.get("image", "") if isinstance(svc, dict) else ""
            triggered = bool(privileged_re.search(str(options))) or bool(dind_re.search(str(image)))
            if triggered:
                findings.append(Finding(
                    id=_finding_id("GHA-RUN-002"),
                    rule_id="GHA-RUN-002",
                    name="Privileged Service Container",
                    description=(
                        f"Service `{svc_name}` in job `{job.id}` runs privileged "
                        "(either via `--privileged` option or docker-in-docker). "
                        "Privileged containers can escape the runner sandbox."
                    ),
                    severity=Severity.CRITICAL,
                    category=Category.RUNNER_SECURITY,
                    location=f"jobs.{job.id}.services.{svc_name}",
                    evidence=f"image: {image}, options: {options}".strip(", "),
                    remediation=(
                        "Avoid docker-in-docker. Use the host Docker daemon via "
                        "`/var/run/docker.sock` mount with appropriate scoping, "
                        "Buildah / Kaniko / Skopeo for rootless image builds, or "
                        "BuildKit's daemonless mode."
                    ),
                    compliance=compliance,
                ))

        # `run:` lines that invoke `docker run --privileged`
        for line in job.all_run_lines():
            if "docker" in line and privileged_re.search(line):
                findings.append(Finding(
                    id=_finding_id("GHA-RUN-002"),
                    rule_id="GHA-RUN-002",
                    name="Privileged Docker Invocation",
                    description=(
                        f"Job `{job.id}` invokes `docker run --privileged`, "
                        "granting the container full host access."
                    ),
                    severity=Severity.CRITICAL,
                    category=Category.RUNNER_SECURITY,
                    location=job.id,
                    evidence=line.strip()[:200],
                    remediation=(
                        "Drop `--privileged`. Add only the specific capabilities "
                        "required (`--cap-add=...`)."
                    ),
                    compliance=compliance,
                ))

    return findings


# ---------------------------------------------------------------------------
# GHA-DEP-001 — Deploy job without GitHub environment
# ---------------------------------------------------------------------------

# Match deploy / release / publish / push as standalone tokens, allowing
# `_` and `-` as boundaries (`deploy_prod`, `release-build` both count).
# Plain `\b` doesn't help because `_` is a word character in Python regex.
_DEPLOY_NAME_RE = re.compile(
    r"(?:^|[^a-z0-9])(deploy|release|publish|push)(?:[^a-z0-9]|$)", re.I,
)
_NON_DEPLOY_MODIFIERS = (
    "build", "test", "lint", "check", "verify", "validate",
    "format", "compile", "audit", "scan", "notify",
)


def _is_deploy_job(job: Job) -> bool:
    name = (job.name or job.id or "").lower()
    if any(m in name for m in _NON_DEPLOY_MODIFIERS):
        return False
    return bool(_DEPLOY_NAME_RE.search(name))


def rule_gha_dep_001(wf: Workflow) -> List[Finding]:
    """GHA-DEP-001: Likely-deploy job without an `environment:` block.

    GitHub's deployment environments are where protection rules live —
    required reviewers, deployment branches, wait timers, and prod-only
    secret scoping. A deploy job without an environment cannot have those
    gates applied.
    """
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.12.1.2", "A.14.2.2"],
        soc2=["CC8.1", "CC7.1"],
        nist=["PR.IP-3", "PR.AC-4"],
    )

    for job in wf.jobs:
        if not _is_deploy_job(job):
            continue
        if job.targets_environment():
            continue
        findings.append(Finding(
            id=_finding_id("GHA-DEP-001"),
            rule_id="GHA-DEP-001",
            name="Deploy Job Without GitHub Environment",
            description=(
                f"Job `{job.id}` looks like a deployment but has no "
                "`environment:` block. GitHub's required-reviewer / wait-timer / "
                "deployment-branch protection rules attach to environments — "
                "without one, none of those gates apply."
            ),
            severity=Severity.CRITICAL,
            category=Category.DEPLOYMENT_GOVERNANCE,
            location=f"jobs.{job.id}",
            evidence=f"job '{job.id}' has no environment",
            remediation=(
                "Add an `environment:` block referencing a configured GitHub "
                "environment, e.g.:\n"
                "  environment:\n"
                "    name: production\n"
                "    url: https://app.example.com\n"
                "Then configure protection rules on that environment in repo settings."
            ),
            compliance=compliance,
        ))

    return findings


# ---------------------------------------------------------------------------
# GHA-SC-001 — Dangerous shell pattern in `run:`
# ---------------------------------------------------------------------------

def rule_gha_sc_001(wf: Workflow) -> List[Finding]:
    """GHA-SC-001: `run:` contains a fetch-and-execute shell pattern."""
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.12.5.1", "A.14.2.5"],
        soc2=["CC6.1", "CC8.1"],
        nist=["PR.IP-1", "PR.DS-6"],
    )

    for job in wf.jobs:
        for line in job.all_run_lines():
            for pattern, label in _DANGEROUS_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        id=_finding_id("GHA-SC-001"),
                        rule_id="GHA-SC-001",
                        name="Dangerous Shell Pattern",
                        description=(
                            f"Job `{job.id}` contains a `{label}` pattern: "
                            "fetching remote content and executing it without "
                            "verification is a known supply-chain attack vector."
                        ),
                        severity=Severity.CRITICAL,
                        category=Category.SUPPLY_CHAIN,
                        location=job.id,
                        evidence=line.strip()[:200],
                        remediation=(
                            "Pin the source to a specific commit SHA, verify a "
                            "checksum before execution, or move the install logic "
                            "into a trusted action that pins its own dependencies."
                        ),
                        compliance=compliance,
                    ))
                    break  # one finding per line
    return findings


# ---------------------------------------------------------------------------
# GHA-SC-002 — Action / reusable workflow not SHA-pinned
# ---------------------------------------------------------------------------

def rule_gha_sc_002(wf: Workflow) -> List[Finding]:
    """GHA-SC-002: `uses:` references not pinned to a 40-char commit SHA.

    Tag and branch refs are mutable — the upstream maintainer (or anyone who
    compromises the upstream maintainer) can repoint them to malicious code
    that then runs with this workflow's permissions and access. SHA pinning
    is the canonical mitigation; ciguard's own release.yml does it.
    """
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.12.5.1", "A.14.2.5"],
        soc2=["CC6.6", "CC6.1"],
        nist=["ID.SC-3", "PR.IP-2"],
    )

    sha_re = re.compile(r"^[0-9a-f]{40}$", re.I)

    def report(ref: str, location: str, kind: str) -> None:
        # Skip `./local-action` and `docker://` refs — those are local checkouts
        # or registry URIs, not version-controlled action references.
        if ref.startswith("./") or ref.startswith("docker://"):
            return
        if "@" not in ref:
            ref_used = "(no @ ref — defaults to default branch)"
            tag = "default-branch"
        else:
            tag = ref.rsplit("@", 1)[1]
            ref_used = tag
            if sha_re.match(tag):
                return  # SHA-pinned; fine
        findings.append(Finding(
            id=_finding_id("GHA-SC-002"),
            rule_id="GHA-SC-002",
            name=f"Unpinned {kind} Reference",
            description=(
                f"`{ref}` resolves at run-time to whatever the upstream points "
                f"`{ref_used}` at. Tag and branch refs are mutable — a compromised "
                "upstream maintainer can swap the implementation between scans."
            ),
            severity=Severity.HIGH,
            category=Category.SUPPLY_CHAIN,
            location=location,
            evidence=f"uses: {ref}",
            remediation=(
                "Replace the tag with the full 40-character commit SHA of the "
                "version you have reviewed:\n"
                f"  uses: {ref.rsplit('@', 1)[0] if '@' in ref else ref}@<sha>  # {tag}\n"
                "Dependabot can keep these SHAs current automatically."
            ),
            compliance=compliance,
        ))

    for job in wf.jobs:
        if job.uses:
            report(job.uses, f"jobs.{job.id}.uses", kind="Reusable Workflow")
        for i, step in enumerate(job.steps):
            if step.uses:
                report(step.uses, f"jobs.{job.id}.steps[{i}].uses", kind="Action")

    return findings


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

GHA_RULES: List[GHARuleFunc] = [
    rule_gha_pipe_001,
    rule_gha_iam_001,
    rule_gha_iam_004,
    rule_gha_run_002,
    rule_gha_dep_001,
    rule_gha_sc_001,
    rule_gha_sc_002,
]
