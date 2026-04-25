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
# GHA-PIPE-002 — pull_request_target without explicit gating
# ---------------------------------------------------------------------------

def rule_gha_pipe_002(wf: Workflow) -> List[Finding]:
    """GHA-PIPE-002: workflow uses `pull_request_target` event with no gate.

    `pull_request_target` runs in the context of the *base* repo (not the
    forked PR head) — meaning it has write access to the repo's secrets and
    GITHUB_TOKEN. Combined with `actions/checkout` of the PR head (or any
    other PR-author-influenced inputs), it is the canonical GitHub Actions
    RCE vector. GitHub itself has published guidance recommending this
    event be used "with extreme caution".

    A scan that finds `pull_request_target` *and* no per-job `if:` filter
    that locks the workflow to trusted contexts is reported as Critical.
    """
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.9.4.4", "A.14.2.5"],
        soc2=["CC6.1", "CC6.6"],
        nist=["PR.AC-4", "PR.IP-1"],
    )

    if not wf.has_event("pull_request_target"):
        return findings

    # If every job has an `if:` filter that gates on something other than
    # `github.event_name`, the developer is at least aware of the risk.
    # We still report — GitHub's own recommendation is "avoid where possible"
    # — but note presence of guards in the description.
    has_any_guard = any(job.if_condition for job in wf.jobs)

    findings.append(Finding(
        id=_finding_id("GHA-PIPE-002"),
        rule_id="GHA-PIPE-002",
        name="Unsafe pull_request_target Event",
        description=(
            "Workflow triggers on `pull_request_target`, which runs in the "
            "context of the base repository with full write access to secrets "
            "and GITHUB_TOKEN. If the workflow checks out the PR head or "
            "executes any code derived from the PR, an attacker who opens a "
            "fork PR can gain RCE on the runner with the base repo's "
            "credentials. " +
            ("Per-job `if:` guards detected — review carefully." if has_any_guard
             else "No per-job `if:` guards detected.")
        ),
        severity=Severity.CRITICAL,
        category=Category.PIPELINE_INTEGRITY,
        location="on.pull_request_target",
        evidence="on: contains pull_request_target",
        remediation=(
            "Strongly prefer `pull_request` (which runs in the PR's fork "
            "context with read-only token). If `pull_request_target` is "
            "essential, gate every job with an explicit `if:` that confirms "
            "the PR is from a trusted source, never check out the PR head, "
            "and treat any PR-derived input as untrusted. See GitHub's "
            "'Keeping your GitHub Actions secure' guidance."
        ),
        compliance=compliance,
    ))

    return findings


# ---------------------------------------------------------------------------
# GHA-IAM-005 — No `permissions:` declared anywhere
# ---------------------------------------------------------------------------

def rule_gha_iam_005(wf: Workflow) -> List[Finding]:
    """GHA-IAM-005: neither workflow nor any job declares `permissions:`.

    Without an explicit block, the workflow inherits the repository default,
    which historically is permissive. GitHub's recommendation is to declare
    least-privilege permissions explicitly so the GITHUB_TOKEN's scope is
    obvious in the YAML and reviewable in code review.
    """
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.9.2.3", "A.9.4.1"],
        soc2=["CC6.1", "CC6.3"],
        nist=["PR.AC-4", "PR.AC-6"],
    )

    workflow_has = wf.permissions is not None
    any_job_has = any(job.permissions is not None for job in wf.jobs)

    if not workflow_has and not any_job_has:
        findings.append(Finding(
            id=_finding_id("GHA-IAM-005"),
            rule_id="GHA-IAM-005",
            name="No Permissions Block Declared",
            description=(
                "No `permissions:` block is declared at the workflow or any "
                "job level. The workflow runs with the repository's default "
                "GITHUB_TOKEN scope, which depends on org settings and is "
                "frequently more permissive than the workflow needs. "
                "Explicit declaration is reviewable in code review; the "
                "repository default is not."
            ),
            severity=Severity.HIGH,
            category=Category.IDENTITY_ACCESS,
            location="permissions",
            evidence="no permissions: block at workflow or job level",
            remediation=(
                "Declare an explicit least-privilege block at workflow level:\n"
                "  permissions:\n"
                "    contents: read\n"
                "Elevate per-job only where strictly required."
            ),
            compliance=compliance,
        ))

    return findings


# ---------------------------------------------------------------------------
# GHA-IAM-006 — pull_request_target + checkout without persist-credentials:false
# ---------------------------------------------------------------------------

def rule_gha_iam_006(wf: Workflow) -> List[Finding]:
    """GHA-IAM-006: pull_request_target workflow uses `actions/checkout`
    without setting `persist-credentials: false`.

    The default for `actions/checkout` is to persist the auto-generated
    GITHUB_TOKEN into the local git config so subsequent steps can push.
    Combined with `pull_request_target` (which has write tokens) and any
    PR-author-influenced step (e.g. running `npm install` whose lockfile
    came from the PR), this is a classic token-theft vector.
    """
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.9.4.3", "A.14.2.5"],
        soc2=["CC6.1", "CC6.7"],
        nist=["PR.AC-1", "PR.DS-5"],
    )

    if not wf.has_event("pull_request_target"):
        return findings

    for job in wf.jobs:
        for i, step in enumerate(job.steps):
            if not step.uses or "actions/checkout" not in step.uses:
                continue
            persist = step.with_inputs.get("persist-credentials")
            # `False` (Python bool from YAML), `"false"`, or `"False"` are all OK.
            if persist is False or str(persist).lower() == "false":
                continue
            findings.append(Finding(
                id=_finding_id("GHA-IAM-006"),
                rule_id="GHA-IAM-006",
                name="Token-Theft Risk in pull_request_target Workflow",
                description=(
                    f"`actions/checkout` in job `{job.id}` runs in a "
                    "`pull_request_target` workflow but does not set "
                    "`persist-credentials: false`. The default behaviour writes "
                    "the GITHUB_TOKEN into `.git/config`; any later step that "
                    "executes PR-author-derived code (build scripts, lockfile "
                    "installs, custom scripts) can read it."
                ),
                severity=Severity.CRITICAL,
                category=Category.IDENTITY_ACCESS,
                location=f"jobs.{job.id}.steps[{i}]",
                evidence=f"uses: {step.uses} (persist-credentials not false)",
                remediation=(
                    "Add `with: { persist-credentials: false }` to the checkout "
                    "step. If you need push access later, use a narrow PAT or "
                    "GitHub App token explicitly, never the auto-injected "
                    "GITHUB_TOKEN credential."
                ),
                compliance=compliance,
            ))

    return findings


# ---------------------------------------------------------------------------
# GHA-RUN-003 — `runs-on: self-hosted` without specific labels
# ---------------------------------------------------------------------------

def rule_gha_run_003(wf: Workflow) -> List[Finding]:
    """GHA-RUN-003: bare `runs-on: self-hosted` (or list with no narrowing label).

    Self-hosted runners with no narrowing labels accept any job in the
    repository (or, with default settings, the org). Public-fork PRs targeting
    the repo can land jobs on the same physical hardware as production builds,
    enabling cross-job data theft. GitHub explicitly recommends narrowing.
    """
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.13.1.3", "A.14.2.5"],
        soc2=["CC6.6", "CC7.1"],
        nist=["PR.PT-3", "PR.AC-4"],
    )

    for job in wf.jobs:
        labels: List[str] = []
        if isinstance(job.runs_on, str):
            labels = [job.runs_on]
        elif isinstance(job.runs_on, list):
            labels = [str(x) for x in job.runs_on]

        if "self-hosted" not in labels:
            continue
        # Anything more specific than [self-hosted] alone is acceptable here.
        generic = ("self-hosted", "Linux", "macOS", "Windows", "X64", "ARM64", "ARM")
        narrowing_labels = [lbl for lbl in labels if lbl not in generic]
        if narrowing_labels:
            continue

        findings.append(Finding(
            id=_finding_id("GHA-RUN-003"),
            rule_id="GHA-RUN-003",
            name="Self-Hosted Runner Without Narrowing Labels",
            description=(
                f"Job `{job.id}` targets `runs-on: self-hosted` with no "
                "narrowing labels. Any repository workflow — including PRs "
                "from forks — can be scheduled onto your shared runner pool, "
                "enabling cross-job data theft and persistence on the runner."
            ),
            severity=Severity.MEDIUM,
            category=Category.RUNNER_SECURITY,
            location=f"jobs.{job.id}.runs-on",
            evidence=f"runs-on: {labels}",
            remediation=(
                "Add a narrowing label that restricts the runner pool to a "
                "specific tier, e.g. `[self-hosted, prod-build, isolated]`. "
                "Disable workflow-from-fork-PR runs on self-hosted runners "
                "in repo Settings > Actions > General."
            ),
            compliance=compliance,
        ))

    return findings


# ---------------------------------------------------------------------------
# GHA-SC-003 — secrets: inherit to non-SHA-pinned reusable workflow
# ---------------------------------------------------------------------------

def rule_gha_sc_003(wf: Workflow) -> List[Finding]:
    """GHA-SC-003: reusable-workflow call uses `secrets: inherit` *and* the
    `uses:` reference is not SHA-pinned.

    `secrets: inherit` forwards every secret in the calling repo to the
    callee. If the callee's `uses:` ref is mutable (a tag or branch), an
    upstream maintainer compromise hands all those secrets to the attacker
    on the next workflow run. SHA pinning is the standard mitigation.
    """
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.9.4.3", "A.12.5.1"],
        soc2=["CC6.1", "CC6.6"],
        nist=["ID.SC-3", "PR.IP-2"],
    )

    sha_re = re.compile(r"^[0-9a-f]{40}$", re.I)

    for job in wf.jobs:
        if not job.uses or job.secrets != "inherit":
            continue
        if "@" in job.uses:
            ref = job.uses.rsplit("@", 1)[1]
            if sha_re.match(ref):
                continue
            tag = ref
        else:
            tag = "default-branch"

        findings.append(Finding(
            id=_finding_id("GHA-SC-003"),
            rule_id="GHA-SC-003",
            name="secrets: inherit on Unpinned Reusable Workflow",
            description=(
                f"Job `{job.id}` calls reusable workflow `{job.uses}` with "
                "`secrets: inherit` — every secret in this repository is "
                f"forwarded to the callee. The ref `{tag}` is mutable, so "
                "an upstream compromise can replace the callee's "
                "implementation between runs and exfiltrate every secret."
            ),
            severity=Severity.CRITICAL,
            category=Category.SUPPLY_CHAIN,
            location=f"jobs.{job.id}",
            evidence=f"uses: {job.uses}, secrets: inherit",
            remediation=(
                "Either pin the `uses:` ref to a 40-character commit SHA, or "
                "stop using `secrets: inherit` and forward only the specific "
                "secrets the callee actually needs (`secrets:\\n  TOKEN: "
                "${{ secrets.NPM_TOKEN }}`)."
            ),
            compliance=compliance,
        ))

    return findings


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

GHA_RULES: List[GHARuleFunc] = [
    rule_gha_pipe_001,
    rule_gha_pipe_002,
    rule_gha_iam_001,
    rule_gha_iam_004,
    rule_gha_iam_005,
    rule_gha_iam_006,
    rule_gha_run_002,
    rule_gha_run_003,
    rule_gha_dep_001,
    rule_gha_sc_001,
    rule_gha_sc_002,
    rule_gha_sc_003,
]
