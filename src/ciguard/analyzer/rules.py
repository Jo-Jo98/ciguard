"""
ciguard deterministic security rules.

Each rule is a function that receives a Pipeline and returns a list of
Findings. Rules are grouped by category and registered via the RULES list.

Rule IDs follow the pattern: {CATEGORY_PREFIX}-{NNN}
  PIPE  = Pipeline Integrity
  IAM   = Identity & Access
  RUN   = Runner Security
  ART   = Artifact Handling
  DEP   = Deployment Governance
  SC    = Supply Chain
"""
from __future__ import annotations

import re
from typing import Callable, List, Optional

from ..models.pipeline import (
    Category,
    ComplianceMapping,
    Finding,
    Job,
    Pipeline,
    Severity,
)

# Type alias for rule functions
RuleFunc = Callable[[Pipeline], List[Finding]]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FINDING_COUNTER: dict[str, int] = {}


def _finding_id(rule_id: str) -> str:
    _FINDING_COUNTER[rule_id] = _FINDING_COUNTER.get(rule_id, 0) + 1
    return f"{rule_id}-{_FINDING_COUNTER[rule_id]:03d}"


def _reset_counters() -> None:
    _FINDING_COUNTER.clear()


def _image_is_pinned(image: str) -> bool:
    """
    An image is considered pinned if it:
    - contains a digest (@sha256:...)
    - has a tag that is NOT :latest AND looks like a version (not just a name)
    """
    if not image:
        return True  # no image = not our concern here
    if "@sha256:" in image:
        return True
    if ":" not in image:
        return False  # bare name, implicitly :latest
    tag = image.split(":")[-1]
    return tag != "latest"


# Secret detection patterns — key names that suggest sensitive values.
# NOTE: `pat` (Personal Access Token) was removed because it is a substring of
# `PATH`, `PATTERN`, `PATCH`, `COMPATIBLE`, etc. and produced systematic false
# positives on every CI variable named `*_PATH`. Real PATs in the wild are
# overwhelmingly named `*_TOKEN` or `*_SECRET` and are caught by those patterns.
_SECRET_KEY_RE = re.compile(
    r"(password|passwd|secret|token|api_key|apikey|access_key|private_key|"
    r"auth_token|credential|credentials|signing_key|jwt_secret|"
    r"encryption_key|db_pass|db_password|database_password)",
    re.IGNORECASE,
)

# Values that look like real secrets (not env var references)
_SECRET_VALUE_RE = re.compile(
    r"^(?!"  # NOT starting with...
    r"\$|"   # shell variable reference
    r"\{\{|" # template placeholder
    r"vault:|"  # Vault reference
    r"http|"
    r"true|false|yes|no|1|0"
    r")"
    r".{8,}$",  # at least 8 chars
    re.IGNORECASE,
)

# Dangerous shell patterns
_DANGEROUS_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"curl\s+.*\|\s*(ba?sh|sh|zsh|python|ruby|perl|node)", re.I),
     "curl pipe to shell"),
    (re.compile(r"wget\s+.*\|\s*(ba?sh|sh|zsh|python|ruby|perl|node)", re.I),
     "wget pipe to shell"),
    (re.compile(r"bash\s+<\s*\(curl", re.I),
     "bash process substitution with curl"),
    (re.compile(r"\beval\s+[\$\"\'`]", re.I),
     "eval with variable or string"),
    (re.compile(r"curl\s+.*\s+-\s*\|\s*python", re.I),
     "curl pipe to python"),
    (re.compile(r"invoke-expression\s+.*\(new-object.*webclient\)", re.I),
     "PowerShell IEX download cradle"),
]


# ---------------------------------------------------------------------------
# PIPE — Pipeline Integrity
# ---------------------------------------------------------------------------

def rule_pipe_001(pipeline: Pipeline) -> List[Finding]:
    """PIPE-001: Unpinned Docker images."""
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.8.9", "A.12.5.1"],
        soc2=["CC6.1", "CC7.1"],
        nist=["PR.IP-2", "PR.DS-6"],
    )

    def check(image: Optional[str], location: str) -> None:
        if image and not _image_is_pinned(image):
            findings.append(Finding(
                id=_finding_id("PIPE-001"),
                rule_id="PIPE-001",
                name="Unpinned Docker Image",
                description=(
                    "Docker images without a pinned digest or specific version tag "
                    "can be silently replaced by a malicious actor with registry "
                    "write access, enabling supply chain compromise."
                ),
                severity=Severity.HIGH,
                category=Category.PIPELINE_INTEGRITY,
                location=location,
                evidence=f"image: {image}",
                remediation=(
                    f"Pin the image to a specific digest: "
                    f"`{image.split(':')[0]}@sha256:<digest>` "
                    "or at minimum a fixed version tag (e.g. `node:20.11.0-alpine`)."
                ),
                compliance=compliance,
            ))

    check(pipeline.image, "global")
    for job in pipeline.jobs:
        check(job.image, job.name)
    for svc in pipeline.services:
        check(svc, "global.services")

    return findings


def rule_pipe_002(pipeline: Pipeline) -> List[Finding]:
    """PIPE-002: Unsafe remote includes without hash pinning."""
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.12.5.1", "A.12.6.1"],
        soc2=["CC6.1", "CC6.6"],
        nist=["PR.IP-2", "ID.SC-3"],
    )

    for inc in pipeline.includes:
        if not isinstance(inc, dict):
            continue
        if "remote" in inc:
            url = inc.get("remote", "")
            # Remote includes are always risky without hash pinning
            # GitLab doesn't natively support hash-pinning remote includes
            findings.append(Finding(
                id=_finding_id("PIPE-002"),
                rule_id="PIPE-002",
                name="Unsafe Remote Include",
                description=(
                    "Including pipeline configuration from a remote URL without "
                    "hash verification allows a compromised remote host to inject "
                    "arbitrary CI commands into your pipeline."
                ),
                severity=Severity.HIGH,
                category=Category.PIPELINE_INTEGRITY,
                location="global.include",
                evidence=f"include: remote: {url}",
                remediation=(
                    "Replace remote includes with local copies committed to your "
                    "repository, or use `include: project:` with a pinned `ref:` "
                    "pointing to a specific commit SHA. If remote is unavoidable, "
                    "implement a separate verification job using checksum comparison."
                ),
                compliance=compliance,
            ))

    return findings


def rule_pipe_003(pipeline: Pipeline) -> List[Finding]:
    """PIPE-003: Dangerous shell patterns."""
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.12.6.1", "A.14.2.5"],
        soc2=["CC6.1", "CC7.1"],
        nist=["PR.IP-2", "DE.CM-7"],
    )

    for job in pipeline.jobs:
        for line in job.all_scripts():
            for pattern, description in _DANGEROUS_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        id=_finding_id("PIPE-003"),
                        rule_id="PIPE-003",
                        name="Dangerous Shell Pattern",
                        description=(
                            f"Detected {description} — this pattern executes "
                            "remotely-fetched code without integrity verification, "
                            "enabling arbitrary code execution if the remote resource "
                            "is compromised."
                        ),
                        severity=Severity.CRITICAL,
                        category=Category.PIPELINE_INTEGRITY,
                        location=job.name,
                        evidence=line.strip()[:200],
                        remediation=(
                            "Download the script first, verify its checksum against a "
                            "known-good value, then execute it. Example:\n"
                            "  curl -o install.sh https://example.com/install.sh\n"
                            "  echo 'abc123  install.sh' | sha256sum -c\n"
                            "  bash install.sh"
                        ),
                        compliance=compliance,
                    ))

    return findings


def rule_pipe_004(pipeline: Pipeline) -> List[Finding]:
    """PIPE-004: Unprotected deploy jobs (deploy with no environment block)."""
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.12.1.2", "A.14.2.2"],
        soc2=["CC8.1", "CC6.1"],
        nist=["PR.IP-3", "DE.CM-3"],
    )

    for job in pipeline.jobs:
        # Hidden jobs (name starts with `.`) are `extends:` templates, not
        # runnable on their own. Concrete jobs that extend them inherit the
        # check, so flagging the template is noise.
        if job.name.startswith("."):
            continue
        if not job.is_deploy_job():
            continue
        if job.environment is None:
            findings.append(Finding(
                id=_finding_id("PIPE-004"),
                rule_id="PIPE-004",
                name="Unprotected Deploy Job",
                description=(
                    "This job appears to deploy code but has no `environment:` "
                    "block. GitLab environment protection rules (approvals, "
                    "deployment freezes) only apply to jobs with a declared "
                    "environment. Without it, any pipeline run can deploy "
                    "unchecked."
                ),
                severity=Severity.CRITICAL,
                category=Category.PIPELINE_INTEGRITY,
                location=job.name,
                evidence=f"Job '{job.name}' deploys without an environment block",
                remediation=(
                    "Add an `environment:` block to this job and configure "
                    "protection rules in GitLab Settings > Environments. "
                    "For production, enable required approvals."
                ),
                compliance=compliance,
            ))

    return findings


# ---------------------------------------------------------------------------
# IAM — Identity & Access
# ---------------------------------------------------------------------------

def rule_iam_001(pipeline: Pipeline) -> List[Finding]:
    """IAM-001: Hardcoded secrets in variables."""
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.9.4.3", "A.10.1.1"],
        soc2=["CC6.1", "CC6.7"],
        nist=["PR.AC-1", "PR.DS-5"],
    )

    def check_vars(variables: dict, location: str) -> None:
        for key, value in variables.items():
            if not value:
                continue
            if _SECRET_KEY_RE.search(key) and _SECRET_VALUE_RE.match(value):
                # Mask most of the value in evidence
                masked = value[:4] + "****" if len(value) > 4 else "****"
                findings.append(Finding(
                    id=_finding_id("IAM-001"),
                    rule_id="IAM-001",
                    name="Hardcoded Secret in Variable",
                    description=(
                        f"Variable `{key}` appears to contain a hardcoded secret "
                        "value. Secrets in YAML files are exposed in version "
                        "control history, pipeline logs, and to any user with "
                        "repository read access."
                    ),
                    severity=Severity.CRITICAL,
                    category=Category.IDENTITY_ACCESS,
                    location=location,
                    evidence=f"{key}: {masked}",
                    remediation=(
                        f"Remove `{key}` from the YAML file. Store it as a "
                        "masked, protected CI/CD variable in GitLab "
                        "(Settings > CI/CD > Variables) and reference it as "
                        f"`${key}`. Rotate the exposed secret immediately."
                    ),
                    compliance=compliance,
                ))

    check_vars(pipeline.variables, "global.variables")
    for job in pipeline.jobs:
        check_vars(job.variables, f"{job.name}.variables")

    return findings


def rule_iam_002(pipeline: Pipeline) -> List[Finding]:
    """IAM-002: Unrestricted CI_JOB_TOKEN usage."""
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.9.2.3", "A.9.4.2"],
        soc2=["CC6.2", "CC6.3"],
        nist=["PR.AC-4", "PR.AC-6"],
    )

    token_pattern = re.compile(r"\$CI_JOB_TOKEN", re.I)

    for job in pipeline.jobs:
        for line in job.all_scripts():
            if token_pattern.search(line):
                # Check if it's used in a risky way (not just cloning self)
                if re.search(r"(curl|wget|npm|pip|docker login|helm|aws)", line, re.I):
                    findings.append(Finding(
                        id=_finding_id("IAM-002"),
                        rule_id="IAM-002",
                        name="Unrestricted CI_JOB_TOKEN Usage",
                        description=(
                            "`$CI_JOB_TOKEN` is being passed to an external tool. "
                            "If the runner is compromised, the token can be "
                            "exfiltrated and used to authenticate to your GitLab "
                            "instance with job-level permissions."
                        ),
                        severity=Severity.MEDIUM,
                        category=Category.IDENTITY_ACCESS,
                        location=job.name,
                        evidence=line.strip()[:200],
                        remediation=(
                            "Review whether `$CI_JOB_TOKEN` scope is minimal for "
                            "this operation. Enable the CI_JOB_TOKEN allowlist "
                            "(Settings > CI/CD > Token Access) to restrict which "
                            "projects can use the token. Consider scoped deploy "
                            "tokens for specific operations."
                        ),
                        compliance=compliance,
                    ))

    return findings


def rule_iam_003(pipeline: Pipeline) -> List[Finding]:
    """IAM-003: Sensitive variables not marked as masked/protected."""
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.9.4.3", "A.10.1.1"],
        soc2=["CC6.1", "CC6.7"],
        nist=["PR.DS-5", "PR.AC-1"],
    )

    # This check applies to variables that LOOK sensitive but have plain-text
    # values (not referencing GitLab protected variables). If the value doesn't
    # look like an env-var reference, it wasn't set as a protected variable.
    def check_vars(variables: dict, location: str) -> None:
        for key, value in variables.items():
            if not value:
                continue
            if _SECRET_KEY_RE.search(key):
                # If the value is a plain reference like $VAR_NAME, that's OK
                # If it's a literal value that looks sensitive, flag it
                if not re.match(r"^\$[A-Z_][A-Z0-9_]*$", value.strip()):
                    findings.append(Finding(
                        id=_finding_id("IAM-003"),
                        rule_id="IAM-003",
                        name="Sensitive Variable May Not Be Masked",
                        description=(
                            f"Variable `{key}` has a name suggesting sensitive "
                            "content but is defined in the YAML rather than as a "
                            "masked GitLab CI variable. Values in YAML are visible "
                            "in repository history and pipeline configuration."
                        ),
                        severity=Severity.MEDIUM,
                        category=Category.IDENTITY_ACCESS,
                        location=location,
                        evidence=f"Variable name: {key}",
                        remediation=(
                            "Move this variable to GitLab CI/CD Settings > Variables "
                            "with 'Masked' and 'Protected' flags enabled. This "
                            "prevents the value appearing in job logs."
                        ),
                        compliance=compliance,
                    ))

    check_vars(pipeline.variables, "global.variables")
    for job in pipeline.jobs:
        check_vars(job.variables, f"{job.name}.variables")

    return findings


# ---------------------------------------------------------------------------
# RUN — Runner Security
# ---------------------------------------------------------------------------

def rule_run_001(pipeline: Pipeline) -> List[Finding]:
    """RUN-001: Shell executor indicators."""
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.12.6.2", "A.14.2.6"],
        soc2=["CC6.1", "CC6.6"],
        nist=["PR.IP-1", "DE.CM-7"],
    )

    shell_tag_re = re.compile(r"\bshell\b", re.I)

    for job in pipeline.jobs:
        for tag in job.tags:
            if shell_tag_re.search(tag):
                findings.append(Finding(
                    id=_finding_id("RUN-001"),
                    rule_id="RUN-001",
                    name="Shell Executor Runner",
                    description=(
                        "Job targets a runner with a 'shell' tag, indicating a "
                        "shell executor. Shell executors run directly on the host "
                        "OS without isolation — a compromised job can access host "
                        "files, environment variables, and other jobs' artifacts."
                    ),
                    severity=Severity.HIGH,
                    category=Category.RUNNER_SECURITY,
                    location=job.name,
                    evidence=f"tags: {job.tags}",
                    remediation=(
                        "Migrate to Docker or Kubernetes executors which provide "
                        "job isolation. If shell executor is required, ensure the "
                        "runner user has minimal OS privileges and each runner "
                        "serves only one project."
                    ),
                    compliance=compliance,
                ))

    return findings


def rule_run_002(pipeline: Pipeline) -> List[Finding]:
    """RUN-002: Privileged Docker mode (docker:dind without restrictions)."""
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.12.6.2", "A.9.1.2"],
        soc2=["CC6.1", "CC6.6"],
        nist=["PR.AC-4", "PR.IP-1"],
    )

    dind_pattern = re.compile(r"docker:.*dind", re.I)
    privileged_pattern = re.compile(r"--privileged", re.I)

    def check_job(job: Job) -> None:
        has_dind = any(dind_pattern.search(s) for s in job.services)
        has_privileged = any(privileged_pattern.search(line) for line in job.all_scripts())

        if has_dind:
            findings.append(Finding(
                id=_finding_id("RUN-002"),
                rule_id="RUN-002",
                name="Privileged Docker-in-Docker",
                description=(
                    "This job uses `docker:dind` (Docker-in-Docker), which "
                    "typically requires the runner to be configured with "
                    "`privileged = true`. A privileged container can escape to "
                    "the host, compromising all other workloads on the runner."
                ),
                severity=Severity.CRITICAL,
                category=Category.RUNNER_SECURITY,
                location=job.name,
                evidence=f"services: {[s for s in job.services if dind_pattern.search(s)]}",
                remediation=(
                    "Replace docker:dind with Kaniko, Buildah, or Podman for "
                    "rootless container builds. If docker:dind is unavoidable, "
                    "ensure the runner is on a dedicated node with no other "
                    "workloads and the runner `privileged` flag is narrowly scoped."
                ),
                compliance=compliance,
            ))

        if has_privileged and not has_dind:
            findings.append(Finding(
                id=_finding_id("RUN-002"),
                rule_id="RUN-002",
                name="Privileged Container Flag",
                description=(
                    "A script uses `--privileged` flag when running a container, "
                    "granting the container full host capabilities."
                ),
                severity=Severity.CRITICAL,
                category=Category.RUNNER_SECURITY,
                location=job.name,
                evidence=next(
                    line.strip()[:200] for line in job.all_scripts()
                    if privileged_pattern.search(line)
                ),
                remediation=(
                    "Remove the `--privileged` flag. Use specific Linux capabilities "
                    "(`--cap-add`) only for what is actually required."
                ),
                compliance=compliance,
            ))

    for job in pipeline.jobs:
        check_job(job)

    return findings


def rule_run_003(pipeline: Pipeline) -> List[Finding]:
    """RUN-003: Shared runner usage."""
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.12.1.3", "A.12.6.2"],
        soc2=["CC6.1", "CC6.6"],
        nist=["PR.AC-4", "PR.IP-1"],
    )

    shared_tag_re = re.compile(
        r"\b(shared|saas-linux|saas-macos|saas-windows|gitlab-org-docker)\b", re.I
    )

    def _job_handles_secrets(job: Job) -> bool:
        """Heuristic: job is in scope for secret material at runtime."""
        if job.secrets or job.id_tokens:
            return True
        for key in job.variables.keys():
            if _SECRET_KEY_RE.search(key):
                return True
        return False

    for job in pipeline.jobs:
        # Hidden template jobs are not runnable; skip.
        if job.name.startswith("."):
            continue
        if not job.tags:
            # Only flag missing-tags as a finding when the job is sensitive
            # (deploys, prod-targeting, or handles secret material). Untagged
            # build/test jobs on shared runners are normal and not a finding
            # in their own right — flagging them produced 10/10 false positives
            # on `good_pipeline.yml` (Phase A validation, 2026-04-23).
            if not (job.is_deploy_job() or job.targets_production() or _job_handles_secrets(job)):
                continue
            findings.append(Finding(
                id=_finding_id("RUN-003"),
                rule_id="RUN-003",
                name="Sensitive Job May Use Shared Runner",
                description=(
                    "This job deploys, targets production, or handles secret "
                    "material, but has no runner tags. Without tags it will be "
                    "picked up by any available runner including shared "
                    "runners that process jobs from multiple tenants."
                ),
                severity=Severity.MEDIUM,
                category=Category.RUNNER_SECURITY,
                location=job.name,
                evidence="tags: [] (no runner tags specified) on a sensitive job",
                remediation=(
                    "Add specific runner tags to target a dedicated runner. "
                    "Use group or project runners with appropriate isolation "
                    "rather than shared runners for sensitive jobs."
                ),
                compliance=compliance,
            ))
        else:
            for tag in job.tags:
                if shared_tag_re.search(tag):
                    findings.append(Finding(
                        id=_finding_id("RUN-003"),
                        rule_id="RUN-003",
                        name="Explicit Shared Runner Tag",
                        description=(
                            f"Tag `{tag}` explicitly targets shared runners. "
                            "Shared runners process jobs from multiple organisations, "
                            "making them higher-risk for sensitive workloads."
                        ),
                        severity=Severity.MEDIUM,
                        category=Category.RUNNER_SECURITY,
                        location=job.name,
                        evidence=f"tags: {job.tags}",
                        remediation=(
                            "Use dedicated runners for jobs that handle secrets, "
                            "deploy to production, or process sensitive data."
                        ),
                        compliance=compliance,
                    ))

    return findings


# ---------------------------------------------------------------------------
# ART — Artifact Handling
# ---------------------------------------------------------------------------

def rule_art_001(pipeline: Pipeline) -> List[Finding]:
    """ART-001: Artifacts without expiry."""
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.8.3.1", "A.11.2.7"],
        soc2=["CC6.5", "A1.2"],
        nist=["PR.DS-3", "PR.IP-6"],
    )

    for job in pipeline.jobs:
        if job.artifacts and not job.artifacts.expire_in:
            findings.append(Finding(
                id=_finding_id("ART-001"),
                rule_id="ART-001",
                name="Artifacts Without Expiry",
                description=(
                    "Job artifacts with no `expire_in` are kept indefinitely "
                    "(up to the instance maximum, typically 30 days). This can "
                    "accumulate sensitive build outputs, credentials baked into "
                    "binaries, or test data that should not be retained long-term."
                ),
                severity=Severity.MEDIUM,
                category=Category.ARTIFACT_HANDLING,
                location=job.name,
                evidence=f"artifacts: {{paths: {job.artifacts.paths}, expire_in: null}}",
                remediation=(
                    "Add `expire_in: 1 week` (or appropriate retention period) to "
                    "the artifacts block. Use `artifacts: reports:` for test "
                    "results which GitLab manages separately."
                ),
                compliance=compliance,
            ))

    return findings


def rule_art_002(pipeline: Pipeline) -> List[Finding]:
    """ART-002: Overly broad artifact paths."""
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.8.3.1", "A.12.4.1"],
        soc2=["CC6.5"],
        nist=["PR.DS-3"],
    )

    broad_patterns = {
        "**/*": "captures entire workspace",
        "**": "captures entire workspace",
        ".": "captures current directory",
        "./": "captures current directory",
        "*": "captures all files in root",
    }

    for job in pipeline.jobs:
        if not job.artifacts:
            continue
        for path in job.artifacts.paths:
            if path.strip() in broad_patterns:
                findings.append(Finding(
                    id=_finding_id("ART-002"),
                    rule_id="ART-002",
                    name="Overly Broad Artifact Path",
                    description=(
                        f"Artifact path `{path}` ({broad_patterns[path.strip()]}) "
                        "captures far more than intended. This risks including "
                        "temporary credentials, `.env` files, private keys, or "
                        "other sensitive material in the artifact archive."
                    ),
                    severity=Severity.LOW,
                    category=Category.ARTIFACT_HANDLING,
                    location=job.name,
                    evidence=f"artifacts.paths: [{path}]",
                    remediation=(
                        "Specify exact artifact paths: the `dist/`, `build/`, or "
                        "specific output file paths your pipeline actually needs. "
                        "Avoid wildcards that span the entire workspace."
                    ),
                    compliance=compliance,
                ))

    return findings


def rule_art_003(pipeline: Pipeline) -> List[Finding]:
    """ART-003: No artifact integrity validation in pipeline."""
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.12.2.1", "A.14.2.6"],
        soc2=["CC7.1"],
        nist=["PR.DS-6", "DE.CM-4"],
    )

    # Check if any job generates checksums or signs artifacts
    integrity_patterns = re.compile(
        r"(sha256sum|sha512sum|md5sum|gpg --sign|cosign sign|sigstore|"
        r"openssl dgst|checksum|digest|intoto|slsa)",
        re.I,
    )

    all_scripts = [line for job in pipeline.jobs for line in job.all_scripts()]
    has_integrity_check = any(integrity_patterns.search(line) for line in all_scripts)

    if not has_integrity_check and pipeline.jobs:
        findings.append(Finding(
            id=_finding_id("ART-003"),
            rule_id="ART-003",
            name="No Artifact Integrity Validation",
            description=(
                "No pipeline job generates checksums, signatures, or provenance "
                "attestations for build artifacts. Without integrity validation, "
                "downstream consumers cannot verify that artifacts were produced "
                "by this pipeline and have not been tampered with."
            ),
            severity=Severity.LOW,
            category=Category.ARTIFACT_HANDLING,
            location="global",
            evidence="No sha256sum, gpg, cosign, or sigstore usage found",
            remediation=(
                "Add a post-build job that generates SHA256 checksums: "
                "`sha256sum dist/* > checksums.sha256` "
                "or use Cosign/Sigstore for keyless signing. "
                "Consider generating SLSA provenance attestations."
            ),
            compliance=compliance,
        ))

    return findings


# ---------------------------------------------------------------------------
# DEP — Deployment Governance
# ---------------------------------------------------------------------------

def rule_dep_001(pipeline: Pipeline) -> List[Finding]:
    """DEP-001: Direct-to-production without any approval gate."""
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.12.1.2", "A.14.2.2"],
        soc2=["CC8.1", "CC7.1"],
        nist=["PR.IP-3", "DE.CM-3"],
    )

    # Build a lookup to check if any needed job has a manual gate
    job_lookup = {j.name: j for j in pipeline.jobs}

    def _needs_has_manual_gate(job: "Job") -> bool:
        """True if any job in the needs chain has when: manual."""
        for need in job.needs:
            needed_name = need if isinstance(need, str) else (need.get("job", "") if isinstance(need, dict) else "")
            needed_job = job_lookup.get(needed_name)
            if needed_job and needed_job.has_manual_gate():
                return True
        return False

    for job in pipeline.jobs:
        if not job.targets_production():
            continue
        if job.has_manual_gate() or _needs_has_manual_gate(job):
            continue
        if not job.has_manual_gate():
            findings.append(Finding(
                id=_finding_id("DEP-001"),
                rule_id="DEP-001",
                name="Direct-to-Production Without Approval",
                description=(
                    f"Job `{job.name}` deploys to a production environment "
                    "automatically without a manual approval gate. Any passing "
                    "pipeline will deploy to production — including pipelines "
                    "triggered by force-pushed commits or compromised branches."
                ),
                severity=Severity.CRITICAL,
                category=Category.DEPLOYMENT_GOVERNANCE,
                location=job.name,
                evidence=(
                    f"environment: {job.environment.name if job.environment else 'production'}, "
                    f"when: {job.when}"
                ),
                remediation=(
                    "Add `when: manual` to require human approval before deploying "
                    "to production. Configure GitLab Environment Protection rules "
                    "(Settings > Environments) with required approvers. "
                    "Consider a separate approval job in the pipeline."
                ),
                compliance=compliance,
            ))

    return findings


def rule_dep_002(pipeline: Pipeline) -> List[Finding]:
    """DEP-002: Missing environment protection (deploy without environment block)."""
    # Covered by PIPE-004, but DEP-002 focuses on the governance aspect
    # i.e. jobs that deploy to production by name without environment: block
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.12.1.2", "A.14.2.2"],
        soc2=["CC8.1"],
        nist=["PR.IP-3"],
    )

    prod_name_re = re.compile(r"(deploy.?prod|release.?prod|push.?prod|prod.?deploy)", re.I)

    for job in pipeline.jobs:
        if prod_name_re.search(job.name) and not job.environment:
            findings.append(Finding(
                id=_finding_id("DEP-002"),
                rule_id="DEP-002",
                name="Production Deploy Without Environment Block",
                description=(
                    f"Job `{job.name}` appears to deploy to production based on "
                    "its name, but lacks an `environment:` declaration. GitLab "
                    "environment protections (approval requirements, deployment "
                    "freezes) only apply when an environment is declared."
                ),
                severity=Severity.HIGH,
                category=Category.DEPLOYMENT_GOVERNANCE,
                location=job.name,
                evidence="Job name suggests production deploy, environment: null",
                remediation=(
                    "Add `environment: name: production` to this job and configure "
                    "deployment protection in GitLab's Environment settings."
                ),
                compliance=compliance,
            ))

    return findings


def rule_dep_003(pipeline: Pipeline) -> List[Finding]:
    """DEP-003: No manual gate anywhere for production deploys."""
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.12.1.2", "A.14.2.2"],
        soc2=["CC8.1", "CC7.2"],
        nist=["PR.IP-3", "RS.MI-1"],
    )

    prod_jobs = pipeline.get_production_jobs()
    if not prod_jobs:
        return findings

    has_any_manual_gate = any(j.has_manual_gate() for j in prod_jobs)
    if not has_any_manual_gate:
        # Report on the first production job as representative
        job = prod_jobs[0]
        findings.append(Finding(
            id=_finding_id("DEP-003"),
            rule_id="DEP-003",
            name="No Manual Approval Gate for Production",
            description=(
                "Pipeline has production deployment jobs but none require manual "
                "approval. Automated production deploys mean any code that passes "
                "tests reaches production without human review — critical for "
                "regulated environments and change management compliance."
            ),
            severity=Severity.HIGH,
            category=Category.DEPLOYMENT_GOVERNANCE,
            location=job.name,
            evidence=f"Production jobs: {[j.name for j in prod_jobs]}, none have when: manual",
            remediation=(
                "Add a manual approval step before any production deployment. "
                "Either set `when: manual` on the deploy job itself, or add "
                "a dedicated `approve-production` job that must be triggered "
                "manually and that the deploy job `needs:`."
            ),
            compliance=compliance,
        ))

    return findings


# ---------------------------------------------------------------------------
# SC — Supply Chain
# ---------------------------------------------------------------------------

def rule_sc_001(pipeline: Pipeline) -> List[Finding]:
    """SC-001: External script execution (download and execute pattern)."""
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.12.6.1", "A.14.2.5"],
        soc2=["CC6.6", "CC7.1"],
        nist=["ID.SC-2", "PR.IP-2"],
    )

    # More expansive check than PIPE-003 — catches download-then-execute
    exec_patterns = [
        re.compile(r"(curl|wget)\s+.*-[oO]\s+\S+.*&&.*\s(ba?sh|sh|python|ruby|node)\s+\S+", re.I),
        re.compile(r"pip\s+install\s+.*--index-url\s+(?!https://pypi\.org)", re.I),
        re.compile(r"npm\s+install\s+.*--registry\s+(?!https://registry\.npmjs\.org)", re.I),
        re.compile(r"gem\s+install\s+.*--source\s+(?!https://rubygems\.org)", re.I),
        re.compile(r"(curl|wget)\s+.*\|\s*(sudo\s+)?(ba?sh|sh)", re.I),
    ]

    for job in pipeline.jobs:
        for line in job.all_scripts():
            for pattern in exec_patterns:
                if pattern.search(line):
                    findings.append(Finding(
                        id=_finding_id("SC-001"),
                        rule_id="SC-001",
                        name="External Script Execution",
                        description=(
                            "Pipeline downloads and executes external scripts without "
                            "integrity verification. A supply chain attacker who "
                            "compromises the hosting server can replace the script "
                            "and execute arbitrary code in your pipeline."
                        ),
                        severity=Severity.CRITICAL,
                        category=Category.SUPPLY_CHAIN,
                        location=job.name,
                        evidence=line.strip()[:200],
                        remediation=(
                            "Pin the external script by committing it to your "
                            "repository. If you must download it, verify its "
                            "SHA256 checksum before execution. For package "
                            "managers, use a private registry proxy with curated "
                            "packages."
                        ),
                        compliance=compliance,
                    ))

    return findings


def rule_sc_002(pipeline: Pipeline) -> List[Finding]:
    """SC-002: Unverified external includes."""
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.12.5.1", "A.14.2.5"],
        soc2=["CC6.6", "CC6.1"],
        nist=["ID.SC-3", "PR.IP-2"],
    )

    for inc in pipeline.includes:
        if not isinstance(inc, dict):
            continue
        # project includes should have a ref pinned to a commit SHA
        if "project" in inc:
            ref = inc.get("ref", "")
            # A commit SHA is 40 hex chars; branch names are risky
            if ref and not re.match(r"^[0-9a-f]{40}$", str(ref)):
                findings.append(Finding(
                    id=_finding_id("SC-002"),
                    rule_id="SC-002",
                    name="Project Include Not Pinned to Commit SHA",
                    description=(
                        f"Include from project `{inc.get('project')}` uses "
                        f"ref `{ref}` (a branch name) rather than a commit "
                        "SHA. If that branch is compromised or force-pushed, "
                        "the included pipeline configuration changes silently."
                    ),
                    severity=Severity.HIGH,
                    category=Category.SUPPLY_CHAIN,
                    location="global.include",
                    evidence=f"include: project: {inc.get('project')}, ref: {ref}",
                    remediation=(
                        "Change `ref:` to the full 40-character commit SHA of "
                        "the version you have reviewed. Update it deliberately "
                        "when you want to consume new changes."
                    ),
                    compliance=compliance,
                ))

    return findings


def rule_sc_003(pipeline: Pipeline) -> List[Finding]:
    """SC-003: No dependency scanning stage."""
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.12.6.1", "A.14.2.5"],
        soc2=["CC6.6", "CC7.1"],
        nist=["ID.SC-2", "ID.RA-1"],
    )

    # Include-only manifests (root file is just `include:` directives) parse
    # to zero jobs locally; we can't see what the included files do, so
    # firing SC-003 here is unreliable noise. Match ART-003's pattern.
    if not pipeline.jobs:
        return findings

    scan_keywords = re.compile(
        r"(dependency.scan|dep.scan|sca\b|software.composition|"
        r"trivy|grype|syft|snyk|retire\.js|audit|owasp.dep|gemnasium)",
        re.I,
    )

    all_text = " ".join(
        [j.name for j in pipeline.jobs]
        + pipeline.stages
        + [line for j in pipeline.jobs for line in j.all_scripts()]
        + [pipeline.include_text()]
    )

    if not scan_keywords.search(all_text):
        findings.append(Finding(
            id=_finding_id("SC-003"),
            rule_id="SC-003",
            name="No Dependency Scanning",
            description=(
                "Pipeline has no dependency scanning stage. Vulnerable or "
                "malicious third-party packages in your dependency tree are "
                "the most common supply chain attack vector. Without scanning, "
                "known CVEs go undetected until exploitation."
            ),
            severity=Severity.MEDIUM,
            category=Category.SUPPLY_CHAIN,
            location="global",
            evidence="No dependency scanning tool detected in pipeline",
            remediation=(
                "Add a dependency scanning stage. Options:\n"
                "- GitLab built-in: include the SAST/Dependency-Scanning template\n"
                "- Trivy: `trivy fs --security-checks vuln .`\n"
                "- Snyk: `snyk test`\n"
                "- npm audit / pip-audit / bundler-audit"
            ),
            compliance=compliance,
        ))

    return findings


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

RULES: List[RuleFunc] = [
    # Pipeline Integrity
    rule_pipe_001,
    rule_pipe_002,
    rule_pipe_003,
    rule_pipe_004,
    # Identity & Access
    rule_iam_001,
    rule_iam_002,
    rule_iam_003,
    # Runner Security
    rule_run_001,
    rule_run_002,
    rule_run_003,
    # Artifact Handling
    rule_art_001,
    rule_art_002,
    rule_art_003,
    # Deployment Governance
    rule_dep_001,
    rule_dep_002,
    rule_dep_003,
    # Supply Chain
    rule_sc_001,
    rule_sc_002,
    rule_sc_003,
]
