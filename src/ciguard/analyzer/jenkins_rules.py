"""
Jenkins Declarative Pipeline security rules (v0.4).

These mirror the GitLab CI / GHA rule families but operate on the
`Jenkinsfile` model. Rule IDs are namespaced with a `JKN-` prefix.

v0.4 ruleset (cross-platform analogues in parens):

    JKN-PIPE-001  Unpinned `agent { docker { image '...' } }`        (cf. PIPE-001 / GHA-PIPE-001)
    JKN-IAM-001   Hardcoded secret-like value in `environment`       (cf. IAM-001  / GHA-IAM-001)
    JKN-RUN-001   Unconstrained `agent any` at top level              (cf. RUN-002)
    JKN-RUN-002   Privileged docker agent (`args '--privileged'`)     (cf. RUN-002 / GHA-RUN-002)
    JKN-SC-001    Dangerous shell pattern in `sh`/`bat`/`pwsh`        (cf. PIPE-003 / GHA-SC-001)
    JKN-SC-002    Dynamic-Groovy `script { }` block inside steps      (Jenkins-specific)

Roadmap (v0.4.x):
    JKN-DEP-001   Production deploy stage without manual `input`
    JKN-IAM-002   `withCredentials` block whose body echoes the binding
"""
from __future__ import annotations

from typing import Callable, List

from ..models.jenkinsfile import Agent, EnvBinding, Jenkinsfile
from ..models.pipeline import (
    Category,
    ComplianceMapping,
    Finding,
    Severity,
)
from .rules import (
    _DANGEROUS_PATTERNS,
    _SECRET_KEY_RE,
    _SECRET_VALUE_RE,
    _finding_id,
    _image_is_pinned,
)


JenkinsRuleFunc = Callable[[Jenkinsfile], List[Finding]]


# ---------------------------------------------------------------------------
# JKN-PIPE-001 — Unpinned Docker agent image
# ---------------------------------------------------------------------------

def rule_jkn_pipe_001(jf: Jenkinsfile) -> List[Finding]:
    """Top-level or per-stage `agent { docker { image '…' } }` without a
    pinned tag or SHA digest. Same threat as PIPE-001/GHA-PIPE-001 — the
    runtime environment can drift silently between runs."""
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.12.5.1", "A.14.2.2"],
        soc2=["CC8.1", "CC7.1"],
        nist=["PR.IP-1", "ID.RA-1"],
    )

    def check(agent: Agent, location: str) -> None:
        if agent.kind not in ("docker", "dockerfile", "kubernetes"):
            return
        if not agent.image:
            return
        if _image_is_pinned(agent.image):
            return
        findings.append(Finding(
            id=_finding_id("JKN-PIPE-001"),
            rule_id="JKN-PIPE-001",
            name="Unpinned Container Agent Image",
            description=(
                f"Agent at `{location}` runs in container `{agent.image}` "
                "which is not pinned to an immutable digest. The base image "
                "can be replaced upstream without changing the Jenkinsfile."
            ),
            severity=Severity.HIGH,
            category=Category.PIPELINE_INTEGRITY,
            location=location,
            evidence=f"agent docker image: {agent.image}",
            remediation=(
                "Pin to a digest: `image 'ghcr.io/org/image@sha256:<digest>'`. "
                "Bare or `:latest` tags allow upstream changes to alter the build."
            ),
            compliance=compliance,
        ))

    if jf.agent:
        check(jf.agent, "pipeline.agent")
    for stage in jf.stages:
        if stage.agent:
            check(stage.agent, f"stage[{stage.name}].agent")
        for sub in stage.parallel_stages:
            if sub.agent:
                check(sub.agent, f"stage[{stage.name}].parallel[{sub.name}].agent")

    return findings


# ---------------------------------------------------------------------------
# JKN-IAM-001 — Hardcoded secret in environment block
# ---------------------------------------------------------------------------

def rule_jkn_iam_001(jf: Jenkinsfile) -> List[Finding]:
    """`environment { API_TOKEN = 'literal' }` with a secret-shaped key
    AND a literal (non-`credentials(…)`) value. The Jenkins-correct
    pattern is `KEY = credentials('id')`, which references a Credential
    Provider entry; literals end up checked into source control."""
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.9.4.1", "A.9.2.4"],
        soc2=["CC6.1", "CC6.7"],
        nist=["PR.AC-1", "PR.DS-5"],
    )

    def check(binding: EnvBinding, location: str) -> None:
        if binding.source != "literal":
            return
        if not _SECRET_KEY_RE.search(binding.key):
            return
        if not _SECRET_VALUE_RE.match(binding.value):
            return
        findings.append(Finding(
            id=_finding_id("JKN-IAM-001"),
            rule_id="JKN-IAM-001",
            name="Hardcoded Secret in Environment Block",
            description=(
                f"`environment` binding `{binding.key}` at `{location}` is "
                "set to a literal value that pattern-matches a secret. "
                "Anyone with read access to the repo can see it."
            ),
            severity=Severity.HIGH,
            category=Category.IDENTITY_ACCESS,
            location=location,
            evidence=f"{binding.key} = '<redacted, {len(binding.value)} chars>'",
            remediation=(
                "Replace the literal with a Jenkins Credentials reference: "
                f"`{binding.key} = credentials('<credential-id>')`. Store "
                "the actual value in Manage Jenkins → Credentials, scoped "
                "to the smallest folder/job that needs it."
            ),
            compliance=compliance,
        ))

    for b in jf.environment:
        check(b, "pipeline.environment")
    for stage in jf.stages:
        for b in stage.environment:
            check(b, f"stage[{stage.name}].environment")
        for sub in stage.parallel_stages:
            for b in sub.environment:
                check(b, f"stage[{stage.name}].parallel[{sub.name}].environment")

    return findings


# ---------------------------------------------------------------------------
# JKN-RUN-001 — Unconstrained `agent any`
# ---------------------------------------------------------------------------

def rule_jkn_run_001(jf: Jenkinsfile) -> List[Finding]:
    """`agent any` at the top level lets the build run on any executor —
    including ones the team doesn't own. A label, container, or
    `kubernetes` agent constrains the blast radius of a compromised
    build."""
    if not jf.agent or jf.agent.kind != "any":
        return []

    compliance = ComplianceMapping(
        iso_27001=["A.6.2.2", "A.13.1.3"],
        soc2=["CC6.1", "CC6.6"],
        nist=["PR.AC-5", "PR.PT-3"],
    )
    return [Finding(
        id=_finding_id("JKN-RUN-001"),
        rule_id="JKN-RUN-001",
        name="Unconstrained Top-Level Agent",
        description=(
            "The pipeline declares `agent any`, so any executor available "
            "to the controller can run this build. Builds for sensitive "
            "projects should pin to a labelled agent or run inside a "
            "container so they cannot land on shared general-purpose nodes."
        ),
        severity=Severity.MEDIUM,
        category=Category.RUNNER_SECURITY,
        location="pipeline.agent",
        evidence="agent any",
        remediation=(
            "Replace `agent any` with one of:\n"
            "  - `agent { label 'build-trusted' }` to pin to a specific node;\n"
            "  - `agent { docker { image 'org/builder@sha256:…' } }` to run in a "
            "pinned container;\n"
            "  - `agent { kubernetes { … } }` for a per-build pod."
        ),
        compliance=compliance,
    )]


# ---------------------------------------------------------------------------
# JKN-RUN-002 — Privileged docker agent
# ---------------------------------------------------------------------------

# Patterns that indicate the docker agent has effectively root-equivalent
# access to the host: `--privileged`, raw docker-socket mounts, host PID/net
# namespaces, broad capability grants.
_PRIVILEGED_AGENT_PATTERNS = [
    ("--privileged", "agent runs with --privileged"),
    ("/var/run/docker.sock", "agent mounts the host docker socket"),
    ("--pid=host", "agent shares the host PID namespace"),
    ("--net=host", "agent shares the host network namespace"),
    ("--network=host", "agent shares the host network namespace"),
    ("--cap-add=ALL", "agent grants every Linux capability"),
    ("--cap-add ALL", "agent grants every Linux capability"),
    ("--user=root", "agent forces a root UID"),
    ("--user 0", "agent forces a root UID"),
]


def rule_jkn_run_002(jf: Jenkinsfile) -> List[Finding]:
    """`agent { docker { ... args '--privileged' } }` — same threat as
    GitLab's RUN-002: a compromised build can break out of the container
    and read other tenants' secrets, the runner filesystem, and the host
    kernel."""
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.13.1.3", "A.6.2.2"],
        soc2=["CC6.1", "CC6.6"],
        nist=["PR.AC-5", "PR.PT-3"],
    )

    def check(agent: Agent, location: str) -> None:
        if agent.kind != "docker":
            return
        args = (agent.args or "").lower()
        if not args:
            return
        for needle, label in _PRIVILEGED_AGENT_PATTERNS:
            if needle.lower() in args:
                findings.append(Finding(
                    id=_finding_id("JKN-RUN-002"),
                    rule_id="JKN-RUN-002",
                    name="Privileged Docker Agent",
                    description=(
                        f"Docker agent at `{location}` is configured with "
                        f"`{needle}` — {label}. A compromised build can "
                        "escape the container sandbox and reach the host and "
                        "any other tenant on the same Jenkins controller."
                    ),
                    severity=Severity.CRITICAL,
                    category=Category.RUNNER_SECURITY,
                    location=location,
                    evidence=f"args '{agent.args}'",
                    remediation=(
                        "Drop `--privileged` and the host mounts; if you need "
                        "specific kernel features, request only the named "
                        "capabilities via `--cap-add=<NAME>`. For nested "
                        "docker builds, switch to a rootless builder "
                        "(buildah, kaniko, img) instead of mounting "
                        "`/var/run/docker.sock`."
                    ),
                    compliance=compliance,
                ))
                return  # one finding per agent is enough

    if jf.agent:
        check(jf.agent, "pipeline.agent")
    for stage in jf.stages:
        if stage.agent:
            check(stage.agent, f"stage[{stage.name}].agent")
        for sub in stage.parallel_stages:
            if sub.agent:
                check(sub.agent, f"stage[{stage.name}].parallel[{sub.name}].agent")

    return findings


# ---------------------------------------------------------------------------
# JKN-SC-001 — Dangerous shell pattern in sh/bat/powershell step
# ---------------------------------------------------------------------------

def rule_jkn_sc_001(jf: Jenkinsfile) -> List[Finding]:
    """Same shell-pattern detection as PIPE-003 / GHA-SC-001, applied to
    every captured `sh`/`bat`/`powershell` step body. `curl | bash`,
    `eval $VAR`, PowerShell IEX cradles, etc."""
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.14.2.5", "A.12.6.1"],
        soc2=["CC8.1", "CC7.1"],
        nist=["PR.IP-1", "DE.CM-4"],
    )

    for stage_name, script in jf.all_step_scripts():
        for line_no, raw_line in enumerate(script.splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue
            for pattern, label in _DANGEROUS_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        id=_finding_id("JKN-SC-001"),
                        rule_id="JKN-SC-001",
                        name="Dangerous Shell Pattern",
                        description=(
                            f"A `sh` step in stage `{stage_name}` contains a "
                            f"{label} pattern. Piping a remote download into a "
                            "shell interpreter inside a build means the next "
                            "host change downstream of the URL becomes a code "
                            "execution path on your build agent."
                        ),
                        severity=Severity.HIGH,
                        category=Category.SUPPLY_CHAIN,
                        location=f"stage[{stage_name}].steps:{line_no}",
                        evidence=line[:200],
                        remediation=(
                            "Pin the script to a specific revision and verify a "
                            "SHA-256 before executing, e.g. "
                            "`curl -sSfL --output installer.sh https://… && "
                            "echo '<sha256>  installer.sh' | sha256sum -c && "
                            "bash installer.sh`. Better still, install via the "
                            "agent's package manager from a vetted repository."
                        ),
                        compliance=compliance,
                    ))
                    break  # one finding per line is enough

    return findings


# ---------------------------------------------------------------------------
# JKN-SC-002 — Dynamic Groovy `script { }` block inside a steps body
# ---------------------------------------------------------------------------

def rule_jkn_sc_002(jf: Jenkinsfile) -> List[Finding]:
    """`script { … }` lets arbitrary Groovy run inside an otherwise-
    Declarative pipeline. Declarative's whole point is the restricted
    surface — the moment a `script {}` block lands, every plugin call,
    every reflective method, and every `Jenkins.instance` lookup is back
    on the table. It also bypasses the In-Process Script Approval gate
    on many Jenkins versions when the block is part of a trusted job.

    This is an INFO-severity signal by default — `script {}` is sometimes
    legitimate — but worth surfacing so reviewers can confirm the block
    is doing only what Declarative cannot.
    """
    findings: List[Finding] = []
    compliance = ComplianceMapping(
        iso_27001=["A.14.2.5", "A.12.5.1"],
        soc2=["CC8.1", "CC7.1"],
        nist=["PR.IP-1", "DE.CM-4"],
    )

    for stage_name, step in jf.all_steps():
        if step.kind != "script":
            continue
        body = (step.script or "").strip()
        preview = body.splitlines()[0][:120] if body else ""
        findings.append(Finding(
            id=_finding_id("JKN-SC-002"),
            rule_id="JKN-SC-002",
            name="Dynamic Groovy script Block",
            description=(
                f"Stage `{stage_name}` contains a `script {{ … }}` block, "
                "which executes arbitrary Groovy inside an otherwise-"
                "Declarative pipeline. Declarative's restricted surface no "
                "longer applies inside the block — review what it does and "
                "whether the same outcome can be achieved with Declarative "
                "directives."
            ),
            severity=Severity.INFO,
            category=Category.PIPELINE_INTEGRITY,
            location=f"stage[{stage_name}].steps.script",
            evidence=f"script {{ {preview}{' …' if len(body) > 120 else ''} }}",
            remediation=(
                "Where possible, replace the `script {}` body with native "
                "Declarative directives (`environment`, `when`, `post`, "
                "`parameters`, `stages`). When dynamic Groovy is genuinely "
                "required, move the logic to a reviewed Shared Library so "
                "the surface is auditable in one place."
            ),
            compliance=compliance,
        ))
    return findings


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

JENKINS_RULES: List[JenkinsRuleFunc] = [
    rule_jkn_pipe_001,
    rule_jkn_iam_001,
    rule_jkn_run_001,
    rule_jkn_run_002,
    rule_jkn_sc_001,
    rule_jkn_sc_002,
]
