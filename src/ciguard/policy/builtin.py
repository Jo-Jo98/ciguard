"""
ciguard built-in policies.

These policies encode common organisational security baselines.
They are always available; no YAML files needed.
"""
from __future__ import annotations

from .models import PolicyCondition, PolicyDefinition, PolicySeverity


BUILTIN_POLICIES: list[PolicyDefinition] = [
    PolicyDefinition(
        id="POL-001",
        name="No Direct-to-Production Deploys",
        description=(
            "All deployments to production must go through a manual approval "
            "gate. Automated direct-to-production deploys bypass change "
            "management controls and expose the environment to unreviewed code."
        ),
        severity=PolicySeverity.CRITICAL,
        condition=PolicyCondition(
            type="no_rule_findings",
            rule_ids=["DEP-001"],
        ),
        remediation=(
            "Add `when: manual` to all production deployment jobs or configure "
            "GitLab Environment protection rules requiring approvals."
        ),
        tags=["deployment", "governance", "change-management"],
        platforms=["gitlab-ci"],
    ),
    PolicyDefinition(
        id="POL-002",
        name="All Docker Images Must Be Pinned",
        description=(
            "Every Docker image reference must use a digest (@sha256:...) or "
            "a specific version tag. Images tagged :latest or with unpinned "
            "references can be silently replaced by a malicious actor."
        ),
        severity=PolicySeverity.HIGH,
        condition=PolicyCondition(
            type="no_rule_findings",
            rule_ids=["PIPE-001"],
        ),
        remediation=(
            "Replace all :latest or bare image references with pinned digests: "
            "`image: node@sha256:<digest>` or at minimum a fixed version tag."
        ),
        tags=["supply-chain", "integrity", "docker"],
        platforms=["gitlab-ci"],
    ),
    PolicyDefinition(
        id="POL-003",
        name="Secret Detection Must Be Present",
        description=(
            "The pipeline must include a stage that scans for exposed secrets "
            "(SAST, Gitleaks, detect-secrets, or similar). Without secret "
            "scanning, credential leaks go undetected until exploitation."
        ),
        severity=PolicySeverity.HIGH,
        condition=PolicyCondition(
            type="pipeline_check",
            check="has_security_scanning",
        ),
        remediation=(
            "Add a SAST or secret-scanning stage. Options: GitLab SAST "
            "template, Gitleaks, detect-secrets, or Semgrep with secret rules."
        ),
        tags=["secrets", "sast", "scanning"],
        platforms=["gitlab-ci"],
    ),
    PolicyDefinition(
        id="POL-004",
        name="Deploy Jobs Must Have Manual Approval",
        description=(
            "Any job that deploys to a named environment must require either "
            "`when: manual` or be downstream of a manual gate job. "
            "This ensures human oversight before every deployment."
        ),
        severity=PolicySeverity.HIGH,
        condition=PolicyCondition(
            type="no_rule_findings",
            rule_ids=["DEP-001", "DEP-003"],
        ),
        remediation=(
            "Set `when: manual` on deploy jobs or add a dedicated "
            "`approve-deploy` job that deploy jobs `needs:`."
        ),
        tags=["deployment", "governance"],
        platforms=["gitlab-ci"],
    ),
    PolicyDefinition(
        id="POL-005",
        name="Production Environment Must Be Protected",
        description=(
            "Production deployment jobs must declare an `environment:` block "
            "so that GitLab's environment protection rules (approvals, "
            "deployment freezes, protected branches) are enforced."
        ),
        severity=PolicySeverity.CRITICAL,
        condition=PolicyCondition(
            type="no_rule_findings",
            rule_ids=["PIPE-004", "DEP-002"],
        ),
        remediation=(
            "Add `environment: name: production` to production deploy jobs "
            "and configure protection rules in Settings > Environments."
        ),
        tags=["deployment", "environment", "governance"],
        platforms=["gitlab-ci"],
    ),
    PolicyDefinition(
        id="POL-006",
        name="Dependency Scanning Must Be Present",
        description=(
            "The pipeline must include dependency or software composition "
            "analysis (SCA) scanning. Vulnerable third-party packages are "
            "the most common supply chain attack vector."
        ),
        severity=PolicySeverity.MEDIUM,
        condition=PolicyCondition(
            type="no_rule_findings",
            rule_ids=["SC-003"],
        ),
        remediation=(
            "Add a dependency scanning stage: Trivy (`trivy fs .`), "
            "Snyk (`snyk test`), `pip-audit`, `npm audit`, or the GitLab "
            "Dependency-Scanning CI template."
        ),
        tags=["supply-chain", "dependencies", "sca"],
        platforms=["gitlab-ci"],
    ),
    PolicyDefinition(
        id="POL-007",
        name="All Includes Must Use SHA Pinning",
        description=(
            "Remote and project `include:` references must use a commit SHA "
            "rather than a branch name. Branch-based includes can be "
            "silently updated by a force-push to inject malicious pipeline "
            "configuration."
        ),
        severity=PolicySeverity.HIGH,
        condition=PolicyCondition(
            type="no_rule_findings",
            rule_ids=["PIPE-002", "SC-002"],
        ),
        remediation=(
            "For project includes, set `ref:` to the full 40-character commit "
            "SHA. For remote includes, migrate to project includes or commit "
            "the configuration locally."
        ),
        tags=["supply-chain", "includes", "integrity"],
        platforms=["gitlab-ci"],
    ),

    # -----------------------------------------------------------------------
    # GitHub Actions built-ins (v0.2.1).
    # -----------------------------------------------------------------------
    # These mirror the GitLab policies above but key off `GHA-*` rule IDs.
    # They are evaluated when `report.platform == "github-actions"`.

    PolicyDefinition(
        id="POL-GHA-001",
        name="All Action References Must Be SHA-Pinned",
        description=(
            "Every `uses:` reference in a workflow must pin to a 40-character "
            "commit SHA. Tag and branch refs are mutable — a compromised "
            "upstream maintainer can swap the implementation between scans "
            "and have it run with this workflow's permissions."
        ),
        severity=PolicySeverity.HIGH,
        condition=PolicyCondition(
            type="no_rule_findings",
            rule_ids=["GHA-SC-002"],
        ),
        remediation=(
            "Replace tag refs with the full 40-character commit SHA of the "
            "version you have reviewed. Dependabot can keep these SHAs current."
        ),
        tags=["supply-chain", "actions", "integrity"],
        platforms=["github-actions"],
    ),
    PolicyDefinition(
        id="POL-GHA-002",
        name="No Hardcoded Secrets in env",
        description=(
            "Workflow / job / step `env:` blocks must not contain literal "
            "secret values. Workflow YAML is committed to source control and "
            "visible in workflow run logs to anyone with read access."
        ),
        severity=PolicySeverity.CRITICAL,
        condition=PolicyCondition(
            type="no_rule_findings",
            rule_ids=["GHA-IAM-001"],
        ),
        remediation=(
            "Move every credential to encrypted Actions secrets and reference "
            "via ${{ secrets.NAME }}. Rotate any value that has been committed."
        ),
        tags=["secrets", "iam"],
        platforms=["github-actions"],
    ),
    PolicyDefinition(
        id="POL-GHA-003",
        name="Workflow Permissions Must Be Least-Privilege",
        description=(
            "Workflows and jobs must declare an explicit, narrowly-scoped "
            "`permissions:` mapping. `permissions: write-all` (or the "
            "permissive repo default) hands every step a broad GITHUB_TOKEN; "
            "a single compromised `uses:` inherits the lot."
        ),
        severity=PolicySeverity.HIGH,
        condition=PolicyCondition(
            type="no_rule_findings",
            rule_ids=["GHA-IAM-004"],
        ),
        remediation=(
            "Replace `permissions: write-all` with an explicit mapping, "
            "e.g. `permissions:\\n  contents: read`. Elevate per-job only "
            "where strictly required."
        ),
        tags=["iam", "least-privilege", "github-token"],
        platforms=["github-actions"],
    ),
    PolicyDefinition(
        id="POL-GHA-004",
        name="All Container Images Must Be Pinned",
        description=(
            "Job `container:` and service-container images must be pinned to "
            "an immutable digest (`@sha256:...`). Bare or `:latest` refs "
            "allow upstream changes to alter the build environment silently."
        ),
        severity=PolicySeverity.HIGH,
        condition=PolicyCondition(
            type="no_rule_findings",
            rule_ids=["GHA-PIPE-001"],
        ),
        remediation=(
            "Replace `image:` references with a SHA digest pin: "
            "`container: ghcr.io/org/image@sha256:<digest>`."
        ),
        tags=["supply-chain", "integrity", "docker"],
        platforms=["github-actions"],
    ),
    PolicyDefinition(
        id="POL-GHA-005",
        name="Deploy Jobs Must Declare a GitHub Environment",
        description=(
            "Jobs that deploy / release / publish must declare an "
            "`environment:` block referencing a configured GitHub environment. "
            "GitHub's deployment-environment protection rules (required "
            "reviewers, deployment branches, wait timers, prod-only secrets) "
            "attach to environments — without one, none of those gates apply."
        ),
        severity=PolicySeverity.CRITICAL,
        condition=PolicyCondition(
            type="no_rule_findings",
            rule_ids=["GHA-DEP-001"],
        ),
        remediation=(
            "Add an `environment:` block to deploy jobs and configure "
            "protection rules in repo Settings > Environments."
        ),
        tags=["deployment", "governance", "environment"],
        platforms=["github-actions"],
    ),
    PolicyDefinition(
        id="POL-GHA-006",
        name="No Privileged Service Containers",
        description=(
            "Service containers must not run as docker-in-docker or with "
            "`options: --privileged`. Privileged containers can escape the "
            "runner sandbox and read other repos' secrets, the runner's "
            "filesystem, and the host kernel."
        ),
        severity=PolicySeverity.CRITICAL,
        condition=PolicyCondition(
            type="no_rule_findings",
            rule_ids=["GHA-RUN-002"],
        ),
        remediation=(
            "Use the host Docker daemon via `/var/run/docker.sock` mount with "
            "scoping, or rootless image builds via Buildah / Kaniko / Skopeo. "
            "Drop `--privileged`; add only specific capabilities via `--cap-add`."
        ),
        tags=["runner", "isolation"],
        platforms=["github-actions"],
    ),
]
