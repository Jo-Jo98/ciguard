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
    ),
]
