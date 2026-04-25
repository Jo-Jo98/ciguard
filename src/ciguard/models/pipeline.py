"""
ciguard data models.

All pipeline constructs and analysis results are represented here.
Pydantic v2 is used for validation and serialisation.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Category(str, Enum):
    PIPELINE_INTEGRITY = "Pipeline Integrity"
    IDENTITY_ACCESS = "Identity & Access"
    RUNNER_SECURITY = "Runner Security"
    ARTIFACT_HANDLING = "Artifact Handling"
    DEPLOYMENT_GOVERNANCE = "Deployment Governance"
    SUPPLY_CHAIN = "Supply Chain"


# ---------------------------------------------------------------------------
# Pipeline structure models
# ---------------------------------------------------------------------------

class Artifact(BaseModel):
    paths: List[str] = Field(default_factory=list)
    exclude: List[str] = Field(default_factory=list)
    expire_in: Optional[str] = None
    name: Optional[str] = None
    when: Optional[str] = None
    reports: Dict[str, Any] = Field(default_factory=dict)
    untracked: bool = False
    expose_as: Optional[str] = None


class Environment(BaseModel):
    name: str
    url: Optional[str] = None
    action: Optional[str] = None  # start, stop, prepare, verify, access
    auto_stop_in: Optional[str] = None
    on_stop: Optional[str] = None
    deployment_tier: Optional[str] = None  # production, staging, testing, development


class Job(BaseModel):
    name: str
    stage: Optional[str] = "test"
    image: Optional[str] = None
    services: List[str] = Field(default_factory=list)
    script: List[str] = Field(default_factory=list)
    before_script: List[str] = Field(default_factory=list)
    after_script: List[str] = Field(default_factory=list)
    variables: Dict[str, str] = Field(default_factory=dict)

    # Flow control
    rules: List[Dict[str, Any]] = Field(default_factory=list)
    only: Optional[Any] = None
    except_: Optional[Any] = Field(None, alias="except")
    when: Optional[str] = "on_success"
    allow_failure: Union[bool, Dict[str, Any]] = False

    # Targeting
    tags: List[str] = Field(default_factory=list)
    environment: Optional[Environment] = None

    # Dependencies
    dependencies: List[str] = Field(default_factory=list)
    needs: List[Any] = Field(default_factory=list)
    extends: Optional[Any] = None

    # Outputs
    artifacts: Optional[Artifact] = None
    cache: Optional[Any] = None

    # Execution
    timeout: Optional[str] = None
    retry: Optional[Any] = None
    parallel: Optional[Any] = None
    coverage: Optional[str] = None
    interruptible: bool = False
    resource_group: Optional[str] = None

    # Cross-project
    trigger: Optional[Any] = None

    # Auth
    id_tokens: Optional[Dict[str, Any]] = None
    secrets: Optional[Dict[str, Any]] = None

    model_config = {"populate_by_name": True}

    def all_scripts(self) -> List[str]:
        """Return all script lines from before_script, script, after_script."""
        return self.before_script + self.script + self.after_script

    def is_deploy_job(self) -> bool:
        """Heuristic: job deploys if it has an environment with action != stop.

        Falls back to a name-based heuristic when no environment block exists,
        but excludes non-deploy modifiers (build, test, lint, etc.) that
        commonly co-occur with deploy keywords. Examples that must NOT match:
        `windows-cmake-x64-release-build` (build), `assembleRelease test`
        (test), `notify-issues-on-release` (notify).
        """
        if self.environment:
            return self.environment.action not in ("stop", "prepare")
        name_lower = self.name.lower()
        non_deploy = (
            "build", "test", "lint", "check", "verify", "validate",
            "format", "compile", "audit", "scan", "notify",
        )
        if any(m in name_lower for m in non_deploy):
            return False
        return any(k in name_lower for k in ("deploy", "release", "publish", "push"))

    def targets_production(self) -> bool:
        """Heuristic: job targets production environment."""
        if self.environment:
            env_name = self.environment.name.lower()
            tier = (self.environment.deployment_tier or "").lower()
            return "prod" in env_name or tier == "production"
        return False

    def has_manual_gate(self) -> bool:
        """True if job requires manual trigger."""
        if self.when == "manual":
            return True
        for rule in self.rules:
            if isinstance(rule, dict) and rule.get("when") == "manual":
                return True
        return False


class Pipeline(BaseModel):
    stages: List[str] = Field(default_factory=list)
    jobs: List[Job] = Field(default_factory=list)
    variables: Dict[str, str] = Field(default_factory=dict)
    image: Optional[str] = None
    services: List[str] = Field(default_factory=list)
    before_script: List[str] = Field(default_factory=list)
    after_script: List[str] = Field(default_factory=list)
    cache: Optional[Any] = None
    includes: List[Dict[str, Any]] = Field(default_factory=list)
    default: Dict[str, Any] = Field(default_factory=dict)
    workflow: Optional[Dict[str, Any]] = None

    def get_deploy_jobs(self) -> List[Job]:
        return [j for j in self.jobs if j.is_deploy_job()]

    def get_production_jobs(self) -> List[Job]:
        return [j for j in self.jobs if j.targets_production()]

    def has_scanning_stage(self) -> bool:
        """True if pipeline has any security/dependency scanning."""
        scan_keywords = {"sast", "dast", "scan", "dependency", "sca", "audit", "security"}
        all_text = " ".join(
            self.stages + [j.name for j in self.jobs] + [self.include_text()]
        ).lower()
        return any(k in all_text for k in scan_keywords)

    def include_text(self) -> str:
        """Flatten all include directive values to a single string for keyword matching.

        GitLab `include:` items can be `local`, `remote`, `template`, `project`/`file`,
        or `component` references. A pipeline that pulls in `Security/SAST.gitlab-ci.yml`
        via `include: template:` has scanning even if no job mentions it by name.
        """
        parts: List[str] = []
        for entry in self.includes:
            for value in entry.values():
                if isinstance(value, str):
                    parts.append(value)
                elif isinstance(value, list):
                    parts.extend(str(v) for v in value)
        return " ".join(parts)


# ---------------------------------------------------------------------------
# Analysis result models
# ---------------------------------------------------------------------------

class ComplianceMapping(BaseModel):
    iso_27001: List[str] = Field(default_factory=list)
    soc2: List[str] = Field(default_factory=list)
    nist: List[str] = Field(default_factory=list)


class Finding(BaseModel):
    id: str
    rule_id: str
    name: str
    description: str
    severity: Severity
    category: Category
    location: str        # job name, "global", or "include"
    evidence: str        # what was found
    remediation: str
    compliance: ComplianceMapping
    source: str = "ciguard"   # "ciguard" | scanner name (e.g. "semgrep")

    @property
    def severity_order(self) -> int:
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return order.get(self.severity, 99)


class RiskScore(BaseModel):
    overall: float
    pipeline_integrity: float
    identity_access: float
    runner_security: float
    artifact_handling: float
    deployment_governance: float
    supply_chain: float
    grade: str

    @classmethod
    def grade_from_score(cls, score: float) -> str:
        """A 90-100 | B 80-89 | C 70-79 | D 60-69 | F <60"""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        return "F"


class LLMInsights(BaseModel):
    # `model_used` collides with pydantic's protected `model_*` namespace
    # without this opt-out, producing a UserWarning at import time.
    model_config = {"protected_namespaces": ()}

    executive_summary: str
    developer_actions: List[str]
    compliance_impact: str
    risk_narrative: str
    provider: str
    model_used: str


class Report(BaseModel):
    pipeline_name: str
    scan_timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    findings: List[Finding] = Field(default_factory=list)
    risk_score: RiskScore
    pipeline: Pipeline
    summary: Dict[str, Any] = Field(default_factory=dict)
    llm_insights: Optional[LLMInsights] = None
    policy_report: Optional[Any] = None   # PolicyReport — Optional import to avoid circular dep
    scanner_findings: List[Any] = Field(default_factory=list)  # List[ScannerFinding]

    def findings_by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def findings_by_category(self, category: Category) -> List[Finding]:
        return [f for f in self.findings if f.category == category]

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: f.severity_order)
