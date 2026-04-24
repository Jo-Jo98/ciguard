"""
ciguard Policy Engine — data models.

Policies express organisational security requirements on top of the deterministic
rule engine.  Each policy:
  - has a severity (how bad a failure is)
  - has a condition (what it checks)
  - produces a PolicyResult (pass/fail + evidence)

Custom policies are loaded from YAML files whose structure mirrors these models.
"""
from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class PolicySeverity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"


# ---------------------------------------------------------------------------
# Condition definitions
# ---------------------------------------------------------------------------

class PolicyCondition(BaseModel):
    """
    Describes what the policy checks.

    Supported ``type`` values:

    ``no_rule_findings``
        Pass when none of the listed ``rule_ids`` produced findings.
        YAML key: rule_ids (list[str])

    ``max_findings``
        Pass when total finding count is ≤ ``max_count``.
        YAML key: max_count (int)

    ``min_risk_score``
        Pass when the pipeline's overall risk score ≥ ``min_score``.
        YAML key: min_score (float)

    ``no_severity``
        Pass when there are no findings of the given ``severity``.
        YAML key: severity (str — Critical/High/Medium/Low)

    ``min_category_score``
        Pass when a specific category score ≥ ``min_score``.
        YAML keys: category (str), min_score (float)
        Valid categories: pipeline_integrity, identity_access, runner_security,
                          artifact_handling, deployment_governance, supply_chain

    ``pipeline_check``
        Pass when a named built-in check function returns True.
        YAML key: check (str — one of the named checks in evaluator.py)
    """
    type: str
    rule_ids:   Optional[List[str]] = None
    max_count:  Optional[int]       = None
    min_score:  Optional[float]     = None
    severity:   Optional[str]       = None
    category:   Optional[str]       = None
    check:      Optional[str]       = None


# ---------------------------------------------------------------------------
# Policy definition
# ---------------------------------------------------------------------------

class PolicyDefinition(BaseModel):
    id:          str
    name:        str
    description: str
    severity:    PolicySeverity
    condition:   PolicyCondition
    remediation: str
    tags:        List[str] = Field(default_factory=list)
    source:      str = "builtin"   # "builtin" | path to YAML file


# ---------------------------------------------------------------------------
# Policy evaluation result
# ---------------------------------------------------------------------------

class PolicyResult(BaseModel):
    policy:   PolicyDefinition
    passed:   bool
    evidence: str            # human-readable description of what was checked
    detail:   str = ""       # extra detail (e.g. which rule_ids triggered)


# ---------------------------------------------------------------------------
# Policy report (collection of results for one scan)
# ---------------------------------------------------------------------------

class PolicyReport(BaseModel):
    policies_evaluated: int = 0
    passed:  int = 0
    failed:  int = 0
    results: List[PolicyResult] = Field(default_factory=list)

    @property
    def pass_rate(self) -> float:
        if self.policies_evaluated == 0:
            return 100.0
        return round(self.passed / self.policies_evaluated * 100, 1)

    def failures_by_severity(self, severity: PolicySeverity) -> List[PolicyResult]:
        return [r for r in self.results if not r.passed and r.policy.severity == severity]
