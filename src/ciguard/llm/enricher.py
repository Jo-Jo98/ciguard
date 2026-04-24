"""
ciguard LLM enricher.

Takes a scan Report and generates plain-language insights:
- Executive summary for non-technical managers
- Developer action plan with immediate next steps
- Compliance impact statement
- Risk narrative explaining cumulative exposure

PRIVACY: evidence fields (which may contain masked credential fragments)
are stripped before the payload is sent to the LLM.
"""
from __future__ import annotations

import json
import re
from typing import Optional

from ..models.pipeline import Finding, LLMInsights, Report, Severity
from .client import DEFAULT_ANTHROPIC_MODEL, DEFAULT_OPENAI_MODEL, call_llm

_SYSTEM_PROMPT = (
    "You are a CI/CD security analyst helping engineering teams understand "
    "their pipeline security posture. Your audience is a mix of developers "
    "and non-technical managers. Be concise, specific, and actionable. "
    "Avoid jargon where possible. Never reference specific author names, "
    "books, or external sources."
)


def _sanitise_finding(finding: Finding) -> dict:
    """Return a finding dict safe for sending to the LLM.

    The ``evidence`` field is excluded — it may contain masked credential
    fragments (e.g. ``mySecr****``) that should never leave the host.
    """
    return {
        "rule_id": finding.rule_id,
        "name": finding.name,
        "severity": finding.severity.value,
        "category": finding.category.value,
        "location": finding.location,
        "description": finding.description,
        "remediation": finding.remediation,
        "compliance": {
            "iso_27001": finding.compliance.iso_27001,
            "soc2": finding.compliance.soc2,
            "nist": finding.compliance.nist,
        },
    }


def _build_prompt(report: Report) -> str:
    score = report.risk_score
    by_sev = report.summary.get("by_severity", {})

    # Cap at 10 Critical+High findings to keep prompt tokens manageable
    top_findings = [
        f for f in report.sorted_findings()
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ][:10]

    findings_json = json.dumps(
        [_sanitise_finding(f) for f in top_findings],
        indent=2,
    )

    category_block = "\n".join([
        f"- Pipeline Integrity:     {score.pipeline_integrity}/100",
        f"- Identity & Access:      {score.identity_access}/100",
        f"- Runner Security:        {score.runner_security}/100",
        f"- Artifact Handling:      {score.artifact_handling}/100",
        f"- Deployment Governance:  {score.deployment_governance}/100",
        f"- Supply Chain:           {score.supply_chain}/100",
    ])

    return f"""Analyse this CI/CD security scan and respond with a JSON object.

PIPELINE: {report.pipeline_name}
OVERALL SCORE: {score.overall}/100  (Grade {score.grade})
TOTAL FINDINGS: {report.summary.get("total", 0)}
  Critical : {by_sev.get("Critical", 0)}
  High     : {by_sev.get("High", 0)}
  Medium   : {by_sev.get("Medium", 0)}
  Low      : {by_sev.get("Low", 0)}

CATEGORY SCORES:
{category_block}

TOP CRITICAL/HIGH FINDINGS (evidence field omitted for privacy):
{findings_json}

Respond ONLY with this exact JSON structure — no markdown, no code fences:
{{
  "executive_summary": "2-3 sentences for a non-technical manager: overall posture and the single most important risk.",
  "developer_actions": [
    "Specific immediate action #1",
    "Specific immediate action #2",
    "Specific immediate action #3"
  ],
  "compliance_impact": "1-2 sentences: which compliance frameworks are most impacted and the audit implication.",
  "risk_narrative": "One paragraph explaining the cumulative risk if these findings remain unaddressed."
}}"""


def enrich_report(
    report: Report,
    provider: str = "anthropic",
    model: Optional[str] = None,
) -> LLMInsights:
    """Generate LLM insights for the given report.

    Returns an LLMInsights object ready to attach to report.llm_insights.
    Raises RuntimeError if the API key is missing or the call fails.
    """
    resolved_model = model or (
        DEFAULT_ANTHROPIC_MODEL if provider == "anthropic" else DEFAULT_OPENAI_MODEL
    )

    prompt = _build_prompt(report)
    raw = call_llm(prompt, _SYSTEM_PROMPT, provider=provider, model=resolved_model)

    # Parse the JSON response; handle LLMs that add preamble text
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if match:
            data = json.loads(match.group())
        else:
            raise ValueError(
                f"LLM did not return valid JSON. First 300 chars: {raw[:300]}"
            )

    return LLMInsights(
        executive_summary=data.get("executive_summary", ""),
        developer_actions=data.get("developer_actions", []),
        compliance_impact=data.get("compliance_impact", ""),
        risk_narrative=data.get("risk_narrative", ""),
        provider=provider,
        model_used=resolved_model,
    )
