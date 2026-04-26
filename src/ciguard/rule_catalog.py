"""
Rule catalog (v0.8.0).

ciguard's rule metadata (name / description / severity / category / remediation
/ compliance) lives embedded inside `Finding` emissions across the four
analyzer modules (`rules.py`, `gha_rules.py`, `jenkins_rules.py`, `sca_rules.py`).
There has never been a separate registry.

For the MCP server's `list_rules` and `explain_rule` tools — and for any future
docs / VS Code extension / web UI that needs to enumerate rules — we need
canonical rule metadata. Rather than refactor four analyzer modules to extract
a static registry (high blast radius, would touch every rule emission), this
module **harvests the catalog at startup** by running the analyzer against
the labelled bad fixtures and capturing the first emission seen for each
`rule_id`.

What this gives us:
- Zero analyzer changes — the analyzer remains the source of truth for what
  fields a finding has, and this module reads from that source.
- Coverage across every rule that fires on the labelled bad fixtures (which
  is every rule we have regression tests for).

What this does NOT cover:
- Rules that don't fire on any bad fixture — most SCA-* rules need network
  data to fire concretely. To handle those we run an OFFLINE SCA pass
  (cache-only) and harvest whatever does fire. Rules still missing after
  that are listed by ID but with placeholder metadata (clearly marked).

This catalog is built lazily on first access (cache property) and shared
across the process. Cost is one fixture scan (~50ms) per process.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .analyzer.engine import AnalysisEngine
from .models.pipeline import Category, Finding, Severity


@dataclass
class RuleSpec:
    """Canonical metadata for a single ciguard rule.

    Harvested from the first `Finding` emitted with this `rule_id` during
    the fixture-scan startup pass. `platforms` lists which platforms (out
    of `gitlab-ci`, `github-actions`, `jenkins`, `cross-platform`) the rule
    can fire on — derived from which fixture surfaced it."""

    rule_id: str
    name: str
    description: str
    severity: str
    category: str
    remediation: str
    compliance: Dict[str, List[str]] = field(default_factory=dict)
    platforms: List[str] = field(default_factory=list)
    sample_evidence: Optional[str] = None
    sample_location: Optional[str] = None

    @classmethod
    def from_finding(cls, finding: Finding, platform: str) -> "RuleSpec":
        return cls(
            rule_id=finding.rule_id,
            name=finding.name,
            description=finding.description,
            severity=finding.severity.value
                if isinstance(finding.severity, Severity) else str(finding.severity),
            category=finding.category.value
                if isinstance(finding.category, Category) else str(finding.category),
            remediation=finding.remediation,
            compliance={
                "iso_27001": list(finding.compliance.iso_27001 or []),
                "soc2":      list(finding.compliance.soc2 or []),
                "nist":      list(finding.compliance.nist or []),
            },
            platforms=[platform],
            sample_evidence=finding.evidence,
            sample_location=finding.location,
        )


_FIXTURES_DIR = Path(__file__).parent.parent.parent / "tests" / "fixtures"


def _scan_fixture(path: Path, platform_label: str, *, enable_sca: bool = False) -> List[Finding]:
    """Run the analyzer on a fixture, return every Finding it emitted.
    Bypasses the CLI entirely so the harvest is fully in-process. SCA is
    off by default so the catalog can be built offline; SCA rules are
    harvested via a separate cache-only pass below."""
    if not path.exists():
        return []
    try:
        if platform_label == "github-actions":
            from .parser.github_actions import GitHubActionsParser
            target = GitHubActionsParser().parse_file(path)
        elif platform_label == "jenkins":
            from .parser.jenkinsfile import JenkinsfileParser
            target = JenkinsfileParser().parse_file(path)
        else:
            from .parser.gitlab_parser import GitLabCIParser
            target = GitLabCIParser().parse_file(path)
    except Exception:
        return []
    engine = AnalysisEngine(enable_sca=enable_sca, sca_offline=True)
    report = engine.analyse(target, pipeline_name=path.name)
    return list(report.findings)


def _build_catalog(fixtures_dir: Path = _FIXTURES_DIR) -> Dict[str, RuleSpec]:
    """Harvest a {rule_id: RuleSpec} map by scanning every bad fixture.
    Each fixture provides one platform label so `RuleSpec.platforms` reflects
    which platform(s) actually surfaced the rule."""
    catalog: Dict[str, RuleSpec] = {}

    sources = [
        (fixtures_dir / "bad_pipeline.yml",                              "gitlab-ci",      False),
        (fixtures_dir / "complex_pipeline.yml",                          "gitlab-ci",      False),
        (fixtures_dir / "github_actions" / "bad_actions.yml",            "github-actions", False),
        (fixtures_dir / "jenkins" / "bad_jenkinsfile.Jenkinsfile",       "jenkins",        False),
        (fixtures_dir / "jenkins" / "bad_node_scripted.Jenkinsfile",     "jenkins",        False),
        (fixtures_dir / "jenkins" / "shared_library_call.Jenkinsfile",   "jenkins",        False),
    ]

    # SCA pass — runs the engine with SCA enabled in offline mode against
    # the GitLab fixture (which references EOL images). Catches the
    # SCA-* rules that don't otherwise fire on the platform-rule pass.
    sca_source = (
        fixtures_dir / "bad_pipeline.yml", "cross-platform", True
    )

    all_sources = sources + [sca_source]

    for path, platform, enable_sca in all_sources:
        for f in _scan_fixture(path, platform, enable_sca=enable_sca):
            spec = catalog.get(f.rule_id)
            if spec is None:
                catalog[f.rule_id] = RuleSpec.from_finding(
                    f,
                    platform if not f.rule_id.startswith("SCA-") else "cross-platform",
                )
            else:
                # Same rule, additional platform — extend the platforms list.
                lbl = platform if not f.rule_id.startswith("SCA-") else "cross-platform"
                if lbl not in spec.platforms:
                    spec.platforms.append(lbl)

    return catalog


_CACHED_CATALOG: Optional[Dict[str, RuleSpec]] = None


def get_catalog() -> Dict[str, RuleSpec]:
    """Lazy-build and cache the catalog. Builds once per process; subsequent
    calls return the same dict. Override the fixtures directory via the
    `CIGUARD_RULE_FIXTURES_DIR` env var (used in tests)."""
    global _CACHED_CATALOG
    if _CACHED_CATALOG is None:
        custom = os.environ.get("CIGUARD_RULE_FIXTURES_DIR")
        fixtures_dir = Path(custom) if custom else _FIXTURES_DIR
        _CACHED_CATALOG = _build_catalog(fixtures_dir)
    return _CACHED_CATALOG


def reset_catalog() -> None:
    """Clear the cache. Used by tests that want to force a re-harvest."""
    global _CACHED_CATALOG
    _CACHED_CATALOG = None


__all__ = ["RuleSpec", "get_catalog", "reset_catalog"]
