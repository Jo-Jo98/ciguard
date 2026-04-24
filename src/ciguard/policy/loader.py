"""
ciguard Policy Loader.

Loads custom organisation policies from a directory of YAML files.

YAML schema (each file may contain one or more policies):

    policies:                        # optional list wrapper
      - id: "ORG-001"
        name: "My Policy"
        description: "..."
        severity: high               # critical | high | medium | low
        condition:
          type: no_rule_findings     # see PolicyCondition for all types
          rule_ids: [PIPE-001]
        remediation: "..."
        tags: [custom, org]

    # OR — a single policy without the `policies:` key:
    id: "ORG-001"
    name: "My Policy"
    ...
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import List

import yaml

from .models import PolicyCondition, PolicyDefinition, PolicySeverity

log = logging.getLogger(__name__)


def load_policies_from_file(path: Path) -> List[PolicyDefinition]:
    """Parse a single YAML file and return PolicyDefinition objects."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        log.warning("Could not parse policy file %s: %s", path, exc)
        return []

    if not isinstance(raw, dict):
        log.warning("Policy file %s: expected a YAML mapping, got %s", path, type(raw).__name__)
        return []

    # Support both `policies: [...]` wrapper and bare single-policy dict
    if "policies" in raw:
        items = raw["policies"]
        if not isinstance(items, list):
            items = [items]
    elif "id" in raw:
        items = [raw]
    else:
        log.warning("Policy file %s: no `id` or `policies` key found", path)
        return []

    results: List[PolicyDefinition] = []
    for item in items:
        try:
            results.append(_parse_policy(item, source=str(path)))
        except Exception as exc:
            log.warning("Policy file %s, entry %s: %s", path, item.get("id", "?"), exc)

    return results


def load_policies_from_directory(directory: Path) -> List[PolicyDefinition]:
    """Recursively load all *.yml / *.yaml policy files in a directory."""
    if not directory.exists():
        log.warning("Policy directory %s does not exist", directory)
        return []

    policies: List[PolicyDefinition] = []
    for path in sorted(directory.rglob("*.y*ml")):
        policies.extend(load_policies_from_file(path))

    log.info("Loaded %d custom policies from %s", len(policies), directory)
    return policies


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_policy(raw: dict, source: str = "custom") -> PolicyDefinition:
    sev_str = str(raw.get("severity", "medium")).lower()
    try:
        severity = PolicySeverity(sev_str)
    except ValueError:
        severity = PolicySeverity.MEDIUM

    cond_raw = raw.get("condition", {})
    condition = PolicyCondition(
        type=cond_raw.get("type", "no_rule_findings"),
        rule_ids=cond_raw.get("rule_ids"),
        max_count=cond_raw.get("max_count"),
        min_score=cond_raw.get("min_score"),
        severity=cond_raw.get("severity"),
        category=cond_raw.get("category"),
        check=cond_raw.get("check"),
    )

    return PolicyDefinition(
        id=str(raw.get("id", "CUSTOM-???")).upper(),
        name=str(raw.get("name", "Unnamed Policy")),
        description=str(raw.get("description", "")),
        severity=severity,
        condition=condition,
        remediation=str(raw.get("remediation", "")),
        tags=[str(t) for t in raw.get("tags", [])],
        source=source,
    )
