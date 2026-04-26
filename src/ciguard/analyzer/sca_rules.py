"""
SCA (Software Composition Analysis) rules — v0.6.0.

These rules cross-reference container image / language runtime references
in the pipeline against the endoflife.date catalogue to flag:

    SCA-EOL-001  Image base release is past end-of-life       (Critical / High)
    SCA-EOL-002  Pinned language runtime is past end-of-life  (Critical / High)
    SCA-EOL-003  Image / runtime is approaching EOL (≤90 d)   (Info)
    SCA-PIN-001  Image is tag-pinned but not digest-pinned    (Low — best-practice nudge)

All rules run for every platform (GitLab CI, GitHub Actions, Jenkins) since
each can reference container images. The image extraction layer
(`sca/image_extractor.py`) flattens platform-specific shapes into a single
`ImageReference` list.

Network: rules use the `EndOfLifeClient` with on-disk caching (24h TTL by
default). `--offline` skips the network entirely and uses only cached data.
A missing cache + offline mode = silent skip, not a finding.

Why we split EOL into severity levels:
  - **Critical** — past EOL by >90 days. The supplier has stopped publishing
    security patches; any new vulnerability disclosed after EOL will not be
    fixed in this version. Real ongoing risk.
  - **High** — past EOL by ≤90 days. Recently EOL — no new patches but the
    inventory of known issues is still small. Window to upgrade.
  - **Info** — approaching EOL (≤90 days remaining). Advance warning so
    the upgrade can be planned, not reactive.

We deliberately distinguish these because flagging "approaching EOL" as
Critical would create alert fatigue and dilute the signal of the genuine
"past-EOL-and-vulnerable" findings.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, List, Union

from ..models.jenkinsfile import Jenkinsfile
from ..models.pipeline import (
    Category,
    ComplianceMapping,
    Finding,
    Pipeline,
    Severity,
)
from ..models.workflow import Workflow
from .rules import _finding_id
from .sca.endoflife import EndOfLifeClient
from .sca.image_extractor import ImageReference, extract_images


SCATarget = Union[Pipeline, Workflow, Jenkinsfile]
SCARuleFunc = Callable[[SCATarget, EndOfLifeClient], List[Finding]]


# Standard compliance mapping for EOL findings — maps to "use of unsupported
# / vulnerable components" controls across all three frameworks.
_EOL_COMPLIANCE = ComplianceMapping(
    iso_27001=["A.12.6.1", "A.14.2.7"],
    soc2=["CC7.1", "CC8.1"],
    nist=["ID.RA-1", "PR.IP-12"],
)

_PIN_COMPLIANCE = ComplianceMapping(
    iso_27001=["A.12.5.1", "A.14.2.2"],
    soc2=["CC8.1"],
    nist=["PR.IP-1"],
)

# Cutoff (days past EOL) for Critical-vs-High split.
_CRITICAL_DAYS_PAST_EOL = 90

# How far ahead to look for "approaching EOL" (Info severity).
_APPROACHING_EOL_DAYS = 90


def _eol_severity_and_label(days_until_eol: int) -> tuple[Severity, str, str]:
    """Map days-until-eol into severity + human-readable phase + summary
    fragment. Negative days = past EOL; positive = approaching."""
    if days_until_eol < -_CRITICAL_DAYS_PAST_EOL:
        return Severity.CRITICAL, "long past EOL", f"{abs(days_until_eol)} days past EOL"
    if days_until_eol < 0:
        return Severity.HIGH, "recently past EOL", f"{abs(days_until_eol)} days past EOL"
    if days_until_eol <= _APPROACHING_EOL_DAYS:
        return Severity.INFO, "approaching EOL", f"EOL in {days_until_eol} days"
    # Not in scope of any SCA-EOL rule
    return Severity.INFO, "supported", f"EOL in {days_until_eol} days"


# ---------------------------------------------------------------------------
# SCA-EOL-001 / SCA-EOL-002 / SCA-EOL-003 — image and runtime EOL detection
# ---------------------------------------------------------------------------

def _eol_finding(
    image: ImageReference,
    cycle: dict,
    days_until_eol: int,
    rule_id: str,
    name: str,
    description_prefix: str,
) -> Finding:
    severity, phase, summary = _eol_severity_and_label(days_until_eol)
    eol_date = cycle.get("eol", "?")
    cycle_id = cycle.get("cycle", image.cycle_id or "?")
    return Finding(
        id=_finding_id(rule_id),
        rule_id=rule_id,
        name=name,
        description=(
            f"{description_prefix} `{image.name}:{image.tag}` resolves to "
            f"cycle `{cycle_id}` which is {phase} ({summary}, EOL date "
            f"`{eol_date}`). After EOL the upstream supplier no longer "
            "publishes security patches; any new vulnerability disclosed "
            "against this version will remain unfixed."
        ),
        severity=severity,
        category=Category.SUPPLY_CHAIN,
        location=image.location,
        evidence=f"image: {image.raw}  (cycle {cycle_id}, EOL {eol_date})",
        remediation=(
            f"Upgrade `{image.name}` to a supported cycle. Consult "
            f"https://endoflife.date/{cycle.get('_product', image.name)} "
            "for the current supported cycles and pick the latest LTS. "
            "Re-run ciguard after the bump to confirm the finding clears."
        ),
        compliance=_EOL_COMPLIANCE,
    )


def _check_image_eol(
    image: ImageReference,
    eol: EndOfLifeClient,
    today: datetime,
) -> List[Finding]:
    """Look up an image in endoflife.date and emit findings if its cycle
    is past or approaching EOL. Returns empty list if no data, no cycle
    match, or cycle is comfortably within support window."""
    if not image.cycle_id:
        return []
    cycles = eol.cycles_for_image(image.name)
    if not cycles:
        return []
    cycle = EndOfLifeClient.find_cycle(cycles, image.cycle_id)
    if not cycle:
        return []
    days = EndOfLifeClient.days_until_eol(cycle, today=today)
    if days is None:
        return []  # cycle has no EOL date yet (`eol: false`)

    # Dispatch by severity. Past EOL → SCA-EOL-001 (image base) /
    # SCA-EOL-002 (language runtime). Approaching EOL → SCA-EOL-003.
    is_language_runtime = image.name.lower() in {
        "python", "node", "nodejs", "ruby", "golang", "go",
        "openjdk", "eclipse-temurin", "amazoncorretto", "rust", "php",
    }

    if days < 0:
        rule_id = "SCA-EOL-002" if is_language_runtime else "SCA-EOL-001"
        name = (
            "End-of-Life Language Runtime"
            if is_language_runtime
            else "End-of-Life Container Base Image"
        )
        prefix = (
            "Language runtime image"
            if is_language_runtime
            else "Container base image"
        )
        return [_eol_finding(image, cycle, days, rule_id, name, prefix)]

    if days <= _APPROACHING_EOL_DAYS:
        return [_eol_finding(
            image, cycle, days,
            "SCA-EOL-003",
            "Container Image Approaching End-of-Life",
            "Image",
        )]
    return []


def rule_sca_eol(target: SCATarget, eol: EndOfLifeClient) -> List[Finding]:
    """Run the SCA-EOL-001 / SCA-EOL-002 / SCA-EOL-003 family. One pass over
    every image reference in the target."""
    findings: List[Finding] = []
    today = datetime.now(tz=timezone.utc)
    for image in extract_images(target):
        findings.extend(_check_image_eol(image, eol, today))
    return findings


# ---------------------------------------------------------------------------
# SCA-PIN-001 — Tag-pinned but not digest-pinned (best-practice nudge)
# ---------------------------------------------------------------------------

def rule_sca_pin_001(target: SCATarget, eol: EndOfLifeClient) -> List[Finding]:
    """Image references with a tag (e.g. `alpine:3.18`) but no digest
    (`@sha256:...`). Tags are mutable in most registries — the same name
    can be repointed to different content by the publisher. Pinning to
    digest is the only way to get true content immutability.

    PIPE-001 / GHA-PIPE-001 / JKN-PIPE-001 already catch the worst case
    (`:latest` or no tag at all). This rule catches the next-tier issue:
    pinned-by-tag-but-not-by-digest. Low severity — most teams accept this
    trade-off knowingly. Still worth surfacing for high-trust pipelines.

    Skipped for images already flagged by the EOL rules (no point
    duplicating signal) — but only when EOL severity is High or Critical.
    Approaching-EOL images still get the pin nudge."""
    findings: List[Finding] = []
    for image in extract_images(target):
        if not image.has_tag:
            continue          # PIPE-001 catches bare/`:latest`
        if image.is_digest_pinned:
            continue          # already pinned correctly
        # Skip the most generic tags — the existing PIPE-001 family
        # handles those cleaner.
        if image.tag in ("latest", "stable", "edge", "main", "master"):
            continue
        findings.append(Finding(
            id=_finding_id("SCA-PIN-001"),
            rule_id="SCA-PIN-001",
            name="Image Pinned by Tag, Not by Digest",
            description=(
                f"Image `{image.name}:{image.tag}` is pinned by tag, not by "
                "digest. Tags are mutable in most container registries — "
                "the publisher can re-point the same tag to different "
                "content (intentionally or via account compromise). "
                "Digest pinning (`@sha256:...`) is the only true content "
                "immutability guarantee."
            ),
            severity=Severity.LOW,
            category=Category.SUPPLY_CHAIN,
            location=image.location,
            evidence=f"image: {image.raw}",
            remediation=(
                f"Resolve the current digest with `docker pull {image.raw} "
                f"&& docker inspect {image.raw} --format '{{{{.Id}}}}'`, "
                f"then update the pipeline to `image: {image.name}:"
                f"{image.tag}@sha256:<digest>`. Automate digest updates "
                "with Renovate or Dependabot's docker ecosystem rather "
                "than hand-pinning."
            ),
            compliance=_PIN_COMPLIANCE,
        ))
    return findings


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

SCA_RULES: List[SCARuleFunc] = [
    rule_sca_eol,
    rule_sca_pin_001,
]
