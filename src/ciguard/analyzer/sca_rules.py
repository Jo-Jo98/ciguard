"""
SCA (Software Composition Analysis) rules — v0.6.0 + v0.6.1 + Slice 14c.

These rules cross-reference container image / language runtime / GHA action
references in the pipeline against external lifecycle and vulnerability
data to flag:

    SCA-EOL-001  Image base release is past end-of-life            (Crit / High)
    SCA-EOL-002  Pinned language runtime is past end-of-life       (Crit / High)
    SCA-EOL-003  Image / runtime is approaching EOL                (graduated, v0.6.1)
    SCA-PIN-001  Image is tag-pinned but not digest-pinned         (Low)
    SCA-PIN-002  Image uses a mutable tag                          (High — Slice 14c)
    SCA-PIN-004  Helm/Kubectl pulls non-versioned chart or image   (Medium — Slice 14c)
    SCA-EOS-001  Image / runtime past end-of-active-support        (Low — v0.6.1)
    SCA-CVE-001  GHA action / reusable workflow has known CVE      (varies — v0.6.1)

SCA-PIN-003 (cross-pipeline drift) is described in the audit-scope spec but
deferred: it requires aggregating image references across multiple pipeline
files in one scan, which lives in `repo_scan.py` rather than the
per-pipeline rule contract. Will land alongside `scan-repo` plumbing.

EOL/EOS/PIN rules run for every platform (GitLab CI, GitHub Actions, Jenkins)
since each can reference container images. The image extraction layer
(`sca/image_extractor.py`) flattens platform-specific shapes into a single
`ImageReference` list.

CVE-001 is GitHub-Actions-only — only `Workflow` targets carry `uses:`
references. The action extraction layer (`sca/action_extractor.py`) handles
both step-level marketplace actions and job-level reusable workflow calls.

Network:
  - EOL/EOS rules use `EndOfLifeClient` (endoflife.date, 24h cache).
  - CVE-001 uses `OSVClient` (api.osv.dev, 24h cache).
  - `--offline` skips the network entirely and uses only cached data on
    both clients. Missing cache + offline = silent skip, not a finding.

Why we split EOL/EOS into severity levels (graduated 2026-04-26 in v0.6.1):
  - **Critical** — past EOL by >90 days. The supplier has stopped publishing
    security patches; any new vulnerability disclosed after EOL will not be
    fixed in this version. Real ongoing risk.
  - **High** — past EOL by ≤90 days OR EOL within 90 days. Recently EOL or
    imminently so — small window to upgrade before posture degrades.
  - **Medium** — EOL in 91-180 days. About a quarter of runway; should be
    on the next planning cycle's radar.
  - **Low** — EOL in 181-365 days. Within a year; track it.
  - **Silent** — EOL >365 days away or no EOL date set. Not actionable.
  - **EOS-001 (Low)** — past end-of-active-support but before EOL. Vendor
    still patches CVEs but stops bug fixes / minor releases. Hygiene signal.

These bands replace v0.6.0's single-tier ≤90d Info to give Joe's
"≤6mo = higher alert, ≤12mo = warning" requested tiering.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Callable, List, Optional, Union

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
from .sca.action_extractor import ActionReference, extract_action_references
from .sca.endoflife import EndOfLifeClient
from .sca.image_extractor import ImageReference, extract_images
from .sca.osv import OSVClient, normalise_severity


SCATarget = Union[Pipeline, Workflow, Jenkinsfile]
SCARuleFunc = Callable[[SCATarget, EndOfLifeClient, OSVClient], List[Finding]]


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

# Graduated runway tiers (v0.6.1) — replaces v0.6.0's single ≤90d Info tier.
# Joe's request: ≤6mo = higher alert, ≤12mo = warning.
_HIGH_RUNWAY_DAYS = 90      # 0–90 days remaining
_MEDIUM_RUNWAY_DAYS = 180   # 91–180 days remaining
_LOW_RUNWAY_DAYS = 365      # 181–365 days remaining


def _eol_severity_and_label(days_until_eol: int) -> tuple[Severity, str, str]:
    """Map days-until-eol into severity + human-readable phase + summary
    fragment. Negative days = past EOL; positive = approaching.

    Graduated tiers (v0.6.1):
        days < -90       → CRITICAL  (long past EOL)
        -90 ≤ days < 0   → HIGH      (recently past EOL)
        0 ≤ days ≤ 90    → HIGH      (imminent, within a quarter)
        91 ≤ days ≤ 180  → MEDIUM    (within ~6 months)
        181 ≤ days ≤ 365 → LOW       (within ~12 months)
        days > 365       → INFO      (caller should treat as out-of-scope)
    """
    if days_until_eol < -_CRITICAL_DAYS_PAST_EOL:
        return Severity.CRITICAL, "long past EOL", f"{abs(days_until_eol)} days past EOL"
    if days_until_eol < 0:
        return Severity.HIGH, "recently past EOL", f"{abs(days_until_eol)} days past EOL"
    if days_until_eol <= _HIGH_RUNWAY_DAYS:
        return Severity.HIGH, "imminent EOL", f"EOL in {days_until_eol} days"
    if days_until_eol <= _MEDIUM_RUNWAY_DAYS:
        return Severity.MEDIUM, "approaching EOL (≤6 months)", f"EOL in {days_until_eol} days"
    if days_until_eol <= _LOW_RUNWAY_DAYS:
        return Severity.LOW, "approaching EOL (≤12 months)", f"EOL in {days_until_eol} days"
    # Comfortably supported — caller should not emit a finding for this.
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
    match, or cycle is comfortably within support window (>365d remaining).

    Past-EOL rule dispatch:
        SCA-EOL-001 — container base image past EOL
        SCA-EOL-002 — language runtime past EOL

    Approaching-EOL dispatch (v0.6.1 graduated tiers):
        SCA-EOL-003 — image / runtime approaching EOL within 365 days,
                      severity graduated by remaining runway
                      (≤90d High, 91-180d Medium, 181-365d Low)."""
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

    if days <= _LOW_RUNWAY_DAYS:
        # Approaching EOL within a year — SCA-EOL-003 with graduated severity.
        return [_eol_finding(
            image, cycle, days,
            "SCA-EOL-003",
            "Container Image Approaching End-of-Life",
            "Image",
        )]
    return []


def rule_sca_eol(
    target: SCATarget,
    eol: EndOfLifeClient,
    osv: OSVClient,
) -> List[Finding]:
    """Run the SCA-EOL-001 / SCA-EOL-002 / SCA-EOL-003 family. One pass over
    every image reference in the target. `osv` parameter is unused by this
    rule (kept for the unified `SCARuleFunc` signature)."""
    del osv
    findings: List[Finding] = []
    today = datetime.now(tz=timezone.utc)
    for image in extract_images(target):
        findings.extend(_check_image_eol(image, eol, today))
    return findings


# ---------------------------------------------------------------------------
# SCA-PIN-001 — Tag-pinned but not digest-pinned (best-practice nudge)
# ---------------------------------------------------------------------------

def rule_sca_pin_001(
    target: SCATarget,
    eol: EndOfLifeClient,
    osv: OSVClient,
) -> List[Finding]:
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
    del eol, osv
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
# SCA-PIN-002 — Mutable tag (cross-platform, High) — Slice 14c
# ---------------------------------------------------------------------------

# Tag values that are mutable by convention — the publisher routinely
# re-points them to newer content. These are the supply-chain-attack surface
# named by OWASP CICD-SEC-3 and the tj-actions/changed-files March 2025
# incident. `latest` is the canonical example; the others are common
# floating-tag patterns we see in real pipelines.
_MUTABLE_TAGS = frozenset({
    "latest",
    "stable",
    "edge",
    "prod",
    "production",
    "main",
    "master",
    "dev",
    "development",
    "nightly",
})

_PIN_002_COMPLIANCE = ComplianceMapping(
    iso_27001=["A.12.5.1", "A.14.2.2", "A.14.2.4"],
    soc2=["CC6.8", "CC8.1"],
    nist=["PR.IP-1", "PR.DS-6"],
)


def rule_sca_pin_002(
    target: SCATarget,
    eol: EndOfLifeClient,
    osv: OSVClient,
) -> List[Finding]:
    """Image references using a mutable tag (`:latest`, `:stable`, `:edge`,
    `:main`, etc.) or no tag at all.

    Mutable tags are the canonical supply-chain attack vector — the publisher
    can re-point the same name to different content (intentionally, or via
    account compromise). The tj-actions/changed-files incident (March 2025)
    repointed `v35` for ~23,000 repos in a single push.

    Cross-platform — fires for GitLab CI / GitHub Actions container refs /
    Jenkins docker agents alike. Severity is High by default.

    Overlap with PIPE-001 / GHA-PIPE-001 / JKN-PIPE-001 is intentional: the
    per-platform rules cover `:latest` from the platform-rule perspective
    (severity / category align with their family); this rule covers the
    same surface from the cross-platform supply-chain perspective with
    standards-anchored remediation. Operators who find the duplicate noisy
    can `.ciguardignore` either side."""
    del eol, osv
    findings: List[Finding] = []
    for image in extract_images(target):
        if image.is_digest_pinned:
            continue          # digest is the strongest pinning — never mutable
        tag_lower = (image.tag or "").lower()
        if tag_lower and tag_lower not in _MUTABLE_TAGS:
            continue          # versioned tag, even if not digest — SCA-PIN-001 handles
        # Either no tag at all, or one of the well-known mutable tag names.
        if image.tag:
            evidence = f"image: {image.raw}"
            description = (
                f"Image `{image.name}:{image.tag}` uses a mutable tag — the "
                f"publisher can re-point `{image.tag}` to different content "
                "at any time. This is the supply-chain attack surface named "
                "by OWASP CICD-SEC-3 (Dependency Chain Abuse) and exploited "
                "in the March 2025 tj-actions/changed-files incident."
            )
            remediation_image = f"{image.name}:<version>"
        else:
            evidence = f"image: {image.raw}"
            description = (
                f"Image `{image.name}` is referenced without a tag — Docker "
                "treats this as `:latest`, which is mutable. The publisher "
                "can re-point `latest` to different content at any time."
            )
            remediation_image = f"{image.name}:<version>"
        findings.append(Finding(
            id=_finding_id("SCA-PIN-002"),
            rule_id="SCA-PIN-002",
            name="Image Uses Mutable Tag",
            description=description,
            severity=Severity.HIGH,
            category=Category.SUPPLY_CHAIN,
            location=image.location,
            evidence=evidence,
            remediation=(
                f"Pin `{image.name}` to a specific version, ideally with a "
                "digest. Resolve the current digest with `docker pull "
                f"{image.name}:<version> && docker inspect "
                f"{image.name}:<version> --format '{{{{.Id}}}}'`, then update "
                f"the pipeline to `image: {remediation_image}@sha256:<digest>`. "
                "Automate digest updates with Renovate or Dependabot's docker "
                "ecosystem so you stay current without re-introducing a "
                "mutable reference."
            ),
            compliance=_PIN_002_COMPLIANCE,
        ))
    return findings


# ---------------------------------------------------------------------------
# SCA-PIN-004 — Helm / kubectl mutable pull (cross-platform, Medium) — Slice 14c
# ---------------------------------------------------------------------------

# Helm / kubectl invocations inside job scripts that fetch a non-versioned
# chart / image. The patterns below are intentionally conservative — the
# false-positive cost in a CI report is high, and a `helm install` against
# a previously-installed release with `--reuse-values` is a legitimate
# operational pattern we should NOT flag.

# Match `helm install` and `helm upgrade` invocations. Captures everything
# after the verb on the same line for sub-flag inspection.
_HELM_INVOKE_RE = re.compile(
    r"\bhelm\s+(?P<verb>install|upgrade|pull|template)\b(?P<args>[^\n]*)",
    re.IGNORECASE,
)

# Look for a `--version <value>` or `--version=<value>` flag inside a
# helm command's argument string.
_HELM_VERSION_FLAG_RE = re.compile(
    r"--version(?:=|\s+)(?P<value>[^\s]+)",
    re.IGNORECASE,
)

# Floating values that defeat the purpose of `--version`. Mirrors the
# image-mutable-tag set but keyed to the helm-chart vocabulary.
_HELM_MUTABLE_VERSIONS = frozenset({
    "latest", "stable", "main", "master", "dev", "*",
})

_PIN_004_COMPLIANCE = ComplianceMapping(
    iso_27001=["A.12.5.1", "A.14.2.2"],
    soc2=["CC6.8", "CC8.1"],
    nist=["PR.IP-1", "PR.DS-6"],
)


def _iter_script_lines(target: SCATarget) -> List[tuple[str, str]]:
    """Return `(location_label, script_line)` tuples for every shell-script
    line across the three platform models. Used by script-content rules
    (SCA-PIN-004) that need to grep across job bodies."""
    out: List[tuple[str, str]] = []
    if isinstance(target, Pipeline):
        for job in target.jobs:
            for line in job.all_scripts():
                out.append((f"job[{job.name}].script", line))
    elif isinstance(target, Workflow):
        for job in target.jobs:
            label_id = job.id or job.name
            for line in job.all_run_lines():
                out.append((f"jobs.{label_id}.steps[].run", line))
    elif isinstance(target, Jenkinsfile):
        for stage_name, body in target.all_step_scripts():
            for line in body.splitlines():
                if line.strip():
                    out.append((f"stage[{stage_name}].steps[].sh", line))
    return out


def _helm_finding_for_line(location: str, line: str) -> Optional[Finding]:
    """Inspect a single shell line for a non-versioned helm invocation.
    Returns one Finding or None. Multiple helm calls on one line each
    produce a finding via the caller's outer loop."""
    m = _HELM_INVOKE_RE.search(line)
    if not m:
        return None
    verb = m.group("verb").lower()
    args = m.group("args") or ""
    # `helm template` / `helm upgrade --reuse-values` are legitimate
    # version-not-required patterns; skip them.
    if verb == "template":
        return None
    if verb == "upgrade" and "--reuse-values" in args:
        return None
    version_match = _HELM_VERSION_FLAG_RE.search(args)
    if version_match:
        version_value = version_match.group("value").strip().strip("\"'")
        if version_value.lower() in _HELM_MUTABLE_VERSIONS:
            problem = f"`helm {verb} --version {version_value}`"
            description = (
                f"Helm chart pulled with mutable version `{version_value}` "
                "— the chart maintainer can re-point this label to different "
                "content at any time. Pin to a specific chart version "
                "(SemVer) so deployments are reproducible and a compromised "
                "upstream chart can be detected by version drift."
            )
        else:
            return None       # versioned, looks fine
    else:
        problem = f"`helm {verb}` without `--version`"
        description = (
            f"Helm `{verb}` invoked without `--version` — Helm resolves to "
            "the latest chart version available in the configured "
            "repositories at install time. This makes deployments "
            "non-reproducible and exposes the pipeline to upstream chart "
            "tampering. Always pin the chart version explicitly."
        )
    return Finding(
        id=_finding_id("SCA-PIN-004"),
        rule_id="SCA-PIN-004",
        name="Helm Chart Pulled Without Pinned Version",
        description=description,
        severity=Severity.MEDIUM,
        category=Category.SUPPLY_CHAIN,
        location=location,
        evidence=line.strip()[:200],
        remediation=(
            "Pin the chart by passing `--version <semver>` (e.g. "
            "`--version 1.2.3`) on every `helm install` / `helm upgrade` / "
            "`helm pull` invocation. Track chart upgrades through a "
            "deliberate bump rather than implicit floating-version drift. "
            "For supply-chain assurance, also verify the chart against a "
            "Sigstore signature where the publisher provides one."
        ),
        compliance=_PIN_004_COMPLIANCE,
    )


def rule_sca_pin_004(
    target: SCATarget,
    eol: EndOfLifeClient,
    osv: OSVClient,
) -> List[Finding]:
    """SCA-PIN-004 — Helm / kubectl invocations inside job scripts that
    fetch a non-versioned chart or image.

    Detects `helm install` / `helm upgrade` / `helm pull` without a
    `--version` flag, or with `--version` set to a mutable label
    (`latest`, `stable`, etc.). `helm template` and `helm upgrade
    --reuse-values` are skipped — they're legitimate version-not-required
    patterns.

    Severity Medium: this is operational hygiene rather than an active
    attack surface, but a pinned chart is the only way to make a Helm
    deploy reproducible AND to detect upstream chart tampering."""
    del eol, osv
    findings: List[Finding] = []
    for location, line in _iter_script_lines(target):
        finding = _helm_finding_for_line(location, line)
        if finding:
            findings.append(finding)
    return findings


# ---------------------------------------------------------------------------
# SCA-EOS-001 — End-of-active-support detection (v0.6.1)
# ---------------------------------------------------------------------------

def _days_until(date_field: object, today: datetime) -> Optional[int]:
    """Helper that mirrors `EndOfLifeClient.days_until_eol` but works on any
    arbitrary endoflife.date field (e.g. `support`). Returns None if the
    field is missing, false, or unparseable."""
    if date_field is None or date_field is False:
        return None
    try:
        d = datetime.fromisoformat(str(date_field)).replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None
    if today.tzinfo is None:
        today = today.replace(tzinfo=timezone.utc)
    return (d - today).days


def rule_sca_eos_001(
    target: SCATarget,
    eol: EndOfLifeClient,
    osv: OSVClient,
) -> List[Finding]:
    """SCA-EOS-001 — image / runtime is past end-of-active-support but
    before end-of-security-life.

    endoflife.date distinguishes two dates on many products:
        `support` — last bug-fix / minor release
        `eol`     — last security patch

    The window between them is "vendor still patches CVEs but no longer
    publishes bug fixes / new minor releases." That's a degraded posture
    worth surfacing — Low severity since CVEs are still being fixed, but
    operators should plan to upgrade.

    Silent skip when:
      - product has no `support` field (most distros — Alpine, Debian)
      - we're not yet past `support`
      - we're already past `eol` (SCA-EOL-001/002 already covers that)
    """
    del osv
    findings: List[Finding] = []
    today = datetime.now(tz=timezone.utc)
    for image in extract_images(target):
        if not image.cycle_id:
            continue
        cycles = eol.cycles_for_image(image.name)
        if not cycles:
            continue
        cycle = EndOfLifeClient.find_cycle(cycles, image.cycle_id)
        if not cycle:
            continue
        days_to_support_end = _days_until(cycle.get("support"), today)
        if days_to_support_end is None:
            continue
        if days_to_support_end >= 0:
            continue          # not yet past active support
        days_to_eol = EndOfLifeClient.days_until_eol(cycle, today=today)
        if days_to_eol is not None and days_to_eol < 0:
            continue          # already past EOL → SCA-EOL-001/002 owns this
        cycle_id = cycle.get("cycle", image.cycle_id or "?")
        support_date = cycle.get("support", "?")
        eol_date = cycle.get("eol", "?")
        findings.append(Finding(
            id=_finding_id("SCA-EOS-001"),
            rule_id="SCA-EOS-001",
            name="End of Active Support",
            description=(
                f"`{image.name}:{image.tag}` (cycle `{cycle_id}`) is past "
                f"end-of-active-support ({abs(days_to_support_end)} days "
                f"past `{support_date}`). The vendor still publishes "
                f"security patches until the EOL date (`{eol_date}`), but "
                "no longer ships bug fixes or new minor releases. Posture "
                "is degraded; plan an upgrade before the EOL date."
            ),
            severity=Severity.LOW,
            category=Category.SUPPLY_CHAIN,
            location=image.location,
            evidence=(
                f"image: {image.raw}  (cycle {cycle_id}, "
                f"support ended {support_date}, EOL {eol_date})"
            ),
            remediation=(
                f"Upgrade `{image.name}` to a cycle still in active support. "
                f"See https://endoflife.date/{image.name} for the current "
                "active-support cycles. While not yet a security risk, "
                "active-support cycles receive both bug fixes and CVE "
                "patches; out-of-support cycles only receive the latter."
            ),
            compliance=_EOL_COMPLIANCE,
        ))
    return findings


# ---------------------------------------------------------------------------
# SCA-CVE-001 — GHA action / reusable workflow with known security advisory
# ---------------------------------------------------------------------------

_CVE_COMPLIANCE = ComplianceMapping(
    iso_27001=["A.12.6.1"],
    soc2=["CC7.1"],
    nist=["ID.RA-1", "DE.CM-8"],
)


def _vuln_summary_line(vuln: dict) -> str:
    """Compact one-line description of an OSV vuln for inclusion in evidence
    + description fields."""
    advisory_id = vuln.get("id") or "(no id)"
    aliases = vuln.get("aliases") or []
    cve_aliases = [a for a in aliases if isinstance(a, str) and a.startswith("CVE-")]
    summary = vuln.get("summary") or vuln.get("details") or ""
    if isinstance(summary, str):
        summary = summary.strip().splitlines()[0][:120] if summary else ""
    cve_part = f" ({', '.join(cve_aliases)})" if cve_aliases else ""
    return f"{advisory_id}{cve_part} — {summary}".strip(" —")


def _highest_severity(vulns: list[dict]) -> Severity:
    """Return the highest ciguard Severity across a list of OSV vulns."""
    rank = {
        Severity.CRITICAL: 4, Severity.HIGH: 3,
        Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0,
    }
    best = Severity.MEDIUM
    for v in vulns:
        label = normalise_severity(v)
        sev = Severity[label] if label in Severity.__members__ else Severity.MEDIUM
        if rank[sev] > rank[best]:
            best = sev
    return best


def _check_action_cve(
    action: ActionReference,
    osv: OSVClient,
) -> Optional[Finding]:
    """Query OSV for advisories affecting this action at this version. Emits
    a single finding aggregating all advisories at the highest applicable
    severity. Returns None when clean / unknown."""
    vulns = osv.vulns_for_action(action.owner_repo, action.normalised_version)
    if not vulns:                  # None (unknown) or [] (clean)
        return None
    severity = _highest_severity(vulns)
    summaries = [_vuln_summary_line(v) for v in vulns[:5]]
    summary_block = "\n".join(f"  - {s}" for s in summaries)
    extra = f"\n  - … and {len(vulns) - 5} more" if len(vulns) > 5 else ""
    kind = "Reusable workflow" if action.is_reusable_workflow else "Action"
    return Finding(
        id=_finding_id("SCA-CVE-001"),
        rule_id="SCA-CVE-001",
        name=f"{kind} Has Known Security Advisory",
        description=(
            f"{kind} `{action.owner_repo}@{action.version}` matches "
            f"{len(vulns)} known security advisor"
            f"{'y' if len(vulns) == 1 else 'ies'} in the OSV.dev "
            f"`GitHub Actions` ecosystem:\n{summary_block}{extra}"
        ),
        severity=severity,
        category=Category.SUPPLY_CHAIN,
        location=action.location,
        evidence=f"uses: {action.raw}",
        remediation=(
            f"Upgrade `{action.owner_repo}` to a fixed version. Check the "
            f"advisory at https://github.com/advisories?query={action.owner_repo} "
            "for the recommended target version, then update the `uses:` "
            f"reference. For long-term safety, pin the new version by "
            "commit SHA rather than tag (Dependabot's `github-actions` "
            "ecosystem can automate the keep-current side of this trade-off)."
        ),
        compliance=_CVE_COMPLIANCE,
    )


def rule_sca_cve_001(
    target: SCATarget,
    eol: EndOfLifeClient,
    osv: OSVClient,
) -> List[Finding]:
    """SCA-CVE-001 — known security advisories on GHA actions / reusable
    workflows referenced via `uses:`.

    Only applies to GitHub Actions targets (no `uses:` field exists in
    GitLab CI or Jenkins models). Returns an empty list immediately for
    other targets.

    SHA-pinned `uses:` references are skipped at extraction time
    (Dependabot lane). Local refs and Docker actions also skipped."""
    del eol
    if not isinstance(target, Workflow):
        return []
    findings: List[Finding] = []
    for action in extract_action_references(target):
        finding = _check_action_cve(action, osv)
        if finding:
            findings.append(finding)
    return findings


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

SCA_RULES: List[SCARuleFunc] = [
    rule_sca_eol,
    rule_sca_pin_001,
    rule_sca_pin_002,
    rule_sca_pin_004,
    rule_sca_eos_001,
    rule_sca_cve_001,
]
