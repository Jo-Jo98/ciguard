"""Interactive HTML reporter — Slice 14a Phase 1.1.

The post-pivot hero artifact: a single self-contained HTML file that
visualises a pipeline as a DAG with security gates annotated. Open in
any browser; no server required; emailable to a client.

Output shape (`ciguard scan --format html-interactive --output map.html`):
- One HTML document
- Inline D3 v7 (vendored under `_assets/d3.v7.min.js`)
- Inline viewer JS (computes a layered layout + renders nodes + edges)
- Inline scan data as `<script type="application/json">`

Phase 1.1 scope (THIS file's current behaviour):
- Render every job as an SVG node positioned by topological depth
- Draw dependency edges between jobs
- Severity-coloured node borders (highest finding on the job determines colour)
- Job-name + finding-count tooltip on hover

Phase 1.2 onwards (follow-up sessions):
- Gate iconography (lock / key / shield / pin badges per node)
- Click-to-side-panel with full job YAML + finding list + remediation
- Filter/focus to highlight blast radius of a finding
- Diff mode (load two HTML files side-by-side, show drift)
- Print-mode CSS for clean PDF export
- Polish: motion, responsive, keyboard nav, screen-reader semantics

Architectural commitment from the pivot's audit-scope reference doc:
every parsed pipeline includes a "service identity" (derivable from
repo + workflow targets) so the multi-pipeline / org-level views
(Slice 16/17) can join across pipelines without a future refactor.
The `service_identity` field below is reserved for that.
"""
from __future__ import annotations

import json
import re as _re
from collections import defaultdict
from importlib.resources import files
from pathlib import Path
from typing import Any, Dict, List

import yaml

from ciguard.models.pipeline import Finding, Job, Report, Severity

from ..analyzer.sca.image_extractor import classify_pin_status as _image_pin_status


def _render_job_yaml(job: Job) -> str:
    """Re-serialise a parsed Job to YAML for the click-to-detail panel.

    This is intentionally lossy — comments and the original key ordering
    are gone — but it produces a clean readable representation of the
    JOB SHAPE that an auditor can refer to. A future iteration could
    capture the raw YAML span at parse time for byte-exact display, but
    that's a parser change; this works against any v0.x Report.

    Default / empty fields are stripped so the output stays focused on
    what's actually configured (no walls of `dependencies: []`).
    """
    raw = job.model_dump(by_alias=True, exclude_none=True, exclude_defaults=True)
    # Pydantic round-trips unknown / Any fields including the empty
    # collections we explicitly set on the model. Drop them post-dump
    # too in case `exclude_defaults` missed them.
    cleaned: Dict[str, Any] = {}
    for k, v in raw.items():
        if v in ("", [], {}, None):
            continue
        cleaned[k] = v
    if not cleaned:
        return f"{job.name}: {{}}\n"
    # Stable, predictable ordering: name first, then config keys alphabetically.
    ordered: Dict[str, Any] = {"name": job.name}
    for k in sorted(cleaned):
        if k == "name":
            continue
        ordered[k] = cleaned[k]
    return yaml.safe_dump(
        ordered, sort_keys=False, default_flow_style=False, width=72,
    )


# ---- Severity → colour palette (post-pivot visual language) ---------------
#
# Severity colours live inline in `_VIEWER_CSS` further down — early
# Slice 14a drafts had Python-side palette constants here; they were
# inlined into the CSS once the visual language stabilised. Removed
# 2026-05-02 to clear `py/unused-global-variable` (#32, #33).


# ---- Data-shape transform: Report → visualiser JSON -----------------------


def _highest_severity(findings: List[Finding]) -> str:
    """Return the highest-severity label among findings, or empty string
    if none. Used to colour node borders."""
    if not findings:
        return ""
    order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    sevs = sorted(findings, key=lambda f: order.get(f.severity, 99))
    return sevs[0].severity.value


def _job_dependencies(job: Job) -> List[str]:
    """Resolve the set of job names this job depends on.

    GitLab CI uses both `dependencies:` (older, artifact-passing) and
    `needs:` (newer, DAG ordering). GitHub Actions uses `needs:`. Both
    are normalised here to a flat list of job-name strings.
    """
    deps: List[str] = list(job.dependencies)
    for n in job.needs:
        if isinstance(n, str):
            deps.append(n)
        elif isinstance(n, dict):
            name = n.get("job") or n.get("name")
            if isinstance(name, str):
                deps.append(name)
    # Dedup while preserving order
    seen: set = set()
    out: List[str] = []
    for d in deps:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


# Patterns that identify which job a finding's `location` belongs to.
# Different rules emit different shapes:
#
#   - bare job name           — most ciguard core rules
#   - "<job>:<line>"          — line-attached findings
#   - "job[<name>].<path>"    — GitLab SCA (image / services / etc.)
#   - "job[<name>]"           — GitLab SCA simple
#   - "jobs.<name>.<path>"    — GitHub Actions SCA + IAM rules
#   - "jobs.<name>"           — GitHub Actions simple
#   - "stage[<name>].<path>"  — Jenkins SCA
#   - "stage[<name>]"         — Jenkins simple
#   - "global", "global.x",
#     "pipeline.x", "<top-level>" — pipeline-level (no owning job)
#
# The visualiser groups findings under the job-node they belong to. A
# regex extracts the candidate name from each bracket / dotted form;
# we then verify it against the known-job-names list (so we don't
# accidentally match a typo'd location that happens to look like a job).

_LOC_PATTERNS = [
    _re.compile(r"^job\[([^\]]+)\](?:\..*)?$"),
    _re.compile(r"^stage\[([^\]]+)\](?:\..*)?$"),
    _re.compile(r"^jobs\.([^.]+)(?:\..*)?$"),
]


def _owning_job(location: str, known_job_names: set) -> str | None:
    """Return the job name a finding's `location` belongs to, or None
    when the finding is pipeline-level / global / unattached."""
    if location in known_job_names:
        return location
    if ":" in location:
        head = location.split(":", 1)[0]
        if head in known_job_names:
            return head
    for pat in _LOC_PATTERNS:
        m = pat.match(location)
        if m:
            candidate = m.group(1)
            if candidate in known_job_names:
                return candidate
    return None


def _humanise_location(location: str) -> str:
    """Render an internal location string into something readable for
    side-panel display.

    Examples:
        job[deploy].image            → deploy · image
        jobs.build.runs-on           → build · runs-on
        stage[Test].steps.script     → Test · steps.script
        global.variables             → Pipeline · variables
        global.include               → Pipeline · include
        pipeline.image               → Pipeline · image
        global                       → Pipeline (global)
        <top-level>                  → Pipeline (top-level)
    """
    if location == "global":
        return "Pipeline (global)"
    if location == "<top-level>":
        return "Pipeline (top-level)"
    if location.startswith("global."):
        return "Pipeline · " + location[len("global."):]
    if location.startswith("pipeline."):
        return "Pipeline · " + location[len("pipeline."):]
    for prefix in ("job[", "stage["):
        if location.startswith(prefix):
            m = _re.match(r"^(?:job|stage)\[([^\]]+)\](?:\.(.*))?$", location)
            if m:
                rest = m.group(2)
                return f"{m.group(1)}{(' · ' + rest) if rest else ''}"
    if location.startswith("jobs."):
        rest = location[len("jobs."):]
        if "." in rest:
            name, sub = rest.split(".", 1)
            return f"{name} · {sub}"
        return rest
    return location


def _findings_for_location(report: Report, job_name: str,
                           known_job_names: set) -> List[Finding]:
    """Match findings owned by a given job, recognising every location
    shape rules emit (see `_LOC_PATTERNS`)."""
    matched: List[Finding] = []
    for f in report.findings:
        if _owning_job(f.location, known_job_names) == job_name:
            matched.append(f)
    return matched


def _to_visual_data(report: Report) -> Dict[str, Any]:
    """Transform a Report into the JSON shape the viewer JS consumes.

    Locked architecture: stable IDs (slugified job names; collision
    prevention via a counter suffix), severity-aware annotations,
    fingerprinted findings carried through for the side-panel work
    in Phase 1.2.
    """
    # Build stable IDs for every job. Job names can contain characters
    # that won't be valid in HTML/CSS IDs (spaces, slashes); slugify.
    used_ids: set = set()

    def _slug(name: str) -> str:
        base = "".join(c if c.isalnum() else "-" for c in name).strip("-").lower()
        candidate = base or "job"
        counter = 1
        while candidate in used_ids:
            counter += 1
            candidate = f"{base}-{counter}"
        used_ids.add(candidate)
        return candidate

    jobs_data: List[Dict[str, Any]] = []
    name_to_id: Dict[str, str] = {}

    # Pre-compute the set of job names so location-matching can verify
    # candidate names extracted from `job[...]` / `jobs.<name>` shapes.
    known_job_names: set = {j.name for j in report.pipeline.jobs}

    for job in report.pipeline.jobs:
        job_id = _slug(job.name)
        name_to_id[job.name] = job_id

        job_findings = _findings_for_location(report, job.name, known_job_names)
        finding_payloads = [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "message": f.name,
                "location": f.location,
                "display_location": _humanise_location(f.location),
                "evidence": f.evidence,
                "category": f.category.value,
                "fingerprint": f.fingerprint,
            }
            for f in sorted(
                job_findings,
                key=lambda f: ({Severity.CRITICAL: 0, Severity.HIGH: 1,
                                Severity.MEDIUM: 2, Severity.LOW: 3,
                                Severity.INFO: 4}.get(f.severity, 99),
                               f.rule_id),
            )
        ]
        env_name = job.environment.name if job.environment else None

        # Per-severity counts on this job (badge population)
        sev_counts: Dict[str, int] = defaultdict(int)
        for f in job_findings:
            sev_counts[f.severity.value] += 1

        jobs_data.append({
            "id": job_id,
            "name": job.name,
            "stage": job.stage,
            "image": job.image,
            "pin_status": _image_pin_status(job.image),
            "environment": env_name,
            "is_deploy": job.is_deploy_job(),
            "targets_production": job.targets_production(),
            "has_manual_gate": job.has_manual_gate(),
            "deps": _job_dependencies(job),  # raw names; resolved client-side
            "findings": finding_payloads,
            "findings_by_severity": dict(sev_counts),
            "highest_severity": _highest_severity(job_findings),
            # YAML excerpt for the click-to-detail panel (Phase 1.3).
            # Re-serialised from the parsed model — clean shape, no
            # comments or original ordering preserved.
            "yaml": _render_job_yaml(job),
        })

    # Resolve dep names to ids; drop deps that don't match a known job.
    edges: List[Dict[str, str]] = []
    for jd in jobs_data:
        for dep_name in jd["deps"]:
            target_id = name_to_id.get(dep_name)
            if target_id:
                edges.append({"from": target_id, "to": jd["id"]})

    by_severity_count: Dict[str, int] = defaultdict(int)
    for f in report.findings:
        by_severity_count[f.severity.value] += 1

    # Pipeline-level (orphan) findings — those whose `location` does not
    # resolve to a known job (global.*, pipeline.*, include, top-level).
    # The side-panel listing already shows these, but Slice 14a's closeout
    # noted they had no visual home in the diagram itself. The
    # `pipeline_globals` aggregate drives the banner that renders above
    # the DAG when count > 0.
    orphan_findings = [
        f for f in report.findings
        if _owning_job(f.location, known_job_names) is None
    ]
    orphan_sev_counts: Dict[str, int] = defaultdict(int)
    for f in orphan_findings:
        orphan_sev_counts[f.severity.value] += 1

    # Pinning-discipline aggregate across every job that declares an image.
    # Slice 14c — surfaced as a sidebar strip so the auditor can read the
    # repo's pin posture at a glance, not only by inspecting individual node
    # badges. Counts derive from `pin_status` already on each job dict so the
    # numbers can never drift from the badge colours.
    pin_counts: Dict[str, int] = defaultdict(int)
    for jd in jobs_data:
        if jd["pin_status"]:
            pin_counts[jd["pin_status"]] += 1

    return {
        "schema_version": 1,  # bump if breaking changes to the shape
        "meta": {
            "pipeline_name": report.pipeline_name,
            "platform": report.platform,
            "scanner_version": report.scanner_version,
            "scan_timestamp": report.scan_timestamp,
            # Reserved per audit-scope.md architecture commitment —
            # populated in Slice 16/17 when service-identity derivation
            # lands. Single-pipeline view leaves this null.
            "service_identity": None,
        },
        "score": {
            "overall": report.risk_score.overall,
            "grade": report.risk_score.grade,
            "by_category": {
                "pipeline_integrity": report.risk_score.pipeline_integrity,
                "identity_access": report.risk_score.identity_access,
                "runner_security": report.risk_score.runner_security,
                "artifact_handling": report.risk_score.artifact_handling,
                "deployment_governance": report.risk_score.deployment_governance,
                "supply_chain": report.risk_score.supply_chain,
            },
            "by_severity_count": dict(by_severity_count),
            "pin_discipline": {
                "digest": pin_counts.get("digest", 0),
                "tag": pin_counts.get("tag", 0),
                "mutable": pin_counts.get("mutable", 0),
            },
        },
        "pipeline_globals": {
            "count": len(orphan_findings),
            "by_severity": dict(orphan_sev_counts),
            "fingerprints": [f.fingerprint for f in orphan_findings],
        },
        "jobs": jobs_data,
        "edges": edges,
        # Side-panel content (Phase 1.2) — full finding list including
        # those not attached to a job (location=global, include).
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "message": f.name,
                "location": f.location,
                "display_location": _humanise_location(f.location),
                "owning_job": _owning_job(f.location, known_job_names),
                "evidence": f.evidence,
                "category": f.category.value,
                "fingerprint": f.fingerprint,
                "remediation": f.remediation,
            }
            for f in report.sorted_findings()
        ],
    }


# ---- Asset loading ---------------------------------------------------------


def _load_vendored(filename: str) -> str:
    """Read a vendored asset shipped under `_assets/`.

    Use importlib.resources so this works whether ciguard is installed
    from a wheel, an editable checkout, or a zipapp.
    """
    pkg = files("ciguard.reporter").joinpath("_assets").joinpath(filename)
    return pkg.read_text(encoding="utf-8")


# ---- HTML wrapper ---------------------------------------------------------


_VIEWER_CSS = """
:root {
  color-scheme: dark;
  --bg: #0a0a0a;
  --bg-card: #131316;
  --bg-card-hover: #1a1a1f;
  --bg-elevated: #18181c;
  --fg: #fafafa;
  --fg-muted: #a1a1aa;
  --fg-dim: #71717a;
  --border: #27272a;
  --border-strong: #3f3f46;
  --accent: #6366f1;
  --crit: #ef4444;
  --high: #f97316;
  --med:  #f59e0b;
  --low:  #22c55e;
  --info: #6366f1;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; height: 100%; overflow: hidden; }
body {
  background: var(--bg);
  color: var(--fg);
  font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", system-ui, sans-serif;
  font-size: 13px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
  display: flex;
  flex-direction: column;
  height: 100vh;
}

/* ---- Top header bar ---- */
.app-header {
  padding: 14px 22px;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
  background: var(--bg);
}
.brand { display: flex; align-items: baseline; gap: 14px; min-width: 0; }
.brand .product { font-size: 12px; color: var(--fg-dim); letter-spacing: 0.04em; text-transform: uppercase; }
.brand h1 { margin: 0; font-size: 17px; font-weight: 600; letter-spacing: -0.01em; }
.brand .platform-chip {
  font-size: 11px;
  padding: 2px 8px;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: 999px;
  color: var(--fg-muted);
  text-transform: lowercase;
}

/* Severity totals strip in the header */
.summary-strip { display: flex; align-items: center; gap: 8px; }
.sev-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  border-radius: 999px;
  font-size: 12px;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  font-variant-numeric: tabular-nums;
}
.sev-chip .dot { width: 6px; height: 6px; border-radius: 50%; }
.sev-chip.zero { color: var(--fg-dim); }
.sev-chip.zero .dot { background: var(--border-strong); }
.sev-chip.Critical .dot { background: var(--crit); }  .sev-chip.Critical { color: var(--crit); border-color: rgba(239,68,68,0.25); }
.sev-chip.High .dot { background: var(--high); }      .sev-chip.High     { color: var(--high); border-color: rgba(249,115,22,0.25); }
.sev-chip.Medium .dot { background: var(--med); }     .sev-chip.Medium   { color: var(--med);  border-color: rgba(245,158,11,0.25); }
.sev-chip.Low .dot { background: var(--low); }        .sev-chip.Low      { color: var(--low);  border-color: rgba(34,197,94,0.25); }
.sev-chip.Info .dot { background: var(--info); }      .sev-chip.Info     { color: var(--info); border-color: rgba(99,102,241,0.25); }

/* Pin-discipline strip — same shape as severity strip but keyed to image
   pinning categories (digest=good / tag=warning / mutable=danger). Renders
   below the severity strip when at least one job declares an image. */
.pin-strip { margin-top: 4px; }
.pin-strip .strip-label {
  font-size: 11px; color: var(--fg-dim);
  text-transform: uppercase; letter-spacing: 0.06em; margin-right: 4px;
}
.pin-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  border-radius: 999px;
  font-size: 12px;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  font-variant-numeric: tabular-nums;
}
.pin-chip .dot { width: 6px; height: 6px; border-radius: 50%; }
.pin-chip.zero { color: var(--fg-dim); }
.pin-chip.zero .dot { background: var(--border-strong); }
.pin-chip.digest .dot  { background: var(--low);  }  .pin-chip.digest  { color: var(--low);  border-color: rgba(34,197,94,0.25); }
.pin-chip.tag .dot     { background: var(--med);  }  .pin-chip.tag     { color: var(--med);  border-color: rgba(245,158,11,0.25); }
.pin-chip.mutable .dot { background: var(--crit); }  .pin-chip.mutable { color: var(--crit); border-color: rgba(239,68,68,0.25); }

/* Score block on far right */
.score-block { display: flex; align-items: center; gap: 12px; }
.score-block .grade-pill {
  display: inline-flex; align-items: center; justify-content: center;
  width: 38px; height: 38px; border-radius: 8px;
  font-size: 18px; font-weight: 700;
  background: linear-gradient(135deg, rgba(99,102,241,0.18), rgba(99,102,241,0.04));
  border: 1px solid rgba(99,102,241,0.4);
}
.score-block .grade-pill.A { background: linear-gradient(135deg, rgba(34,197,94,0.18), rgba(34,197,94,0.04)); border-color: rgba(34,197,94,0.4); color: var(--low); }
.score-block .grade-pill.B { background: linear-gradient(135deg, rgba(34,197,94,0.12), rgba(34,197,94,0.02)); border-color: rgba(34,197,94,0.3); color: var(--low); }
.score-block .grade-pill.C { background: linear-gradient(135deg, rgba(245,158,11,0.18), rgba(245,158,11,0.04)); border-color: rgba(245,158,11,0.4); color: var(--med); }
.score-block .grade-pill.D { background: linear-gradient(135deg, rgba(249,115,22,0.18), rgba(249,115,22,0.04)); border-color: rgba(249,115,22,0.4); color: var(--high); }
.score-block .grade-pill.F { background: linear-gradient(135deg, rgba(239,68,68,0.18), rgba(239,68,68,0.04)); border-color: rgba(239,68,68,0.4); color: var(--crit); }
.score-block .score-num { font-size: 20px; font-weight: 700; font-variant-numeric: tabular-nums; }
.score-block .score-num small { color: var(--fg-dim); font-size: 12px; font-weight: 400; margin-left: 2px; }

/* ---- Main split layout ---- */
main { display: flex; flex: 1; min-height: 0; }
#graph-container {
  flex: 1;
  overflow: auto;
  background:
    radial-gradient(circle at 18% -10%, rgba(99,102,241,0.07) 0%, transparent 60%),
    radial-gradient(circle at 80% 110%, rgba(239,68,68,0.04) 0%, transparent 60%),
    var(--bg);
  position: relative;
}
#graph-container svg { display: block; }

/* ---- Stage swimlanes ---- */
.swimlane-band rect { fill: rgba(255,255,255,0.012); stroke: var(--border); stroke-dasharray: 2 4; }
.swimlane-label {
  font-size: 11px;
  font-weight: 600;
  fill: var(--fg-dim);
  text-transform: uppercase;
  letter-spacing: 0.08em;
}

/* ---- Job nodes ---- */
.node { cursor: pointer; }
.node rect.card {
  fill: var(--bg-card);
  stroke: var(--border-strong);
  stroke-width: 1.5;
  rx: 8; ry: 8;
  transition: filter 120ms;
}
.node:hover rect.card { fill: var(--bg-card-hover); filter: drop-shadow(0 4px 16px rgba(99,102,241,0.18)); }
.node.selected rect.card { stroke-width: 2.5; filter: drop-shadow(0 0 0 2px rgba(99,102,241,0.35)); }

/* Severity-coloured top-stripe per node */
.node rect.sev-stripe { rx: 8; ry: 8; }
.node text.title {
  fill: var(--fg); font-size: 13px; font-weight: 600;
  pointer-events: none;
}
.node text.subtitle {
  fill: var(--fg-muted); font-size: 11px;
  pointer-events: none;
  font-variant-numeric: tabular-nums;
}
.node text.image-text {
  fill: var(--fg-dim); font-size: 10.5px;
  font-family: "SF Mono", "Menlo", "Consolas", ui-monospace, monospace;
  pointer-events: none;
}

/* Pin-status badge inside a node */
.pin-badge { font-size: 9.5px; font-weight: 600; }
.pin-badge.digest  { fill: var(--low); }
.pin-badge.tag     { fill: var(--med); }
.pin-badge.mutable { fill: var(--crit); }

/* Production target badge */
.prod-flag rect { fill: rgba(239,68,68,0.16); stroke: rgba(239,68,68,0.4); rx: 4; ry: 4; }
.prod-flag text { fill: var(--crit); font-size: 9.5px; font-weight: 700; letter-spacing: 0.06em; }

/* Manual-approval gate icon */
.gate-flag rect { fill: rgba(99,102,241,0.16); stroke: rgba(99,102,241,0.4); rx: 4; ry: 4; }
.gate-flag text { fill: var(--info); font-size: 9.5px; font-weight: 600; letter-spacing: 0.04em; }

/* Severity finding badges */
.sev-badge { font-size: 10px; font-weight: 700; }
.sev-badge text { fill: #0a0a0a; pointer-events: none; }
.sev-badge rect { rx: 3; ry: 3; }
.sev-badge.Critical rect { fill: var(--crit); }
.sev-badge.High rect     { fill: var(--high); }
.sev-badge.Medium rect   { fill: var(--med); }
.sev-badge.Low rect      { fill: var(--low); }
.sev-badge.Info rect     { fill: var(--info); }

/* ---- Edges ---- */
.edge {
  stroke: var(--border-strong);
  stroke-width: 1.5;
  fill: none;
  marker-end: url(#arrowhead);
  transition: stroke 120ms;
}
.edge.dim { stroke: var(--border); opacity: 0.35; }
.edge.highlight { stroke: var(--accent); stroke-width: 2; }

/* ---- Right side panel ---- */
#side-panel {
  width: 380px;
  border-left: 1px solid var(--border);
  background: var(--bg);
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
}
.panel-header {
  padding: 14px 16px 10px;
  border-bottom: 1px solid var(--border);
}
.panel-header h2 { margin: 0; font-size: 13px; font-weight: 600; }
.panel-header .panel-sub { color: var(--fg-dim); font-size: 11px; margin-top: 2px; }
.panel-filter {
  display: flex; gap: 4px; padding: 8px 16px;
  border-bottom: 1px solid var(--border);
  flex-wrap: wrap;
}
.filter-btn {
  font-size: 11px;
  padding: 4px 10px;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: 999px;
  color: var(--fg-muted);
  cursor: pointer;
  font-family: inherit;
  transition: all 120ms;
}
.filter-btn:hover { color: var(--fg); background: var(--bg-card-hover); }
.filter-btn.active { color: var(--fg); background: var(--bg-card); border-color: var(--border-strong); }

.globals-banner {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 10px 24px;
  margin: 0;
  background: var(--bg-elevated);
  border-bottom: 1px solid var(--border);
  border-left: 3px solid var(--accent);
  font-size: 12px;
  flex-wrap: wrap;
}
.globals-banner .globals-text { display: flex; flex-direction: column; min-width: 0; }
.globals-banner .globals-text strong { color: var(--fg); font-size: 13px; }
.globals-banner .globals-sub { color: var(--fg-dim); font-size: 11px; margin-top: 2px; }
.globals-banner .globals-chips { display: flex; gap: 6px; flex-wrap: wrap; }
.globals-banner .globals-chip {
  font-size: 10px; font-weight: 700;
  padding: 3px 8px;
  border-radius: 999px;
  letter-spacing: 0.04em;
  color: #0a0a0a;
}
.globals-banner .globals-chip.Critical { background: var(--crit); }
.globals-banner .globals-chip.High     { background: var(--high); }
.globals-banner .globals-chip.Medium   { background: var(--med); }
.globals-banner .globals-chip.Low      { background: var(--low); }
.globals-banner .globals-chip.Info     { background: var(--info); }
.globals-banner .globals-show {
  margin-left: auto;
  font-family: inherit;
  font-size: 11px;
  padding: 5px 12px;
  background: var(--bg-card);
  border: 1px solid var(--border-strong);
  border-radius: 6px;
  color: var(--fg);
  cursor: pointer;
  transition: background 120ms;
}
.globals-banner .globals-show:hover { background: var(--bg-card-hover); }
.globals-banner.dimmed { opacity: 0.55; }
.filter-btn[data-origin="pipeline"] { color: var(--fg); }
.filter-btn[data-origin="pipeline"].active { background: var(--accent); color: #0a0a0a; border-color: var(--accent); }

.findings-list {
  overflow: auto;
  flex: 1;
  padding: 4px 0;
}
.finding-item {
  padding: 10px 16px;
  border-bottom: 1px solid var(--border);
  cursor: pointer;
  transition: background 120ms;
}
.finding-item:hover { background: var(--bg-card); }
.finding-item.selected { background: var(--bg-card-hover); border-left: 3px solid var(--accent); padding-left: 13px; }
.finding-item .row1 { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
.finding-item .sev-pill {
  font-size: 10px; font-weight: 700;
  padding: 2px 7px;
  border-radius: 3px;
  letter-spacing: 0.04em;
  color: #0a0a0a;
}
.finding-item .sev-pill.Critical { background: var(--crit); }
.finding-item .sev-pill.High     { background: var(--high); }
.finding-item .sev-pill.Medium   { background: var(--med); }
.finding-item .sev-pill.Low      { background: var(--low); }
.finding-item .sev-pill.Info     { background: var(--info); }
.finding-item .rule-id { color: var(--fg-dim); font-size: 11px; font-family: "SF Mono", ui-monospace, monospace; }
.finding-item .message { font-weight: 500; color: var(--fg); margin-bottom: 3px; }
.finding-item .location {
  color: var(--fg-muted); font-size: 11px;
  font-family: "SF Mono", ui-monospace, monospace;
}
.findings-empty {
  padding: 24px 16px; color: var(--fg-dim); font-size: 12px; text-align: center;
}

/* ---- Footer legend ---- */
.legend {
  border-top: 1px solid var(--border);
  padding: 8px 22px;
  display: flex;
  flex-wrap: wrap;
  gap: 18px;
  font-size: 11px;
  color: var(--fg-muted);
  background: var(--bg);
}
.legend-item { display: inline-flex; align-items: center; gap: 6px; }
.legend-swatch { display: inline-block; width: 12px; height: 12px; border-radius: 3px; }
.legend-swatch.line { width: 16px; height: 0; border-top: 2px solid var(--border-strong); border-radius: 0; }

/* ---- Tooltip (kept for hover-detail in DAG) ---- */
.tooltip {
  position: absolute;
  background: var(--bg-elevated);
  border: 1px solid var(--border-strong);
  border-radius: 6px;
  padding: 8px 12px;
  font-size: 11.5px;
  pointer-events: none;
  max-width: 320px;
  z-index: 100;
  opacity: 0;
  transition: opacity 100ms;
  box-shadow: 0 4px 16px rgba(0,0,0,0.4);
}
.tooltip strong { display: block; margin-bottom: 4px; font-size: 12.5px; }
.tooltip .tip-row { color: var(--fg-muted); }
.tooltip .tip-row code { font-family: "SF Mono", ui-monospace, monospace; font-size: 11px; color: var(--fg); }

/* dimmed nodes when filtering */
.node.dim { opacity: 0.25; }

/* ---- Search input ---- */
.panel-search {
  padding: 8px 16px;
  border-bottom: 1px solid var(--border);
}
.panel-search input {
  width: 100%;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 6px 10px;
  color: var(--fg);
  font-size: 12px;
  font-family: inherit;
  outline: none;
}
.panel-search input:focus { border-color: var(--accent); }
.panel-search input::placeholder { color: var(--fg-dim); }

/* ---- Job-detail panel (click a node to enter) ---- */
#job-detail { display: none; flex-direction: column; flex: 1; overflow: hidden; }
#job-detail.active { display: flex; }
#findings-view.hidden { display: none; }

.detail-header {
  padding: 14px 16px 10px;
  border-bottom: 1px solid var(--border);
}
.detail-header .back-btn {
  background: none;
  border: none;
  color: var(--fg-dim);
  font-size: 11px;
  font-family: inherit;
  cursor: pointer;
  padding: 0;
  margin-bottom: 8px;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.detail-header .back-btn:hover { color: var(--fg); }
.detail-header h2 {
  margin: 0; font-size: 14px; font-weight: 600;
  font-family: "SF Mono", "Menlo", "Consolas", ui-monospace, monospace;
}
.detail-header .detail-sub { color: var(--fg-dim); font-size: 11px; margin-top: 4px; }

.gates-summary {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px 12px;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
}
.gate-row { display: flex; flex-direction: column; gap: 2px; }
.gate-row .label { color: var(--fg-dim); font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; }
.gate-row .value { color: var(--fg); font-size: 12px; }
.gate-row .value.danger  { color: var(--crit); }
.gate-row .value.warn    { color: var(--med); }
.gate-row .value.success { color: var(--low); }
.gate-row .value.muted   { color: var(--fg-dim); }
.gate-row .value code {
  font-family: "SF Mono", ui-monospace, monospace;
  font-size: 11.5px;
}

.detail-scroll { overflow: auto; flex: 1; }

.yaml-section {
  border-bottom: 1px solid var(--border);
  padding: 12px 16px;
}
.yaml-section .section-label {
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--fg-dim);
  margin-bottom: 6px;
}
.yaml-block {
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 10px 12px;
  font-family: "SF Mono", "Menlo", "Consolas", ui-monospace, monospace;
  font-size: 11.5px;
  line-height: 1.55;
  white-space: pre;
  overflow-x: auto;
  color: var(--fg);
}

.findings-on-job { padding: 0 0 12px; }
.finding-detail {
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
}
.finding-detail .row1 { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
.finding-detail .sev-pill {
  font-size: 10px; font-weight: 700;
  padding: 2px 7px; border-radius: 3px;
  letter-spacing: 0.04em; color: #0a0a0a;
}
.finding-detail .sev-pill.Critical { background: var(--crit); }
.finding-detail .sev-pill.High     { background: var(--high); }
.finding-detail .sev-pill.Medium   { background: var(--med); }
.finding-detail .sev-pill.Low      { background: var(--low); }
.finding-detail .sev-pill.Info     { background: var(--info); }
.finding-detail .rule-id {
  color: var(--fg-dim); font-size: 11px;
  font-family: "SF Mono", ui-monospace, monospace;
}
.finding-detail .message { font-weight: 500; color: var(--fg); margin-bottom: 6px; }
.finding-detail .evidence-block {
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 6px 9px;
  font-family: "SF Mono", ui-monospace, monospace;
  font-size: 11px;
  color: var(--fg-muted);
  margin: 6px 0;
  white-space: pre-wrap;
  word-break: break-word;
}
.finding-detail .remediation-label {
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--low);
  margin-top: 8px;
  margin-bottom: 4px;
}
.finding-detail .remediation {
  color: var(--fg-muted);
  font-size: 12px;
  line-height: 1.5;
}

/* ---- Diff-mode UI ---- */
.diff-status {
  display: inline-block;
  font-size: 9.5px;
  font-weight: 700;
  padding: 1px 6px;
  border-radius: 3px;
  letter-spacing: 0.04em;
  margin-left: 6px;
}
.diff-status.NEW       { background: var(--crit); color: #0a0a0a; }
.diff-status.RESOLVED  { background: var(--low); color: #0a0a0a; }
.diff-status.UNCHANGED { background: var(--bg-elevated); color: var(--fg-dim); border: 1px solid var(--border); }
.compare-btn {
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  color: var(--fg-muted);
  font-size: 11px;
  padding: 5px 12px;
  border-radius: 6px;
  cursor: pointer;
  font-family: inherit;
  transition: all 120ms;
}
.compare-btn:hover { color: var(--fg); border-color: var(--border-strong); }
.compare-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }
.diff-banner {
  display: none;
  padding: 8px 22px;
  background: var(--bg-elevated);
  border-bottom: 1px solid var(--border);
  font-size: 12px;
  color: var(--fg-muted);
}
.diff-banner.visible { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
.diff-banner .diff-pill {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 3px 10px; border-radius: 999px; font-size: 11.5px;
  font-variant-numeric: tabular-nums;
}
.diff-banner .diff-pill.added    { background: rgba(239,68,68,0.15); color: var(--crit); border: 1px solid rgba(239,68,68,0.3); }
.diff-banner .diff-pill.resolved { background: rgba(34,197,94,0.15); color: var(--low);  border: 1px solid rgba(34,197,94,0.3); }
.diff-banner .diff-pill.unchanged { background: var(--bg-card); color: var(--fg-dim); border: 1px solid var(--border); }
.diff-banner button {
  background: none; border: none; color: var(--fg-dim);
  cursor: pointer; font-family: inherit; font-size: 11px;
  margin-left: auto;
}
.diff-banner button:hover { color: var(--fg); }
/* Node border tweak in diff mode: nodes with new findings get a thicker red ring */
.node.has-new rect.card { stroke: var(--crit); stroke-width: 2.5; }
.node.fully-resolved rect.card { stroke: var(--low); stroke-width: 2.5; }

/* ---- Keyboard accessibility ---- */
.node:focus rect.card,
.finding-item:focus,
.finding-item:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}
.skip-link {
  position: absolute;
  left: -10000px;
  top: -10000px;
}
.skip-link:focus {
  position: fixed;
  left: 12px; top: 12px;
  background: var(--accent);
  color: #fff;
  padding: 8px 14px;
  border-radius: 6px;
  z-index: 1000;
  text-decoration: none;
  font-size: 12px;
}

/* Smooth motion (respects prefers-reduced-motion) */
@media (prefers-reduced-motion: no-preference) {
  .node rect.card { transition: stroke 120ms, stroke-width 120ms, filter 160ms; }
  .edge { transition: stroke 160ms, opacity 160ms; }
  .finding-item, .filter-btn, .compare-btn { transition: background 120ms, color 120ms, border-color 120ms; }
}

/* ---- Print mode (clean PDF export) ---- */
@media print {
  :root {
    color-scheme: light;
    --bg: #ffffff;
    --bg-card: #ffffff;
    --bg-card-hover: #ffffff;
    --bg-elevated: #f4f4f5;
    --fg: #18181b;
    --fg-muted: #52525b;
    --fg-dim: #71717a;
    --border: #d4d4d8;
    --border-strong: #a1a1aa;
  }
  html, body { overflow: visible !important; height: auto !important; background: #fff; color: #000; }
  .panel-search, .panel-filter, .compare-btn, .skip-link, .diff-banner button { display: none !important; }
  .app-header { padding: 12px 18px; border-bottom: 2px solid #000; page-break-after: avoid; }
  .legend { page-break-before: avoid; }
  main { display: block !important; height: auto !important; }
  #graph-container { overflow: visible !important; height: auto !important; background: #fff !important; }
  #graph-container svg { background: #fff; }
  #side-panel {
    width: 100% !important;
    border-left: none !important;
    border-top: 1px solid #d4d4d8;
    page-break-before: always;
  }
  #findings-view, #job-detail {
    display: block !important;
  }
  #findings-view.hidden { display: block !important; }
  .findings-list, .detail-scroll { overflow: visible !important; max-height: none !important; }
  .finding-item { page-break-inside: avoid; }
  .node rect.card { fill: #fff !important; stroke: #71717a; }
  .node:hover rect.card { filter: none !important; }
  .swimlane-band rect { fill: #fafafa !important; stroke: #d4d4d8 !important; }
  .tooltip { display: none !important; }
  /* Print-only banner so the printed deliverable is self-explanatory */
  .print-banner {
    display: block;
    padding: 6px 18px;
    border-bottom: 1px solid #d4d4d8;
    font-size: 11px;
    color: #52525b;
    page-break-after: avoid;
  }
}
.print-banner { display: none; }
"""

_VIEWER_JS = r"""
(() => {
  const data = JSON.parse(document.getElementById('ciguard-data').textContent);

  const SEV = { Critical:'#ef4444', High:'#f97316', Medium:'#f59e0b', Low:'#22c55e', Info:'#6366f1' };
  const SEV_ORDER = ['Critical','High','Medium','Low','Info'];

  // ---- Layered layout: column = topological depth ----
  const incoming = new Map(data.jobs.map(j => [j.id, []]));
  const outgoing = new Map(data.jobs.map(j => [j.id, []]));
  for (const e of data.edges) {
    incoming.get(e.to)?.push(e.from);
    outgoing.get(e.from)?.push(e.to);
  }
  const depth = new Map();
  const seeds = data.jobs.filter(j => incoming.get(j.id).length === 0).map(j => j.id);
  const q = [...seeds];
  for (const id of q) depth.set(id, 0);
  let safety = data.jobs.length * 4;
  while (q.length && safety-- > 0) {
    const id = q.shift();
    for (const child of outgoing.get(id) || []) {
      const cand = (depth.get(id) || 0) + 1;
      if (cand > (depth.get(child) || -1)) { depth.set(child, cand); q.push(child); }
    }
  }
  for (const j of data.jobs) if (!depth.has(j.id)) depth.set(j.id, 0);

  // Group by column, then optionally by stage within a column
  const columns = {};
  for (const j of data.jobs) {
    const d = depth.get(j.id);
    if (!columns[d]) columns[d] = [];
    columns[d].push(j);
  }
  const maxDepth = Math.max(0, ...Object.keys(columns).map(Number));

  // ---- Layout constants ----
  const NODE_W  = 240;
  const NODE_H  = 110;
  const COL_GAP = 80;
  const ROW_GAP = 22;
  const PAD_X   = 48;
  const PAD_TOP = 56;   // room above first node for swimlane labels

  // Compute swimlane bands by column. Each column gets a band whose
  // label is the most-common stage in that column (or "—").
  const positioned = [];
  const columnMeta = [];
  for (let d = 0; d <= maxDepth; d++) {
    const col = columns[d] || [];
    // Dominant stage label
    const stageCounts = {};
    for (const j of col) {
      const s = j.stage || '—';
      stageCounts[s] = (stageCounts[s] || 0) + 1;
    }
    const dominantStage = Object.entries(stageCounts).sort((a,b) => b[1]-a[1])[0]?.[0] || '—';
    columnMeta.push({ depth: d, label: dominantStage, count: col.length });
    col.forEach((j, idx) => {
      positioned.push({
        ...j,
        x: PAD_X + d * (NODE_W + COL_GAP),
        y: PAD_TOP + idx * (NODE_H + ROW_GAP),
      });
    });
  }
  const tallestCol = Math.max(1, ...Object.values(columns).map(c => c.length));
  const svgW = PAD_X * 2 + (maxDepth + 1) * NODE_W + maxDepth * COL_GAP;
  const svgH = PAD_TOP + tallestCol * (NODE_H + ROW_GAP) + 32;

  // ---- SVG ----
  const svg = d3.select('#graph-container').append('svg')
    .attr('width', svgW).attr('height', svgH);

  // Arrowhead
  svg.append('defs').append('marker')
    .attr('id', 'arrowhead').attr('viewBox', '0 -5 10 10')
    .attr('refX', 8).attr('refY', 0).attr('markerWidth', 6).attr('markerHeight', 6)
    .attr('orient', 'auto').append('path').attr('d', 'M0,-5L10,0L0,5').attr('fill', '#52525b');

  // ---- Swimlane bands per column ----
  const lanes = svg.append('g').attr('class', 'swimlane-band');
  columnMeta.forEach(cm => {
    if (!cm.count) return;
    const x = PAD_X + cm.depth * (NODE_W + COL_GAP) - 16;
    const w = NODE_W + 32;
    const h = svgH - 24;
    lanes.append('rect').attr('x', x).attr('y', 12).attr('width', w).attr('height', h);
    lanes.append('text').attr('class', 'swimlane-label')
      .attr('x', x + 12).attr('y', 32).text(cm.label);
  });

  // ---- Edges ----
  const idToPos = new Map(positioned.map(p => [p.id, p]));
  const edgeSel = svg.append('g').attr('class', 'edges').selectAll('path')
    .data(data.edges.filter(e => idToPos.has(e.from) && idToPos.has(e.to)))
    .enter().append('path').attr('class', 'edge')
    .attr('d', e => {
      const s = idToPos.get(e.from), t = idToPos.get(e.to);
      const x1 = s.x + NODE_W, y1 = s.y + NODE_H / 2;
      const x2 = t.x,          y2 = t.y + NODE_H / 2;
      const mx = (x1 + x2) / 2;
      return `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`;
    });

  // ---- Tooltip ----
  const tooltip = d3.select('body').append('div').attr('class', 'tooltip');

  // ---- Nodes ----
  const nodeSel = svg.append('g').attr('class', 'nodes')
    .selectAll('g').data(positioned).enter().append('g')
    .attr('class', 'node').attr('data-id', d => d.id)
    .attr('transform', d => `translate(${d.x},${d.y})`);

  // Severity stripe (top 4px of card)
  nodeSel.append('rect').attr('class', 'sev-stripe')
    .attr('x', 0).attr('y', 0).attr('width', NODE_W).attr('height', 6)
    .attr('fill', d => d.highest_severity ? SEV[d.highest_severity] : '#3f3f46');

  // Card body
  nodeSel.append('rect').attr('class', 'card')
    .attr('x', 0).attr('y', 4).attr('width', NODE_W).attr('height', NODE_H - 4);

  // Title (job name)
  nodeSel.append('text').attr('class', 'title')
    .attr('x', 14).attr('y', 26)
    .text(d => d.name.length > 28 ? d.name.slice(0, 26) + '…' : d.name);

  // Subtitle: stage · environment
  nodeSel.append('text').attr('class', 'subtitle')
    .attr('x', 14).attr('y', 44)
    .text(d => {
      const parts = [];
      if (d.stage && d.stage !== '—') parts.push(d.stage);
      if (d.environment) parts.push(d.environment + (d.targets_production ? ' · prod' : ''));
      return parts.join(' · ');
    });

  // Image with pin status badge
  nodeSel.filter(d => d.image).append('text').attr('class', 'image-text')
    .attr('x', 14).attr('y', 62)
    .text(d => {
      const max = 30;
      return d.image.length > max ? d.image.slice(0, max - 1) + '…' : d.image;
    });
  nodeSel.filter(d => d.image && d.pin_status).append('text')
    .attr('class', d => `pin-badge ${d.pin_status}`)
    .attr('x', NODE_W - 14).attr('y', 62).attr('text-anchor', 'end')
    .text(d => ({ digest: '✓ DIGEST', tag: 'TAG', mutable: '⚠ MUTABLE' }[d.pin_status] || ''));

  // Severity-count badges (chip-row at bottom)
  nodeSel.each(function(d) {
    const counts = d.findings_by_severity || {};
    const filtered = SEV_ORDER.filter(s => counts[s] > 0);
    const g = d3.select(this).append('g').attr('class', 'sev-badges');
    let xOff = 14;
    filtered.forEach(s => {
      const txt = `${counts[s]} ${s[0]}`;
      const w = txt.length * 6.5 + 10;
      const bg = g.append('g').attr('class', `sev-badge ${s}`).attr('transform', `translate(${xOff},${NODE_H - 26})`);
      bg.append('rect').attr('width', w).attr('height', 16);
      bg.append('text').attr('x', w/2).attr('y', 12).attr('text-anchor', 'middle').text(txt);
      xOff += w + 4;
    });
    if (!filtered.length) {
      g.append('text').attr('class', 'subtitle').attr('x', 14).attr('y', NODE_H - 14).text('clean');
    }
  });

  // Right-side flag column: prod + manual-gate
  nodeSel.each(function(d) {
    const flags = d3.select(this).append('g').attr('class', 'flags').attr('transform', `translate(${NODE_W - 12},${NODE_H - 28})`);
    let yOff = 0;
    if (d.targets_production) {
      const g = flags.append('g').attr('class', 'prod-flag').attr('transform', `translate(0,${yOff})`);
      g.append('rect').attr('x', -54).attr('y', 0).attr('width', 54).attr('height', 16);
      g.append('text').attr('x', -27).attr('y', 12).attr('text-anchor', 'middle').text('PROD');
      yOff -= 20;
    }
    if (d.has_manual_gate) {
      const g = flags.append('g').attr('class', 'gate-flag').attr('transform', `translate(0,${yOff})`);
      g.append('rect').attr('x', -54).attr('y', 0).attr('width', 54).attr('height', 16);
      g.append('text').attr('x', -27).attr('y', 12).attr('text-anchor', 'middle').text('MANUAL');
    }
  });

  // ---- Accessibility: nodes are keyboard-reachable buttons ----
  nodeSel
    .attr('role', 'button')
    .attr('tabindex', 0)
    .attr('aria-label', d => {
      const f = d.findings.length;
      const sev = d.highest_severity ? ` worst severity ${d.highest_severity},` : '';
      const env = d.environment ? ` environment ${d.environment},` : '';
      const prod = d.targets_production ? ' deploys to production,' : '';
      return `Job ${d.name},${env}${prod}${sev} ${f} finding${f===1?'':'s'}.`;
    });

  // Hover tooltip + click-select wiring
  nodeSel
    .on('mouseenter', (event, d) => {
      const lines = [];
      if (d.stage && d.stage !== '—') lines.push(`<div class="tip-row">stage <code>${escapeHtml(d.stage)}</code></div>`);
      if (d.image) lines.push(`<div class="tip-row">image <code>${escapeHtml(d.image)}</code></div>`);
      if (d.environment) lines.push(`<div class="tip-row">environment <code>${escapeHtml(d.environment)}</code></div>`);
      if (d.has_manual_gate) lines.push(`<div class="tip-row">manual approval gate</div>`);
      const f = d.findings.length;
      if (f) lines.push(`<div class="tip-row" style="color:${SEV[d.highest_severity]}">${f} finding${f===1?'':'s'} — click to filter</div>`);
      else lines.push(`<div class="tip-row">no findings</div>`);
      tooltip.html(`<strong>${escapeHtml(d.name)}</strong>${lines.join('')}`)
        .style('left', (event.pageX + 14) + 'px')
        .style('top', (event.pageY + 12) + 'px')
        .style('opacity', 1);
    })
    .on('mousemove', (event) => {
      tooltip.style('left', (event.pageX + 14) + 'px').style('top', (event.pageY + 12) + 'px');
    })
    .on('mouseleave', () => tooltip.style('opacity', 0))
    .on('click', (event, d) => selectJob(d.id))
    .on('keydown', (event, d) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        selectJob(d.id);
      } else if (event.key === 'Escape') {
        deselectJob();
      }
    });

  // ---- Side-panel state machine ----
  // Two views: "findings" (default — global list with filters + search)
  // and "detail" (when a job is clicked — shows YAML + per-finding remediation).
  const findingsView = document.getElementById('findings-view');
  const detailView = document.getElementById('job-detail');
  const findingsList = d3.select('#findings-list');
  let activeSeverity = 'all';
  let activeJob = null;
  let searchQuery = '';
  // 'all' | 'pipeline' — when 'pipeline', filter to orphan findings
  // (those without an owning_job). Set by the globals-banner Show
  // button + the Pipeline-level filter pill.
  let activeOrigin = 'all';

  function setView(view) {
    if (view === 'detail') {
      findingsView.classList.add('hidden');
      detailView.classList.add('active');
    } else {
      findingsView.classList.remove('hidden');
      detailView.classList.remove('active');
    }
  }

  function matchSearch(f, q) {
    if (!q) return true;
    const hay = `${f.rule_id} ${f.message} ${f.location}`.toLowerCase();
    return hay.includes(q.toLowerCase());
  }

  function renderFindings() {
    findingsList.html('');
    const items = data.findings.filter(f => {
      if (activeSeverity !== 'all' && f.severity !== activeSeverity) return false;
      if (activeOrigin === 'pipeline' && f.owning_job !== null) return false;
      if (!matchSearch(f, searchQuery)) return false;
      return true;
    });
    if (!items.length) {
      findingsList.append('div').attr('class', 'findings-empty')
        .text(searchQuery
          ? `No findings match "${searchQuery}".`
          : 'No findings match the current filter.');
      d3.select('#findings-count').text(`0 of ${data.findings.length}`);
      return;
    }
    items.forEach(f => {
      const it = findingsList.append('div').attr('class', 'finding-item').attr('data-fp', f.fingerprint);
      const r1 = it.append('div').attr('class', 'row1');
      r1.append('span').attr('class', `sev-pill ${f.severity}`).text(f.severity);
      r1.append('span').attr('class', 'rule-id').text(f.rule_id);
      it.append('div').attr('class', 'message').text(f.message);
      it.append('div').attr('class', 'location').text(f.location);
      it.on('click', () => {
        const target = data.jobs.find(j => f.location === j.name || f.location.startsWith(j.name + ':'));
        if (target) selectJob(target.id);
        d3.selectAll('.finding-item').classed('selected', false);
        it.classed('selected', true);
      });
    });
    d3.select('#findings-count').text(`${items.length} of ${data.findings.length}`);
  }

  function renderJobDetail(jobId) {
    const job = data.jobs.find(j => j.id === jobId);
    if (!job) return;

    document.getElementById('detail-job-name').textContent = job.name;
    const subParts = [];
    if (job.stage && job.stage !== '—') subParts.push(`stage: ${job.stage}`);
    if (job.environment) subParts.push(`env: ${job.environment}`);
    document.getElementById('detail-job-sub').textContent = subParts.join(' · ') || ' ';

    // Gates summary grid
    const gates = document.getElementById('gates-summary');
    gates.innerHTML = '';
    function addGate(label, value, klass) {
      const row = document.createElement('div');
      row.className = 'gate-row';
      const lab = document.createElement('div');
      lab.className = 'label';
      lab.textContent = label;
      const val = document.createElement('div');
      val.className = `value ${klass || ''}`;
      val.innerHTML = value;
      row.append(lab, val);
      gates.append(row);
    }
    if (job.image) {
      const pinClass = job.pin_status === 'mutable' ? 'danger'
        : job.pin_status === 'tag' ? 'warn'
        : job.pin_status === 'digest' ? 'success'
        : 'muted';
      const pinLabel = job.pin_status === 'mutable' ? '⚠ MUTABLE'
        : job.pin_status === 'tag' ? 'TAG'
        : job.pin_status === 'digest' ? '✓ DIGEST'
        : '—';
      addGate('Image', `<code>${escapeHtml(job.image)}</code> · ${pinLabel}`, pinClass);
    } else {
      addGate('Image', '—', 'muted');
    }
    addGate('Production target', job.targets_production ? '⚠ deploys to prod' : 'no', job.targets_production ? 'danger' : 'muted');
    addGate('Approval gate', job.has_manual_gate ? '✓ manual gate set' : 'no manual gate', job.has_manual_gate ? 'success' : 'muted');
    addGate('Highest finding', job.highest_severity || 'clean', job.highest_severity ? 'danger' : 'success');

    // YAML block
    document.getElementById('yaml-block').textContent = job.yaml || `${job.name}: {}`;

    // Per-finding cards with remediation expanded
    const findingsBox = document.getElementById('findings-on-job');
    findingsBox.innerHTML = '';
    if (!job.findings.length) {
      const empty = document.createElement('div');
      empty.className = 'findings-empty';
      empty.textContent = 'No findings raised against this job.';
      findingsBox.append(empty);
    } else {
      // Side-panel data carries remediation; per-job findings only carry
      // the slim shape. Cross-look up by fingerprint for the full record.
      const fullByFp = new Map(data.findings.map(f => [f.fingerprint, f]));
      job.findings.forEach(jf => {
        const full = fullByFp.get(jf.fingerprint) || jf;
        const card = document.createElement('div');
        card.className = 'finding-detail';
        card.innerHTML = `
          <div class="row1">
            <span class="sev-pill ${full.severity}">${full.severity}</span>
            <span class="rule-id">${escapeHtml(full.rule_id)}</span>
          </div>
          <div class="message">${escapeHtml(full.message)}</div>
          <div class="evidence-block">${escapeHtml(full.evidence)}</div>
          <div class="remediation-label">Remediation</div>
          <div class="remediation">${escapeHtml(full.remediation || '(no remediation text recorded)')}</div>
        `;
        findingsBox.append(card);
      });
    }
  }

  function selectJob(id) {
    if (activeJob === id) {
      // Toggle off — return to global findings view
      deselectJob();
      return;
    }
    activeJob = id;
    d3.selectAll('.node').classed('selected', d => d.id === activeJob);
    const neighbours = new Set([activeJob]);
    data.edges.forEach(e => {
      if (e.from === activeJob) neighbours.add(e.to);
      if (e.to === activeJob) neighbours.add(e.from);
    });
    d3.selectAll('.node').classed('dim', d => !neighbours.has(d.id));
    d3.selectAll('.edge').classed('dim', e => !(neighbours.has(e.from) && neighbours.has(e.to)))
      .classed('highlight', e => e.from === activeJob || e.to === activeJob);
    renderJobDetail(activeJob);
    setView('detail');
  }

  function deselectJob() {
    activeJob = null;
    d3.selectAll('.node').classed('selected', false).classed('dim', false);
    d3.selectAll('.edge').classed('dim', false).classed('highlight', false);
    setView('findings');
  }

  // Back button
  document.getElementById('back-to-findings').addEventListener('click', deselectJob);

  // Severity / origin filter buttons. Severity buttons are mutually
  // exclusive within their group; the Pipeline-level button toggles
  // the orphan-only origin filter independently and composes with
  // any severity selection.
  document.querySelectorAll('.filter-btn[data-sev]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn[data-sev]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeSeverity = btn.dataset.sev;
      renderFindings();
    });
  });
  const globalsFilterBtn = document.getElementById('filter-globals');
  if (globalsFilterBtn) {
    globalsFilterBtn.addEventListener('click', () => {
      activeOrigin = (activeOrigin === 'pipeline') ? 'all' : 'pipeline';
      globalsFilterBtn.classList.toggle('active', activeOrigin === 'pipeline');
      const banner = document.getElementById('globals-banner');
      if (banner) banner.classList.toggle('dimmed', activeOrigin === 'pipeline');
      renderFindings();
    });
  }
  // Globals banner "Show in panel" — same toggle, different entry point.
  const globalsShowBtn = document.getElementById('globals-show');
  if (globalsShowBtn) {
    globalsShowBtn.addEventListener('click', () => {
      if (globalsFilterBtn) globalsFilterBtn.click();
      // Scroll the side panel into view in case it's off-screen.
      const sidePanel = document.getElementById('side-panel');
      if (sidePanel && sidePanel.scrollIntoView) {
        sidePanel.scrollIntoView({behavior: 'smooth', block: 'nearest'});
      }
    });
  }

  // Text-search input
  document.getElementById('findings-search').addEventListener('input', (e) => {
    searchQuery = e.target.value.trim();
    renderFindings();
  });

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  // ---- Global keyboard handlers ----
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && activeJob) deselectJob();
    // `/` focuses the search input (common convention)
    if (event.key === '/' && document.activeElement.tagName !== 'INPUT') {
      event.preventDefault();
      document.getElementById('findings-search')?.focus();
    }
  });

  // ---- Embed mode: ?embed=1 hides demo-irrelevant UI affordances ----
  // Used by the ciguard.dev landing page when iframing this HTML, where
  // the Compare-against-previous-scan flow has no meaningful target +
  // visitors (rightly) flag the file picker as "what is this asking
  // me to upload?" Strips the Compare button, its hidden file input,
  // and the diff banner from the DOM. Diff-mode handlers below are
  // gated on `!embedMode` so they never wire up -- a determined user
  // can't trigger the file picker by URL hash trickery.
  const embedMode = new URLSearchParams(window.location.search).get('embed') === '1';
  if (embedMode) {
    ['compare-btn', 'compare-file', 'diff-banner'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.style.display = 'none';
    });
  }

  // ---- Diff mode: load a second ciguard map.html, compute diff ----
  let diffData = null;  // the previous-scan data, or null when not in diff mode

  if (!embedMode) document.getElementById('compare-btn').addEventListener('click', () => {
    if (diffData) {
      clearDiff();
    } else {
      document.getElementById('compare-file').click();
    }
  });
  if (!embedMode) document.getElementById('compare-file').addEventListener('change', (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    file.text().then(text => {
      // Extract the ciguard-data JSON blob from the HTML. Match the
      // open + close script tags. NB: don't write the literal close tag
      // string in this comment or in source, it would terminate the
      // inline script tag we're embedded inside.
      const m = text.match(/<script id="ciguard-data" type="application\/json">([\s\S]*?)<\/script>/);
      if (!m) {
        alert('That file does not contain a ciguard-data blob.');
        return;
      }
      try {
        const parsed = JSON.parse(m[1].replace(/<\\\//g, '</'));
        applyDiff(parsed);
      } catch (err) {
        alert('Failed to parse the previous-scan data: ' + err.message);
      }
    });
    // Reset so re-selecting the same file re-fires the change event
    e.target.value = '';
  });
  if (!embedMode) document.getElementById('diff-clear').addEventListener('click', clearDiff);

  function applyDiff(prev) {
    diffData = prev;
    document.getElementById('compare-btn').classList.add('active');
    document.getElementById('compare-btn').textContent = 'Clear comparison';

    // Index by fingerprint
    const prevFps = new Set(prev.findings.map(f => f.fingerprint));
    const curFps  = new Set(data.findings.map(f => f.fingerprint));
    let added = 0, resolved = 0, unchanged = 0;
    const newFps = new Set(), resolvedFps = new Set();
    for (const f of data.findings) {
      if (prevFps.has(f.fingerprint)) { unchanged++; }
      else { added++; newFps.add(f.fingerprint); }
    }
    for (const f of prev.findings) {
      if (!curFps.has(f.fingerprint)) { resolved++; resolvedFps.add(f.fingerprint); }
    }

    // Banner
    const banner = document.getElementById('diff-banner');
    banner.classList.add('visible');
    document.getElementById('diff-added').textContent = `+${added} new`;
    document.getElementById('diff-resolved').textContent = `−${resolved} resolved`;
    document.getElementById('diff-unchanged').textContent = `${unchanged} unchanged`;
    const prevTs = prev.meta?.scan_timestamp || '(unknown)';
    document.getElementById('diff-meta').textContent = `vs scan at ${prevTs}`;

    // Annotate findings in the global list (re-render)
    data.__diffNew = newFps;
    data.__diffResolved = resolvedFps;
    // Inject "RESOLVED" pseudo-findings so the user can SEE what's gone
    data.__resolvedFindings = prev.findings.filter(f => resolvedFps.has(f.fingerprint));

    // Mark nodes whose findings changed
    const newJobIds = new Set();
    for (const j of data.jobs) {
      const has = j.findings.some(f => newFps.has(f.fingerprint));
      if (has) newJobIds.add(j.id);
    }
    d3.selectAll('.node').classed('has-new', d => newJobIds.has(d.id));

    renderFindings();
  }

  function clearDiff() {
    diffData = null;
    document.getElementById('compare-btn').classList.remove('active');
    document.getElementById('compare-btn').textContent = 'Compare…';
    document.getElementById('diff-banner').classList.remove('visible');
    delete data.__diffNew;
    delete data.__diffResolved;
    delete data.__resolvedFindings;
    d3.selectAll('.node').classed('has-new', false).classed('fully-resolved', false);
    renderFindings();
  }

  // Patch renderFindings to surface diff status when active
  const _origRenderFindings = renderFindings;
  renderFindings = function() {
    findingsList.html('');
    let pool = [...data.findings];
    if (data.__resolvedFindings) {
      // Append resolved findings as ghosts at the end of the list
      pool = pool.concat(data.__resolvedFindings.map(f => ({...f, __resolved: true})));
    }
    const items = pool.filter(f => {
      if (activeSeverity !== 'all' && f.severity !== activeSeverity) return false;
      if (activeOrigin === 'pipeline' && f.owning_job !== null) return false;
      if (!matchSearch(f, searchQuery)) return false;
      return true;
    });
    if (!items.length) {
      findingsList.append('div').attr('class', 'findings-empty')
        .text(searchQuery
          ? `No findings match "${searchQuery}".`
          : 'No findings match the current filter.');
      d3.select('#findings-count').text(`0 of ${pool.length}`);
      return;
    }
    items.forEach(f => {
      const it = findingsList.append('div').attr('class', 'finding-item')
        .attr('data-fp', f.fingerprint)
        .attr('role', 'button')
        .attr('tabindex', 0);
      const r1 = it.append('div').attr('class', 'row1');
      r1.append('span').attr('class', `sev-pill ${f.severity}`).text(f.severity);
      r1.append('span').attr('class', 'rule-id').text(f.rule_id);
      // Diff-status pill
      let status = null;
      if (f.__resolved) status = 'RESOLVED';
      else if (data.__diffNew?.has(f.fingerprint)) status = 'NEW';
      else if (diffData) status = 'UNCHANGED';
      if (status) r1.append('span').attr('class', `diff-status ${status}`).text(status);
      it.append('div').attr('class', 'message').text(f.message);
      // Use display_location (humanised) — falls back to raw location.
      it.append('div').attr('class', 'location').text(f.display_location || f.location);
      it.on('click', () => {
        // Use the precomputed `owning_job` mapping (server-side recognises
        // every location shape: bare, job[name], jobs.name, stage[name]).
        const target = f.owning_job
          ? data.jobs.find(j => j.name === f.owning_job)
          : null;
        if (target) selectJob(target.id);
        d3.selectAll('.finding-item').classed('selected', false);
        it.classed('selected', true);
      })
      .on('keydown', function(event) {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          this.click();
        }
      });
    });
    d3.select('#findings-count').text(`${items.length} of ${pool.length}`);
  };
  void _origRenderFindings;  // keep reference for debugging

  // Initial render
  renderFindings();
})();
"""


def _escape_close_tag(js: str) -> str:
    """Replace any literal `</script>` in JS source with the escaped form
    so it can't terminate the inline `<script>` tag we embed it inside.

    Hit by Phase 1.4 — a comment in viewer JS contained an unescaped
    close-tag, breaking the embedded script silently. Defensive belt-
    and-braces so a future edit can't do the same."""
    # Case-insensitive: HTML parsers don't care about case on close tags.
    # `_re` is imported at module top; no local reimport needed (#35).
    return _re.sub(r"<(/script[^>]*>)", r"<\\\1", js, flags=_re.IGNORECASE)


def render(report: Report) -> str:
    """Build the self-contained HTML document."""
    data = _to_visual_data(report)
    d3_js = _load_vendored("d3.v7.min.js")

    score = data["score"]
    meta = data["meta"]

    # Pre-encode the data so we don't fight HTML escaping on the JS side.
    # We use json.dumps with ensure_ascii=False for compactness; the
    # `</script>` close-tag is escaped because that's the only sequence
    # that can break out of the embedded script context.
    data_json = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")

    # Severity totals for the header strip — render zero-chips for
    # severities with no findings so the visual vocabulary stays
    # consistent across pipelines (an "all clean" pipeline still shows
    # the legend; just dimmed).
    severity_chips: List[str] = []
    counts = score.get("by_severity_count", {})
    for sev_label in ("Critical", "High", "Medium", "Low", "Info"):
        n = counts.get(sev_label, 0)
        klass = sev_label if n else "zero"
        severity_chips.append(
            f'<span class="sev-chip {klass}"><span class="dot"></span>'
            f'{n} {sev_label}</span>'
        )
    severity_strip = "".join(severity_chips)

    # Pin-discipline strip — three compact chips reflecting per-image pin
    # status across every job that declares an image. Empty when nothing
    # in the report references images at all (e.g. minimal Jenkins jobs).
    pin = score.get("pin_discipline", {})
    pin_total = pin.get("digest", 0) + pin.get("tag", 0) + pin.get("mutable", 0)
    if pin_total:
        pin_chips = []
        for kind, label in (("digest", "digest"), ("tag", "tag"), ("mutable", "mutable")):
            n = pin.get(kind, 0)
            klass = kind if n else "zero"
            pin_chips.append(
                f'<span class="pin-chip {klass}" title="{n} image(s) pinned by {label}">'
                f'<span class="dot"></span>{n} {label}</span>'
            )
        pin_strip = (
            '<div class="summary-strip pin-strip" aria-label="Pinning discipline">'
            '<span class="strip-label">pinning</span>'
            + "".join(pin_chips) +
            '</div>'
        )
    else:
        pin_strip = ""

    grade = _html_escape(score["grade"])
    total_findings = sum(counts.values())

    # Pipeline-globals banner — surfaces orphan findings (pipeline.image,
    # global.variables, include directives) above the DAG so they have a
    # visual home rather than only appearing in the side-panel list.
    # Suppressed entirely when count == 0 — clean pipelines stay clean.
    globals_data = data.get("pipeline_globals", {})
    globals_count = globals_data.get("count", 0)
    if globals_count:
        globals_chips: List[str] = []
        for sev_label in ("Critical", "High", "Medium", "Low", "Info"):
            n = globals_data.get("by_severity", {}).get(sev_label, 0)
            if n:
                globals_chips.append(
                    f'<span class="globals-chip {sev_label}">{n} {sev_label}</span>'
                )
        plural = "s" if globals_count != 1 else ""
        globals_banner = (
            '<div class="globals-banner" id="globals-banner" '
            'role="region" aria-label="Pipeline-level findings">'
            '<div class="globals-text">'
            '<strong>Pipeline-level finding'
            f'{plural}</strong>'
            f'<span class="globals-sub">{globals_count} not attached to any job — '
            'pipeline-wide config (variables, includes, default image, runner). '
            'Resolves the gap noted in Slice 14a closeout.</span>'
            '</div>'
            f'<div class="globals-chips">{"".join(globals_chips)}</div>'
            '<button class="globals-show" id="globals-show" '
            f'aria-label="Show {globals_count} pipeline-level finding{plural} '
            'in side panel">Show in panel →</button>'
            '</div>'
        )
    else:
        globals_banner = ""

    # Inline all assets. Single self-contained file is the design goal.
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ciguard — {_html_escape(meta['pipeline_name'])}</title>
  <style>{_VIEWER_CSS}</style>
</head>
<body>
  <a href="#graph-container" class="skip-link">Skip to pipeline diagram</a>
  <div class="print-banner">
    ciguard audit · {_html_escape(meta['pipeline_name'])} · {_html_escape(meta['platform'])} · scanned {_html_escape(meta['scan_timestamp'])} · grade {grade} ({score['overall']:.0f}/100)
  </div>
  <header class="app-header">
    <div class="brand">
      <span class="product">ciguard audit</span>
      <h1>{_html_escape(meta['pipeline_name'])}</h1>
      <span class="platform-chip">{_html_escape(meta['platform'])}</span>
    </div>
    <div class="summary-strip">{severity_strip}</div>
    {pin_strip}
    <div class="score-block">
      <button class="compare-btn" id="compare-btn" aria-label="Compare against another scan">Compare…</button>
      <input type="file" id="compare-file" accept=".html,text/html" hidden>
      <div class="grade-pill {grade}" aria-label="Grade {grade}">{grade}</div>
      <div class="score-num" aria-label="Score {score['overall']:.0f} of 100">{score['overall']:.0f}<small>/100</small></div>
    </div>
  </header>
  <div class="diff-banner" id="diff-banner" role="status" aria-live="polite">
    <strong>Diff against previous scan:</strong>
    <span class="diff-pill added" id="diff-added">+0 new</span>
    <span class="diff-pill resolved" id="diff-resolved">−0 resolved</span>
    <span class="diff-pill unchanged" id="diff-unchanged">0 unchanged</span>
    <span id="diff-meta"></span>
    <button id="diff-clear" aria-label="Clear comparison">clear</button>
  </div>
  {globals_banner}
  <main>
    <div id="graph-container"></div>
    <aside id="side-panel">
      <div id="findings-view">
        <div class="panel-header">
          <h2>Findings</h2>
          <div class="panel-sub"><span id="findings-count">{total_findings} of {total_findings}</span> · click a finding to highlight its job</div>
        </div>
        <div class="panel-search">
          <input id="findings-search" type="search" placeholder="Search rule id, message, location…" autocomplete="off">
        </div>
        <div class="panel-filter">
          <button class="filter-btn active" data-sev="all">All</button>
          <button class="filter-btn" data-sev="Critical">Critical</button>
          <button class="filter-btn" data-sev="High">High</button>
          <button class="filter-btn" data-sev="Medium">Medium</button>
          <button class="filter-btn" data-sev="Low">Low</button>
          <button class="filter-btn" data-sev="Info">Info</button>
          <button class="filter-btn" data-origin="pipeline" id="filter-globals">Pipeline-level</button>
        </div>
        <div id="findings-list" class="findings-list"></div>
      </div>
      <div id="job-detail">
        <div class="detail-header">
          <button class="back-btn" id="back-to-findings">← Back to all findings</button>
          <h2 id="detail-job-name"></h2>
          <div class="detail-sub" id="detail-job-sub"></div>
        </div>
        <div class="gates-summary" id="gates-summary"></div>
        <div class="detail-scroll">
          <div class="yaml-section">
            <div class="section-label">Job configuration</div>
            <pre class="yaml-block" id="yaml-block"></pre>
          </div>
          <div class="findings-on-job" id="findings-on-job"></div>
        </div>
      </div>
    </aside>
  </main>
  <footer class="legend">
    <span class="legend-item"><span class="legend-swatch" style="background:#ef4444"></span>Critical</span>
    <span class="legend-item"><span class="legend-swatch" style="background:#f97316"></span>High</span>
    <span class="legend-item"><span class="legend-swatch" style="background:#f59e0b"></span>Medium</span>
    <span class="legend-item"><span class="legend-swatch" style="background:#22c55e"></span>Low</span>
    <span class="legend-item"><span class="legend-swatch" style="background:#6366f1"></span>Info</span>
    <span class="legend-item" style="margin-left:auto"><span class="legend-swatch" style="background:rgba(239,68,68,0.3); border:1px solid rgba(239,68,68,0.6)"></span>PROD target</span>
    <span class="legend-item"><span class="legend-swatch" style="background:rgba(99,102,241,0.3); border:1px solid rgba(99,102,241,0.6)"></span>Manual gate</span>
    <span class="legend-item"><span style="color:#22c55e">✓ DIGEST</span> · <span style="color:#f59e0b">TAG</span> · <span style="color:#ef4444">⚠ MUTABLE</span> &nbsp;image pin status</span>
    <span class="legend-item" style="color:#71717a">scanned {_html_escape(meta['scan_timestamp'])}</span>
  </footer>
  <script id="ciguard-data" type="application/json">{data_json}</script>
  <script>{_escape_close_tag(d3_js)}</script>
  <script>{_escape_close_tag(_VIEWER_JS)}</script>
</body>
</html>
"""


def _html_escape(value: Any) -> str:
    if value is None:
        return ""
    s = str(value)
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def write_report(report: Report, output_path: Path) -> Path:
    """File-system entry point used by the CLI's `--format html-interactive`."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render(report), encoding="utf-8")
    return output_path
