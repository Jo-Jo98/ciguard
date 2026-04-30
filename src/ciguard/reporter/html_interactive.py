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
from collections import defaultdict
from importlib.resources import files
from pathlib import Path
from typing import Any, Dict, List

from ciguard.models.pipeline import Finding, Job, Report, Severity


# ---- Severity → colour palette (post-pivot visual language) ---------------
#
# Mirrors `reference_ciguard_audit_scope.md` Slice 14a visual language.
# Severity colours match Tailwind's palette so any future themer hits
# familiar tokens. Border colour is what a node renders by default;
# fill stays neutral to keep the map readable in dense pipelines.

_SEVERITY_COLOURS: Dict[str, str] = {
    "Critical": "#ef4444",  # red-500
    "High":     "#f97316",  # orange-500
    "Medium":   "#f59e0b",  # amber-500
    "Low":      "#22c55e",  # green-500 (intentional: Low = "best practice", not danger)
    "Info":     "#6366f1",  # indigo-500
}
_NEUTRAL_BORDER = "#3f3f46"  # zinc-700 — node has no findings


# ---- Data-shape transform: Report → visualiser JSON -----------------------


def _image_pin_status(image: str | None) -> str:
    """Classify an image reference's pin discipline.

    Mirrors the spec for Slice 14c rules SCA-PIN-001..002 even though
    the rules themselves haven't shipped — the visualiser benefits from
    surfacing this on every node from day one. Categories:

      - "digest" — `image@sha256:...` form (immutable, verifiable)
      - "tag" — versioned tag without digest (`python:3.11.4`)
      - "mutable" — `:latest`, `:stable`, `:edge`, `:prod`, `:main`,
        `:master`, OR no tag at all (defaults to `:latest` at pull time)
      - "" — no image declared on this job
    """
    if not image:
        return ""
    # `image@sha256:abc...` — digest pin
    if "@sha256:" in image:
        return "digest"
    # Split on last colon for `host:port/repo:tag` shapes — the tag is
    # the suffix after the LAST colon if it doesn't look like a port.
    if ":" not in image:
        return "mutable"  # no tag = `:latest` at pull time
    # Strip registry prefix (e.g. `ghcr.io/org/img`) — only the tag-side
    # of the last colon matters for the pin category.
    after_last_colon = image.rsplit(":", 1)[-1]
    if after_last_colon.lower() in {
        "latest", "stable", "edge", "prod", "main", "master",
    }:
        return "mutable"
    return "tag"


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


def _findings_for_location(report: Report, location: str) -> List[Finding]:
    """Match findings whose `location` references a given job name.

    `location` on a Finding can be the literal job name OR `<job>:<line>`
    OR `global` / `include`. Job-attached findings include both the bare
    job-name match and the `<job>:` prefix match.
    """
    matched: List[Finding] = []
    prefix = f"{location}:"
    for f in report.findings:
        if f.location == location or f.location.startswith(prefix):
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

    for job in report.pipeline.jobs:
        job_id = _slug(job.name)
        name_to_id[job.name] = job_id

        job_findings = _findings_for_location(report, job.name)
        finding_payloads = [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "message": f.name,
                "location": f.location,
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
main { display: flex; height: calc(100% - 65px); }
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
    .on('click', (event, d) => selectJob(d.id));

  // ---- Side-panel: findings list with filtering ----
  const panel = d3.select('#findings-list');
  let activeSeverity = 'all';
  let activeJob = null;

  function renderFindings() {
    panel.html('');
    const items = data.findings.filter(f => {
      if (activeSeverity !== 'all' && f.severity !== activeSeverity) return false;
      if (activeJob) {
        // Show only findings whose location is the selected job (bare or `<job>:line`)
        const job = data.jobs.find(j => j.id === activeJob);
        if (!job) return false;
        return f.location === job.name || f.location.startsWith(job.name + ':');
      }
      return true;
    });
    if (!items.length) {
      panel.append('div').attr('class', 'findings-empty').text('No findings match the current filter.');
      return;
    }
    items.forEach(f => {
      const it = panel.append('div').attr('class', 'finding-item').attr('data-fp', f.fingerprint);
      const r1 = it.append('div').attr('class', 'row1');
      r1.append('span').attr('class', `sev-pill ${f.severity}`).text(f.severity);
      r1.append('span').attr('class', 'rule-id').text(f.rule_id);
      it.append('div').attr('class', 'message').text(f.message);
      it.append('div').attr('class', 'location').text(f.location);
      it.on('click', () => {
        // Navigate map: highlight the affected job (if any)
        const target = data.jobs.find(j => f.location === j.name || f.location.startsWith(j.name + ':'));
        if (target) selectJob(target.id);
        d3.selectAll('.finding-item').classed('selected', false);
        it.classed('selected', true);
      });
    });
    // Update sub-header count
    d3.select('#findings-count').text(`${items.length} of ${data.findings.length}`);
  }

  function selectJob(id) {
    activeJob = (activeJob === id) ? null : id;
    d3.selectAll('.node').classed('selected', d => d.id === activeJob);
    if (activeJob) {
      // Dim non-related nodes + edges, highlight selected and direct neighbours
      const neighbours = new Set([activeJob]);
      data.edges.forEach(e => {
        if (e.from === activeJob) neighbours.add(e.to);
        if (e.to === activeJob) neighbours.add(e.from);
      });
      d3.selectAll('.node').classed('dim', d => !neighbours.has(d.id));
      d3.selectAll('.edge').classed('dim', e => !(neighbours.has(e.from) && neighbours.has(e.to)))
        .classed('highlight', e => e.from === activeJob || e.to === activeJob);
    } else {
      d3.selectAll('.node').classed('dim', false);
      d3.selectAll('.edge').classed('dim', false).classed('highlight', false);
    }
    renderFindings();
  }

  // Filter buttons
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeSeverity = btn.dataset.sev;
      renderFindings();
    });
  });

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  // Initial render
  renderFindings();
})();
"""


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

    grade = _html_escape(score["grade"])
    total_findings = sum(counts.values())

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
  <header class="app-header">
    <div class="brand">
      <span class="product">ciguard audit</span>
      <h1>{_html_escape(meta['pipeline_name'])}</h1>
      <span class="platform-chip">{_html_escape(meta['platform'])}</span>
    </div>
    <div class="summary-strip">{severity_strip}</div>
    <div class="score-block">
      <div class="grade-pill {grade}">{grade}</div>
      <div class="score-num">{score['overall']:.0f}<small>/100</small></div>
    </div>
  </header>
  <main>
    <div id="graph-container"></div>
    <aside id="side-panel">
      <div class="panel-header">
        <h2>Findings</h2>
        <div class="panel-sub"><span id="findings-count">{total_findings} of {total_findings}</span> · click to highlight job</div>
      </div>
      <div class="panel-filter">
        <button class="filter-btn active" data-sev="all">All</button>
        <button class="filter-btn" data-sev="Critical">Critical</button>
        <button class="filter-btn" data-sev="High">High</button>
        <button class="filter-btn" data-sev="Medium">Medium</button>
        <button class="filter-btn" data-sev="Low">Low</button>
        <button class="filter-btn" data-sev="Info">Info</button>
      </div>
      <div id="findings-list" class="findings-list"></div>
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
  <script>{d3_js}</script>
  <script>{_VIEWER_JS}</script>
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
