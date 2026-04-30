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

        jobs_data.append({
            "id": job_id,
            "name": job.name,
            "stage": job.stage,
            "image": job.image,
            "environment": env_name,
            "is_deploy": job.is_deploy_job(),
            "targets_production": job.targets_production(),
            "has_manual_gate": job.has_manual_gate(),
            "deps": _job_dependencies(job),  # raw names; resolved client-side
            "findings": finding_payloads,
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
  --bg-card: #111113;
  --fg: #fafafa;
  --fg-muted: #a1a1aa;
  --border: #27272a;
  --accent: #6366f1;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; height: 100%; }
body {
  background: var(--bg);
  color: var(--fg);
  font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", system-ui, sans-serif;
  font-size: 14px;
  line-height: 1.5;
}
header {
  padding: 16px 24px;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: baseline;
  gap: 16px;
}
header h1 { margin: 0; font-size: 16px; font-weight: 600; }
header .meta { color: var(--fg-muted); font-size: 12px; }
.score-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 999px;
  padding: 4px 12px;
  font-size: 12px;
}
.score-pill .grade { font-weight: 700; font-size: 14px; }
main { display: flex; height: calc(100% - 57px); }
#graph-container {
  flex: 1;
  overflow: auto;
  background:
    radial-gradient(circle at 20% 0%, rgba(99,102,241,0.06) 0%, transparent 50%),
    var(--bg);
}
#graph-container svg { display: block; }
.node rect {
  fill: var(--bg-card);
  stroke-width: 2;
  rx: 6;
  ry: 6;
}
.node text {
  fill: var(--fg);
  font-size: 12px;
  font-weight: 500;
  pointer-events: none;
}
.node .findings-badge {
  fill: var(--fg-muted);
  font-size: 10px;
  pointer-events: none;
}
.edge {
  stroke: var(--border);
  stroke-width: 1.5;
  fill: none;
  marker-end: url(#arrowhead);
}
.tooltip {
  position: absolute;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 10px 14px;
  font-size: 12px;
  pointer-events: none;
  max-width: 320px;
  z-index: 100;
  opacity: 0;
  transition: opacity 100ms;
}
.tooltip strong { display: block; margin-bottom: 4px; }
.tooltip .severity-line {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-top: 4px;
}
.tooltip .severity-dot {
  width: 8px; height: 8px; border-radius: 50%; display: inline-block;
}
.severity-Critical { color: #ef4444; }
.severity-High { color: #f97316; }
.severity-Medium { color: #f59e0b; }
.severity-Low { color: #22c55e; }
.severity-Info { color: #6366f1; }
"""

_VIEWER_JS = r"""
(() => {
  const data = JSON.parse(document.getElementById('ciguard-data').textContent);

  // ---- Layered layout: assign each node a column based on dep depth ----
  const idToJob = new Map(data.jobs.map(j => [j.id, j]));
  const incoming = new Map(data.jobs.map(j => [j.id, []]));
  const outgoing = new Map(data.jobs.map(j => [j.id, []]));
  for (const e of data.edges) {
    incoming.get(e.to).push(e.from);
    outgoing.get(e.from).push(e.to);
  }

  // Topological depth: jobs with no incoming edges → depth 0; everyone
  // else's depth is 1 + max(depth of dependencies). Cycles are guarded
  // against by capping the BFS at jobs.length.
  const depth = new Map();
  const queue = data.jobs.filter(j => incoming.get(j.id).length === 0).map(j => j.id);
  for (const id of queue) depth.set(id, 0);
  let safety = data.jobs.length * 2;
  while (queue.length && safety-- > 0) {
    const id = queue.shift();
    for (const child of outgoing.get(id) || []) {
      const candidate = (depth.get(id) || 0) + 1;
      if (candidate > (depth.get(child) || -1)) {
        depth.set(child, candidate);
        queue.push(child);
      }
    }
  }
  // Fallback for orphan / cycle-stuck nodes
  for (const j of data.jobs) {
    if (!depth.has(j.id)) depth.set(j.id, 0);
  }

  // Group nodes by depth column
  const columns = {};
  for (const j of data.jobs) {
    const d = depth.get(j.id);
    if (!columns[d]) columns[d] = [];
    columns[d].push(j);
  }
  const maxDepth = Math.max(0, ...Object.keys(columns).map(Number));

  // Node + spacing constants
  const NODE_W = 200;
  const NODE_H = 56;
  const COL_GAP = 80;
  const ROW_GAP = 24;
  const PAD = 40;

  // Position
  const positioned = [];
  for (let d = 0; d <= maxDepth; d++) {
    const col = columns[d] || [];
    col.forEach((j, idx) => {
      positioned.push({
        ...j,
        x: PAD + d * (NODE_W + COL_GAP),
        y: PAD + idx * (NODE_H + ROW_GAP),
      });
    });
  }
  const totalRows = Math.max(...Object.values(columns).map(c => c.length), 1);
  const svgWidth = PAD * 2 + (maxDepth + 1) * NODE_W + maxDepth * COL_GAP;
  const svgHeight = PAD * 2 + totalRows * (NODE_H + ROW_GAP);

  // Severity → colour
  const SEV = {
    Critical: '#ef4444',
    High:     '#f97316',
    Medium:   '#f59e0b',
    Low:      '#22c55e',
    Info:     '#6366f1',
  };
  const NEUTRAL = '#3f3f46';

  // ---- Render ----
  const svg = d3.select('#graph-container')
    .append('svg')
    .attr('width', svgWidth)
    .attr('height', svgHeight);

  // Arrowhead marker
  svg.append('defs').append('marker')
    .attr('id', 'arrowhead')
    .attr('viewBox', '0 -5 10 10')
    .attr('refX', 8)
    .attr('refY', 0)
    .attr('markerWidth', 6)
    .attr('markerHeight', 6)
    .attr('orient', 'auto')
    .append('path')
    .attr('d', 'M0,-5L10,0L0,5')
    .attr('fill', '#52525b');

  // Edges
  const idToPos = new Map(positioned.map(p => [p.id, p]));
  svg.append('g').attr('class', 'edges').selectAll('path')
    .data(data.edges.filter(e => idToPos.has(e.from) && idToPos.has(e.to)))
    .enter()
    .append('path')
    .attr('class', 'edge')
    .attr('d', e => {
      const s = idToPos.get(e.from);
      const t = idToPos.get(e.to);
      const x1 = s.x + NODE_W;
      const y1 = s.y + NODE_H / 2;
      const x2 = t.x;
      const y2 = t.y + NODE_H / 2;
      const mx = (x1 + x2) / 2;
      return `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`;
    });

  // Tooltip
  const tooltip = d3.select('body').append('div').attr('class', 'tooltip');

  // Nodes
  const nodes = svg.append('g').attr('class', 'nodes')
    .selectAll('g')
    .data(positioned)
    .enter()
    .append('g')
    .attr('class', 'node')
    .attr('transform', d => `translate(${d.x},${d.y})`)
    .on('mouseenter', (event, d) => {
      const sev = d.highest_severity;
      const findCount = d.findings.length;
      const sevHtml = sev
        ? `<div class="severity-line"><span class="severity-dot" style="background:${SEV[sev]}"></span><span class="severity-${sev}">${findCount} finding${findCount === 1 ? '' : 's'} — worst: ${sev}</span></div>`
        : `<div class="severity-line"><span class="severity-dot" style="background:${NEUTRAL}"></span>No findings</div>`;
      const stageLine = d.stage ? `<div>stage: ${d.stage}</div>` : '';
      const imageLine = d.image ? `<div>image: ${d.image}</div>` : '';
      const envLine = d.environment ? `<div>environment: ${d.environment}${d.targets_production ? ' (prod)' : ''}</div>` : '';
      tooltip.html(`<strong>${d.name}</strong>${stageLine}${imageLine}${envLine}${sevHtml}`)
        .style('left', (event.pageX + 12) + 'px')
        .style('top', (event.pageY + 12) + 'px')
        .style('opacity', 1);
    })
    .on('mousemove', (event) => {
      tooltip
        .style('left', (event.pageX + 12) + 'px')
        .style('top', (event.pageY + 12) + 'px');
    })
    .on('mouseleave', () => tooltip.style('opacity', 0));

  nodes.append('rect')
    .attr('width', NODE_W)
    .attr('height', NODE_H)
    .attr('stroke', d => d.highest_severity ? SEV[d.highest_severity] : NEUTRAL);

  nodes.append('text')
    .attr('x', 12)
    .attr('y', 22)
    .text(d => d.name.length > 26 ? d.name.slice(0, 24) + '…' : d.name);

  nodes.append('text')
    .attr('class', 'findings-badge')
    .attr('x', 12)
    .attr('y', 42)
    .text(d => {
      const f = d.findings.length;
      if (!f) return 'no findings';
      return `${f} finding${f === 1 ? '' : 's'}`;
    });
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
  <header>
    <h1>{_html_escape(meta['pipeline_name'])}</h1>
    <span class="meta">{_html_escape(meta['platform'])} · scanned {_html_escape(meta['scan_timestamp'])}</span>
    <span class="score-pill"><span class="grade">{_html_escape(score['grade'])}</span> · {score['overall']:.1f}/100</span>
  </header>
  <main>
    <div id="graph-container"></div>
  </main>
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
