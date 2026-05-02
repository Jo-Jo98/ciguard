"""
Standalone HTML reporter for `ciguard topology --format html`.

Tabular swimlane view of the multi-environment topology: one row per
service, one column per environment, ordered by tier (development →
test → staging → production). Each (service, env) cell shows whether
that service deploys to that env and which gates protect the deploy.

Promotion-transition arrows render between adjacent environment columns
with their gates listed; gateless transitions are red-flagged.

Bottom panels: secret-scope blast radius (what does each scope expose?)
and network-segment reachability (which segments can reach which?).

Same dark-mode vocabulary as `inventory_html.py` and the per-pipeline
`html_interactive.py` so the audit deliverable is visually coherent.
Print-friendly via `@media print`. Pure function — no JavaScript, no
external dependencies, fully self-contained.

Why standalone (vs embedded in the per-pipeline visualiser): topology
is per-org, the visualiser is per-pipeline. Embedding the same
topology page in every pipeline's HTML would duplicate the data N
times. The org-level audit (Slice 17) is where the two will combine
into one page.
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from ..models.topology import (
    DeployEdge,
    EnvTransition,
    Environment,
    NetworkSegment,
    SecretScope,
    Service,
    Topology,
)

# Tier ordering for swimlane left-to-right layout. Unknown tiers sort
# alphabetically AFTER the recognised ones so they stay grouped on the
# right edge — operators see the canonical promotion path first.
_TIER_ORDER = [
    "development",
    "dev",
    "test",
    "qa",
    "staging",
    "stage",
    "preprod",
    "production",
    "prod",
    "live",
]
_TIER_RANK = {t: i for i, t in enumerate(_TIER_ORDER)}

# Gates the renderer understands well enough to badge in green; everything
# else still renders but gets the neutral chip styling.
_KNOWN_GATES = {
    "manual_approval",
    "required_reviewer",
    "branch_protection",
    "required_status_check",
    "wait_timer",
    "deployment_environment_protection",
}

_PROD_TIERS = {"production", "prod", "live"}


# ---------------------------------------------------------------------------
# HTML escaping (kept local, mirrors the inventory_html helper)
# ---------------------------------------------------------------------------


def _html_escape(value) -> str:
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


# ---------------------------------------------------------------------------
# Layout helpers
# ---------------------------------------------------------------------------


def _ordered_environments(envs: Sequence[Environment]) -> List[Environment]:
    """Sort environments left-to-right by `_TIER_ORDER`, then by id for
    stability within a tier. Unknown tiers fall after the canonical set."""
    def key(env: Environment):
        tier = (env.tier or "").lower()
        rank = _TIER_RANK.get(tier, len(_TIER_ORDER))
        return (rank, env.id)
    return sorted(envs, key=key)


def _services_with_edges(topology: Topology) -> List[Service]:
    """Only render service rows for services that actually have deploy
    edges — otherwise the swimlane fills with empty rows. Topologies
    that declare a service with no edges are still recorded in JSON
    output, just not in the rendered grid."""
    referenced = {e.service for e in topology.deploy_edges}
    return [s for s in topology.services if s.id in referenced]


def _edge_lookup(edges: Sequence[DeployEdge]) -> Dict[tuple, DeployEdge]:
    """Build a `(service_id, env_id) → DeployEdge` map for O(1) cell
    rendering. Last-write-wins when an operator declares duplicate
    edges; this matches the topology validator's no-uniqueness-required
    posture for edges (multiple edges to the same env can be legitimate
    when different pipelines deploy the same service)."""
    out: Dict[tuple, DeployEdge] = {}
    for e in edges:
        out[(e.service, e.environment)] = e
    return out


# ---------------------------------------------------------------------------
# Cell + chip renderers
# ---------------------------------------------------------------------------


def _gate_chip(gate: str) -> str:
    klass = "gate-known" if gate in _KNOWN_GATES else "gate-other"
    return f'<span class="gate-chip {klass}">{_html_escape(gate)}</span>'


def _gate_chips(gates: Sequence[str]) -> str:
    if not gates:
        return '<span class="gate-chip gate-missing">no gates</span>'
    return " ".join(_gate_chip(g) for g in gates)


def _deploy_cell(edge: Optional[DeployEdge], env_is_prod: bool) -> str:
    if edge is None:
        return '<td class="cell empty">&mdash;</td>'
    danger = env_is_prod and not edge.gates
    cell_class = "cell deploy danger" if danger else "cell deploy"
    pipeline_html = (
        f'<div class="pipeline-path">{_html_escape(edge.pipeline)}</div>'
        if edge.pipeline else ""
    )
    return (
        f'<td class="{cell_class}">'
        f'<div class="gates">{_gate_chips(edge.gates)}</div>'
        f"{pipeline_html}"
        '</td>'
    )


def _env_header_cell(env: Environment) -> str:
    tier = (env.tier or "").lower()
    is_prod = tier in _PROD_TIERS
    klass = "env-header prod" if is_prod else "env-header"
    region = (
        f'<div class="env-region">{_html_escape(env.region)}</div>'
        if env.region else ""
    )
    tier_html = (
        f'<div class="env-tier">{_html_escape(env.tier)}</div>'
        if env.tier else ""
    )
    return (
        f'<th class="{klass}">'
        f'<div class="env-id">{_html_escape(env.id)}</div>'
        f"{tier_html}{region}"
        '</th>'
    )


def _transition_row(envs: Sequence[Environment], transitions: Sequence[EnvTransition]) -> str:
    """Render a row above the service rows showing promotion-transition
    gates between adjacent env columns. Only adjacent-pair transitions
    fit naturally in the swimlane; non-adjacent ones (e.g. dev → prod)
    are noted in the audit summary instead.

    For each adjacent pair (env[i], env[i+1]) we look up a transition
    `from=env[i].id, to=env[i+1].id`. Missing transition → blank cell."""
    by_pair: Dict[tuple, EnvTransition] = {
        (t.from_env, t.to_env): t for t in transitions
    }
    cells: List[str] = ['<th class="trans-corner"></th>']
    for i, env in enumerate(envs):
        if i == len(envs) - 1:
            cells.append(f'<th class="trans-cell"><span class="muted">{_html_escape(env.id)}</span></th>')
            break
        nxt = envs[i + 1]
        t = by_pair.get((env.id, nxt.id))
        if t is None:
            arrow = '<span class="muted">no transition</span>'
        elif not t.gates:
            arrow = '<span class="trans-arrow danger">&rarr;</span> <span class="gate-chip gate-missing">no gates</span>'
        else:
            arrow = (
                '<span class="trans-arrow ok">&rarr;</span> '
                + _gate_chips(t.gates)
            )
        cells.append(
            f'<th class="trans-cell">'
            f'<div class="trans-label">{_html_escape(env.id)} {arrow}</div>'
            '</th>'
        )
    return f'<tr class="trans-row">{"".join(cells)}</tr>'


def _swimlane_table(topology: Topology) -> str:
    envs = _ordered_environments(topology.environments)
    services = _services_with_edges(topology)
    if not envs or not services:
        return '<p class="empty">No deploy edges to render.</p>'

    edge_map = _edge_lookup(topology.deploy_edges)

    header = "".join(_env_header_cell(e) for e in envs)
    head = (
        f'<thead><tr><th class="service-corner">service</th>{header}</tr>'
        f"{_transition_row(envs, topology.transitions)}</thead>"
    )

    body_rows: List[str] = []
    for svc in services:
        cells = "".join(
            _deploy_cell(
                edge_map.get((svc.id, env.id)),
                env_is_prod=(env.tier or "").lower() in _PROD_TIERS,
            )
            for env in envs
        )
        repo_html = (
            f'<div class="muted">{_html_escape(svc.repo)}</div>'
            if svc.repo else ""
        )
        body_rows.append(
            f'<tr><th class="service-cell">'
            f'<div class="service-id">{_html_escape(svc.id)}</div>'
            f"{repo_html}"
            f"</th>{cells}</tr>"
        )
    body = "<tbody>" + "".join(body_rows) + "</tbody>"
    return f'<table class="swimlane">{head}{body}</table>'


# ---------------------------------------------------------------------------
# Bottom panels — secret scopes + network reachability
# ---------------------------------------------------------------------------


def _secret_scopes_panel(topology: Topology) -> str:
    if not topology.secret_scopes:
        return ""
    rows: List[str] = []
    for scope in topology.secret_scopes:
        envs_chips = " ".join(
            f'<span class="entity-chip">{_html_escape(e)}</span>'
            for e in scope.environments
        )
        svcs_chips = " ".join(
            f'<span class="entity-chip">{_html_escape(s)}</span>'
            for s in scope.services
        )
        desc = (
            f'<div class="muted">{_html_escape(scope.description)}</div>'
            if scope.description else ""
        )
        rows.append(
            f'<tr>'
            f'<td><strong>{_html_escape(scope.id)}</strong>{desc}</td>'
            f'<td>{envs_chips or "&mdash;"}</td>'
            f'<td>{svcs_chips or "&mdash;"}</td>'
            f'</tr>'
        )
    return (
        '<section class="panel"><h2>Secret-scope blast radius</h2>'
        '<table class="ledger"><thead><tr>'
        '<th>scope</th><th>environments</th><th>services</th>'
        '</tr></thead><tbody>'
        + "".join(rows)
        + '</tbody></table></section>'
    )


def _network_panel(topology: Topology) -> str:
    if not topology.network_segments:
        return ""
    rows: List[str] = []
    for seg in topology.network_segments:
        try:
            reach = sorted(topology.reachable_segments(seg.id))
        except KeyError:
            reach = []
        reach_html = (
            " ".join(
                f'<span class="entity-chip">{_html_escape(r)}</span>'
                for r in reach
            )
            if reach
            else '<span class="muted">isolated</span>'
        )
        desc = (
            f'<div class="muted">{_html_escape(seg.description)}</div>'
            if seg.description else ""
        )
        rows.append(
            f'<tr>'
            f'<td><strong>{_html_escape(seg.id)}</strong>{desc}</td>'
            f'<td>{reach_html}</td>'
            f'</tr>'
        )
    return (
        '<section class="panel"><h2>Network reachability</h2>'
        '<table class="ledger"><thead><tr>'
        '<th>segment</th><th>can reach</th>'
        '</tr></thead><tbody>'
        + "".join(rows)
        + '</tbody></table></section>'
    )


def _gateless_warnings(topology: Topology) -> str:
    """Top-of-page banner enumerating gateless transitions to prod-tier
    environments. These are the auditor's highest-signal red flags."""
    prod_env_ids = {e.id for e in topology.production_environments()}
    gateless_to_prod: List[EnvTransition] = [
        t for t in topology.transitions_without_gates()
        if t.to_env in prod_env_ids
    ]
    gateless_prod_edges: List[DeployEdge] = [
        e for e in topology.deploy_edges
        if e.environment in prod_env_ids and not e.gates
    ]
    if not gateless_to_prod and not gateless_prod_edges:
        return ""
    items: List[str] = []
    for t in gateless_to_prod:
        items.append(
            f'<li>transition <code>{_html_escape(t.from_env)}</code> '
            f'&rarr; <code>{_html_escape(t.to_env)}</code> '
            'has no approval gate</li>'
        )
    for e in gateless_prod_edges:
        pipeline = e.pipeline or "(no pipeline path)"
        items.append(
            f'<li>service <code>{_html_escape(e.service)}</code> '
            f'deploys to <code>{_html_escape(e.environment)}</code> '
            f'via <code>{_html_escape(pipeline)}</code> '
            'with no gates</li>'
        )
    return (
        '<aside class="warnings">'
        '<strong>Posture warnings:</strong>'
        f"<ul>{''.join(items)}</ul>"
        '</aside>'
    )


# ---------------------------------------------------------------------------
# Public render entry point
# ---------------------------------------------------------------------------


_CSS = """
:root { color-scheme: dark; }
body {
  margin: 0; padding: 32px;
  background: #0a0a0a; color: #fafafa;
  font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Inter", "Geist Sans", sans-serif;
}
h1 { font-size: 22px; font-weight: 600; margin: 0 0 4px; }
h2 { font-size: 14px; font-weight: 600; text-transform: uppercase;
     letter-spacing: 0.08em; color: #a1a1aa; margin: 32px 0 12px; }
.meta { color: #a1a1aa; font-size: 12px; margin-bottom: 18px; }
.muted { color: #71717a; font-size: 11px; font-family: ui-monospace, "SF Mono", Menlo, monospace; }
code {
  font-family: ui-monospace, "SF Mono", Menlo, monospace;
  font-size: 12px; padding: 1px 5px; border-radius: 3px;
  background: #18181c; color: #fafafa;
}

.warnings {
  background: linear-gradient(135deg, rgba(239,68,68,0.12), rgba(239,68,68,0.02));
  border: 1px solid rgba(239,68,68,0.4); border-radius: 8px;
  padding: 12px 16px; color: #fca5a5; margin-bottom: 24px;
}
.warnings ul { margin: 6px 0 0; padding-left: 20px; }
.warnings code { background: #1a1a1f; }

table.swimlane {
  width: 100%; border-collapse: separate; border-spacing: 0;
  background: #131316; border: 1px solid #27272a; border-radius: 8px;
  overflow: hidden; margin-bottom: 16px;
}
table.swimlane th, table.swimlane td {
  padding: 10px 12px; vertical-align: top; border-bottom: 1px solid #27272a;
}
table.swimlane thead th { background: #18181c; color: #a1a1aa; font-weight: 600;
                          font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; }
.env-header.prod { background: linear-gradient(135deg, rgba(239,68,68,0.16), rgba(239,68,68,0.04)); }
.env-id { color: #fafafa; font-size: 13px; font-weight: 600; text-transform: none; letter-spacing: 0; }
.env-tier, .env-region { color: #a1a1aa; font-size: 10px; font-weight: 400;
                         text-transform: uppercase; letter-spacing: 0.06em; margin-top: 2px; }
.service-corner, .trans-corner { background: #18181c; }
.service-cell { background: #18181c; min-width: 200px; }
.service-id { color: #fafafa; font-size: 13px; font-weight: 600; }
.trans-row th { background: #131316; padding: 6px 12px; }
.trans-label { color: #a1a1aa; font-size: 11px; }
.trans-arrow.ok { color: #22c55e; font-weight: 700; }
.trans-arrow.danger { color: #ef4444; font-weight: 700; }
.cell.empty { color: #52525b; text-align: center; }
.cell.deploy { background: #1a1a1f; }
.cell.deploy.danger { background: linear-gradient(135deg, rgba(239,68,68,0.18), rgba(239,68,68,0.04));
                      border-left: 3px solid #ef4444; }
.gates { display: flex; flex-wrap: wrap; gap: 4px; }
.pipeline-path { color: #71717a; font-size: 11px; font-family: ui-monospace, "SF Mono", Menlo, monospace;
                 margin-top: 6px; word-break: break-all; }
.gate-chip {
  display: inline-block; font-size: 10px; padding: 2px 8px; border-radius: 999px;
  border: 1px solid #27272a; background: #18181c;
  font-variant-numeric: tabular-nums;
}
.gate-known { color: #22c55e; border-color: rgba(34,197,94,0.3); }
.gate-other { color: #a1a1aa; border-color: #3f3f46; }
.gate-missing { color: #ef4444; border-color: rgba(239,68,68,0.5); background: rgba(239,68,68,0.06); }

.panel { margin-top: 24px; }
table.ledger {
  width: 100%; border-collapse: collapse;
  background: #131316; border: 1px solid #27272a; border-radius: 8px;
  overflow: hidden;
}
table.ledger th, table.ledger td { padding: 10px 14px; text-align: left;
                                   border-bottom: 1px solid #27272a; vertical-align: top; }
table.ledger thead th { background: #18181c; color: #a1a1aa; font-weight: 600; font-size: 11px;
                        text-transform: uppercase; letter-spacing: 0.06em; }
table.ledger tbody tr:last-child td { border-bottom: none; }
.entity-chip {
  display: inline-block; font-size: 11px; padding: 2px 8px; border-radius: 999px;
  border: 1px solid #3f3f46; background: #18181c; color: #fafafa; margin-right: 4px;
}

.empty { color: #a1a1aa; text-align: center; padding: 32px; }

@media print {
  body { background: #fff; color: #18181c; }
  table.swimlane, table.ledger { background: #fff; border-color: #e4e4e7; }
  table.swimlane thead th, table.ledger thead th { background: #f4f4f5; color: #52525b; }
  table.swimlane th, table.swimlane td, table.ledger th, table.ledger td { border-bottom-color: #e4e4e7; }
  .service-cell, .service-corner, .trans-corner { background: #fafafa; }
  .cell.deploy { background: #fafafa; }
  .cell.deploy.danger { background: rgba(239,68,68,0.1); }
  .env-header.prod { background: rgba(239,68,68,0.1); }
  .gate-chip { background: #fff; }
  .gate-other { color: #52525b; }
  .entity-chip { background: #fff; color: #18181c; border-color: #d4d4d8; }
  code, .muted { color: #52525b; background: #f4f4f5; }
  .warnings { background: #fef2f2; color: #991b1b; }
  .warnings code { background: #fff5f5; }
  .trans-row th { background: #fff; }
}
"""


def render(topology: Topology) -> str:
    """Build the self-contained topology HTML document."""
    summary = (
        f"{len(topology.services)} services &middot; "
        f"{len(topology.environments)} environments &middot; "
        f"{len(topology.deploy_edges)} deploy edges &middot; "
        f"{len(topology.transitions)} transitions &middot; "
        f"{len(topology.secret_scopes)} secret scopes &middot; "
        f"{len(topology.network_segments)} network segments"
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ciguard topology</title>
  <style>{_CSS}</style>
</head>
<body>
  <h1>ciguard topology</h1>
  <div class="meta">{summary}</div>
  {_gateless_warnings(topology)}
  {_swimlane_table(topology)}
  {_secret_scopes_panel(topology)}
  {_network_panel(topology)}
</body>
</html>
"""


def write_report(topology: Topology, output_path: Path) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render(topology), encoding="utf-8")
    return output_path
