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

from pathlib import Path
from typing import Dict, List, Optional, Sequence

from ..models.topology import (
    DeployEdge,
    EnvTransition,
    Environment,
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

# Severity → CSS variable / chip colour. Mirrors the per-pipeline visualiser
# palette so the same severity reads the same colour across all three
# audit-deliverable pages (visualiser, inventory, topology).
_SEV_COLOURS = {
    "Critical": "#ef4444",
    "High":     "#f97316",
    "Medium":   "#f59e0b",
    "Low":      "#22c55e",
    "Info":     "#6366f1",
}
_SEV_ORDER = ("Critical", "High", "Medium", "Low", "Info")


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


def _severity_chips(counts: dict) -> str:
    """Render a row of compact severity chips for a `{Critical: N, ...}`
    counts dict. Skips severities at zero so the cell stays compact."""
    chips: List[str] = []
    for sev in _SEV_ORDER:
        n = int(counts.get(sev, 0) or 0)
        if not n:
            continue
        colour = _SEV_COLOURS[sev]
        chips.append(
            f'<span class="sev-chip" style="color:{colour};border-color:{colour}40;">'
            f'{n} {sev[0]}</span>'
        )
    return " ".join(chips)


def _deploy_cell(
    edge: Optional[DeployEdge],
    env_is_prod: bool,
    *,
    edge_overlay: Optional[dict] = None,
) -> str:
    if edge is None:
        return '<td class="cell empty">&mdash;</td>'
    danger = env_is_prod and not edge.gates
    cell_class = "cell deploy danger" if danger else "cell deploy"
    pipeline_html = (
        f'<div class="pipeline-path">{_html_escape(edge.pipeline)}</div>'
        if edge.pipeline else ""
    )
    overlay_html = ""
    if edge_overlay is not None and edge_overlay.get("total", 0) > 0:
        chips = _severity_chips(edge_overlay)
        overlay_html = f'<div class="findings">{chips}</div>'
    elif edge_overlay is not None:
        overlay_html = '<div class="findings clean">clean</div>'
    return (
        f'<td class="{cell_class}">'
        f'<div class="gates">{_gate_chips(edge.gates)}</div>'
        f"{pipeline_html}"
        f"{overlay_html}"
        '</td>'
    )


def _env_header_cell(env: Environment, *, env_overlay: Optional[dict] = None) -> str:
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
    overlay_html = ""
    if env_overlay is not None and env_overlay.get("total", 0) > 0:
        overlay_html = (
            f'<div class="env-totals">{_severity_chips(env_overlay)}</div>'
        )
    return (
        f'<th class="{klass}">'
        f'<div class="env-id">{_html_escape(env.id)}</div>'
        f"{tier_html}{region}{overlay_html}"
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


def _swimlane_table(topology: Topology, aggregate: Optional[dict] = None) -> str:
    envs = _ordered_environments(topology.environments)
    services = _services_with_edges(topology)
    if not envs or not services:
        return '<p class="empty">No deploy edges to render.</p>'

    edge_map = _edge_lookup(topology.deploy_edges)
    by_env = (aggregate or {}).get("by_env", {}) or {}
    by_edge = (aggregate or {}).get("by_edge", {}) or {}
    aggregate_present = aggregate is not None

    header = "".join(
        _env_header_cell(e, env_overlay=by_env.get(e.id) if aggregate_present else None)
        for e in envs
    )
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
                edge_overlay=(
                    by_edge.get(f"{svc.id}::{env.id}")
                    if aggregate_present and edge_map.get((svc.id, env.id)) is not None
                    else None
                ),
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


def _verify_panel(verification: Optional[dict]) -> str:
    """Live-API drift panel (Slice 16, session 4). Surfaces three drift
    kinds returned by `verify_topology`:

      - `environment-not-found` (red): asserted env doesn't exist
      - `gate-not-actual` (red): asserted gate not present on live env
      - `gate-actual-not-asserted` (yellow): live gate not asserted

    Plus a per-repo summary row showing what the live snapshot looks
    like, and an `unverifiable` list for edges that couldn't be
    checked (no repo set, API failure, etc.). Renders nothing when
    verification is None or fully clean."""
    if not verification:
        return ""
    drift = verification.get("drift") or []
    by_repo = verification.get("by_repo") or {}
    unverifiable = verification.get("unverifiable") or []
    if not drift and not by_repo and not unverifiable:
        return ""

    sections: List[str] = []

    if drift:
        rows: List[str] = []
        for d in drift:
            kind = d.get("kind", "drift")
            kind_class = {
                "environment-not-found": "drift-kind danger",
                "gate-not-actual": "drift-kind danger",
                "gate-actual-not-asserted": "drift-kind warning",
            }.get(kind, "drift-kind")
            asserted = ", ".join(d.get("asserted_gates") or []) or "—"
            actual = ", ".join(d.get("actual_gates") or []) or "—"
            rows.append(
                "<tr>"
                f'<td><span class="{kind_class}">{_html_escape(kind)}</span></td>'
                f"<td><code>{_html_escape(d.get('service'))}</code></td>"
                f"<td><code>{_html_escape(d.get('environment'))}</code></td>"
                f"<td>{_html_escape(asserted)}</td>"
                f"<td>{_html_escape(actual)}</td>"
                f"<td>{_html_escape(d.get('detail'))}</td>"
                "</tr>"
            )
        sections.append(
            "<div><strong>Drift between asserted topology and live platform "
            f"({len(drift)}):</strong>"
            '<table class="ledger drift-table"><thead><tr>'
            "<th>kind</th><th>service</th><th>environment</th>"
            "<th>asserted gates</th><th>actual gates</th><th>detail</th>"
            "</tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table></div>"
        )

    if by_repo:
        rows = []
        for repo, snap in sorted(by_repo.items()):
            envs = snap.get("environments") or []
            err = snap.get("error")
            env_html = (
                ", ".join(
                    f'<code>{_html_escape(e.get("name"))}</code>'
                    for e in envs
                ) if envs else '<span class="muted">none</span>'
            )
            bp = snap.get("branch_protection")
            if bp:
                bp_rules = ", ".join(bp.get("rules") or []) or "—"
                bp_html = (
                    f'<code>{_html_escape(bp.get("branch"))}</code>: '
                    f'{_html_escape(bp_rules)}'
                )
            else:
                bp_html = '<span class="muted">none</span>'
            err_html = (
                f'<span class="drift-kind danger">{_html_escape(err)}</span>'
                if err else '<span class="muted">ok</span>'
            )
            rows.append(
                "<tr>"
                f"<td><code>{_html_escape(repo)}</code></td>"
                f"<td>{env_html}</td>"
                f"<td>{bp_html}</td>"
                f"<td>{err_html}</td>"
                "</tr>"
            )
        sections.append(
            "<div><strong>Live snapshot per repo "
            f"({len(by_repo)}):</strong>"
            '<table class="ledger"><thead><tr>'
            "<th>repo</th><th>environments</th>"
            "<th>default-branch protection</th><th>status</th>"
            "</tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table></div>"
        )

    if unverifiable:
        items = "".join(
            "<li>"
            f"<code>{_html_escape(u.get('service'))}</code> &rarr; "
            f"<code>{_html_escape(u.get('environment'))}</code> — "
            f"{_html_escape(u.get('reason'))}"
            "</li>"
            for u in unverifiable
        )
        sections.append(
            "<div><strong>Unverifiable deploy edges "
            f"({len(unverifiable)}):</strong><ul>{items}</ul></div>"
        )

    return (
        '<section class="panel">'
        "<h2>Live verification</h2>"
        '<div class="drift-panel">' + "".join(sections) + "</div></section>"
    )


def _drift_panel(aggregate: Optional[dict]) -> str:
    """When a scan-repo aggregate is overlaid, surface the drift between
    asserted topology and actual scanned files. Two lists matter:
    asserted pipelines that aren't present (renamed / deleted) and
    scanned pipelines that no DeployEdge claims (orphan workflows).
    Both are auditor-relevant — silence is suspicious."""
    if not aggregate:
        return ""
    unmatched_pipelines = aggregate.get("unmatched_pipelines") or []
    unmatched_files = aggregate.get("unmatched_files") or []
    if not unmatched_pipelines and not unmatched_files:
        return ""
    sections: List[str] = []
    if unmatched_pipelines:
        items = "".join(
            f'<li><code>{_html_escape(p)}</code></li>'
            for p in unmatched_pipelines
        )
        sections.append(
            "<div><strong>Asserted pipelines not found by scan-repo "
            f"({len(unmatched_pipelines)}):</strong>"
            f"<ul>{items}</ul></div>"
        )
    if unmatched_files:
        items = "".join(
            f'<li><code>{_html_escape(p)}</code></li>'
            for p in unmatched_files
        )
        sections.append(
            "<div><strong>Scanned pipelines with no DeployEdge "
            f"({len(unmatched_files)}):</strong>"
            f"<ul>{items}</ul></div>"
        )
    return (
        '<section class="panel"><h2>Drift between asserted topology and scan</h2>'
        '<div class="drift-panel">' + "".join(sections) + '</div></section>'
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

/* Scan-aggregate overlay (Slice 16 session 3) */
.findings { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 6px; }
.findings.clean { color: #22c55e; font-size: 10px; text-transform: uppercase;
                  letter-spacing: 0.06em; opacity: 0.7; }
.sev-chip {
  display: inline-block; font-size: 10px; padding: 2px 7px; border-radius: 999px;
  border: 1px solid; background: #18181c;
  font-variant-numeric: tabular-nums; font-weight: 600;
}
.env-totals { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 6px; }
.drift-panel { display: flex; flex-direction: column; gap: 12px; }
.drift-panel ul { margin: 6px 0 0; padding-left: 20px; color: #a1a1aa;
                  font-size: 12px; }
.drift-panel code { font-size: 11px; }
.drift-kind {
  display: inline-block; font-size: 10px; padding: 2px 8px; border-radius: 999px;
  border: 1px solid; background: #18181c;
  font-variant-numeric: tabular-nums; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.04em;
}
.drift-kind.danger { color: #ef4444; border-color: rgba(239,68,68,0.4); }
.drift-kind.warning { color: #f59e0b; border-color: rgba(245,158,11,0.4); }
table.drift-table { font-size: 12px; }
table.drift-table td { vertical-align: top; }

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


def render(
    topology: Topology,
    aggregate: Optional[dict] = None,
    verification: Optional[dict] = None,
) -> str:
    """Build the self-contained topology HTML document. When `aggregate`
    is passed (output of `aggregate_scan_into_topology()`), each
    swimlane cell is overlaid with severity chips for the matching
    pipeline + each environment header gets a totals strip + a drift
    panel surfaces asserted-vs-actual mismatches. When `verification`
    is passed (output of `verify_topology()`), an additional 'Live
    verification' panel surfaces gate drift between the asserted
    topology and the live SCM platform."""
    summary_bits = [
        f"{len(topology.services)} services",
        f"{len(topology.environments)} environments",
        f"{len(topology.deploy_edges)} deploy edges",
        f"{len(topology.transitions)} transitions",
        f"{len(topology.secret_scopes)} secret scopes",
        f"{len(topology.network_segments)} network segments",
    ]
    if aggregate is not None:
        total = sum(env.get("total", 0) for env in aggregate.get("by_env", {}).values())
        summary_bits.append(f"{total} matched findings (scan overlay)")
    if verification is not None:
        n_drift = len(verification.get("drift") or [])
        n_repos = len(verification.get("by_repo") or {})
        summary_bits.append(
            f"{n_drift} live drift record(s) across {n_repos} repo(s)"
        )
    summary = " &middot; ".join(summary_bits)
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
  {_swimlane_table(topology, aggregate)}
  {_drift_panel(aggregate)}
  {_verify_panel(verification)}
  {_secret_scopes_panel(topology)}
  {_network_panel(topology)}
</body>
</html>
"""


def write_report(
    topology: Topology,
    output_path: Path,
    aggregate: Optional[dict] = None,
    verification: Optional[dict] = None,
) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        render(topology, aggregate, verification),
        encoding="utf-8",
    )
    return output_path
