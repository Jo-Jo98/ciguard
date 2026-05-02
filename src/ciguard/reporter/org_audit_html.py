"""
Standalone HTML org-audit dashboard (Slice 17).

`ciguard audit-org --format html --output dashboard.html` produces a
single self-contained dark-mode HTML page summarising one org's
posture across N repos. Pure function — no JavaScript, no
dependencies, fully self-contained. Same vocabulary as
`topology_html.py` and `inventory_html.py` so the three audit
deliverables (per-pipeline visualiser, infra inventory, topology,
org dashboard) read as one family.

Layout:

  - Header strip: org id + scan timestamp + summary counts (repos
    scanned, total findings, by-severity).
  - Grade-distribution bar: A/B/C/D/F + `?` (no scannable files) chip
    counts so the auditor sees the org-wide shape at a glance.
  - Per-platform counts: which CI platforms appear across the org.
  - Repo cards table: one row per repo with grade, finding counts,
    pipeline-file count, archived/fork/private flags, error if any.
  - Errors panel (when any errors collected).

The dashboard intentionally does NOT embed per-repo drill-down maps
— those will come in session 2 when each repo gets a linked
`html-interactive` artifact. For session 1 the dashboard tells you
WHICH repos to drill into; the drill-in itself uses the existing
per-pipeline visualiser as a separate run.
"""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from ..models.org_audit import (
    GRADE_ORDER,
    OrgAuditReport,
    RepoScanRecord,
    SEVERITY_ORDER,
)

# Severity → CSS variable / chip colour. Same palette as the rest of
# the audit deliverables.
_SEV_COLOURS = {
    "Critical": "#ef4444",
    "High":     "#f97316",
    "Medium":   "#f59e0b",
    "Low":      "#22c55e",
    "Info":     "#6366f1",
}
_GRADE_COLOURS = {
    "A": "#22c55e",
    "B": "#84cc16",
    "C": "#f59e0b",
    "D": "#f97316",
    "F": "#ef4444",
    "?": "#71717a",
}


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


def _severity_chips(counts: dict) -> str:
    chips: List[str] = []
    for sev in SEVERITY_ORDER:
        n = int(counts.get(sev, 0) or 0)
        if not n:
            continue
        colour = _SEV_COLOURS[sev]
        chips.append(
            f'<span class="sev-chip" style="color:{colour};border-color:{colour}40;">'
            f'{n} {sev[0]}</span>'
        )
    return " ".join(chips) if chips else (
        '<span class="sev-chip clean">no findings</span>'
    )


def _grade_chip(grade: Optional[str]) -> str:
    label = grade or "?"
    colour = _GRADE_COLOURS.get(label, "#71717a")
    return (
        f'<span class="grade-chip" style="color:{colour};border-color:{colour}50;">'
        f'{_html_escape(label)}</span>'
    )


def _grade_distribution_strip(report: OrgAuditReport) -> str:
    dist = report.grade_distribution
    parts: List[str] = []
    for grade in (*GRADE_ORDER, "?"):
        n = dist.get(grade, 0)
        if not n:
            continue
        colour = _GRADE_COLOURS.get(grade, "#71717a")
        label = "no scan" if grade == "?" else grade
        parts.append(
            f'<span class="dist-chip" style="border-color:{colour}50;">'
            f'<strong style="color:{colour};">{n}</strong> '
            f'<span class="dist-label">{_html_escape(label)}</span></span>'
        )
    return " ".join(parts) if parts else ""


def _platforms_strip(report: OrgAuditReport) -> str:
    plat = report.platforms_detected
    if not plat:
        return ""
    parts = [
        f'<span class="dist-chip platform-chip">'
        f'<strong>{n}</strong> <span class="dist-label">{_html_escape(name)}</span></span>'
        for name, n in sorted(plat.items(), key=lambda kv: -kv[1])
    ]
    return " ".join(parts)


def _repo_row(record: RepoScanRecord) -> str:
    flags: List[str] = []
    if record.private:
        flags.append('<span class="flag flag-priv">private</span>')
    if record.archived:
        flags.append('<span class="flag flag-arc">archived</span>')
    if record.fork:
        flags.append('<span class="flag flag-fork">fork</span>')

    if record.error:
        body = (
            f'<td colspan="4" class="error">'
            f'<span class="flag flag-err">error</span> '
            f'{_html_escape(record.error)}</td>'
        )
    elif record.scan is None:
        if record.pipeline_file_count == 0:
            body = (
                '<td>—</td>'
                '<td class="muted">no pipeline files</td>'
                '<td class="muted">—</td>'
                '<td class="muted">0</td>'
            )
        else:
            body = (
                '<td>—</td>'
                '<td class="muted">scan skipped</td>'
                '<td class="muted">—</td>'
                f'<td class="muted">{record.pipeline_file_count}</td>'
            )
    else:
        sev_html = _severity_chips(record.scan.get("by_severity") or {})
        files_n = record.scan.get("files_scanned", 0)
        total = record.scan.get("total_findings", 0)
        body = (
            f"<td>{_grade_chip(record.grade)}</td>"
            f'<td class="findings-cell">{sev_html}</td>'
            f"<td>{total}</td>"
            f"<td>{files_n}</td>"
        )

    flags_html = " ".join(flags)
    desc_html = (
        f'<div class="repo-desc">{_html_escape(record.description)}</div>'
        if record.description else ""
    )
    return (
        "<tr>"
        f"<td><code>{_html_escape(record.repo)}</code> "
        f"{flags_html}"
        f"{desc_html}"
        "</td>"
        + body
        + "</tr>"
    )


def _errors_panel(report: OrgAuditReport) -> str:
    if not report.errors:
        return ""
    items: List[str] = []
    for err in report.errors:
        repo = err.get("repo", "(global)")
        phase = err.get("phase", "?")
        msg = err.get("error", "")
        items.append(
            f"<li><code>{_html_escape(repo)}</code> "
            f"<span class=\"muted\">[{_html_escape(phase)}]</span> "
            f"— {_html_escape(msg)}</li>"
        )
    return (
        '<section class="panel">'
        f"<h2>Errors ({len(report.errors)})</h2>"
        f'<ul class="error-list">{"".join(items)}</ul>'
        "</section>"
    )


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
.dist-strip { display: flex; flex-wrap: wrap; gap: 8px; margin: 6px 0 18px; }
.dist-chip {
  display: inline-flex; align-items: baseline; gap: 6px;
  font-size: 11px; padding: 3px 10px; border-radius: 999px;
  border: 1px solid #3f3f46; background: #18181c;
}
.dist-chip strong { font-size: 13px; font-variant-numeric: tabular-nums; }
.dist-label { color: #a1a1aa; text-transform: uppercase; letter-spacing: 0.06em; font-size: 10px; }
.platform-chip strong { color: #fafafa; }

.summary-line { display: flex; gap: 16px; flex-wrap: wrap; margin: 4px 0 18px; }
.summary-num { font-variant-numeric: tabular-nums; font-weight: 600; color: #fafafa; }

table.repos {
  width: 100%; border-collapse: collapse;
  background: #131316; border: 1px solid #27272a; border-radius: 8px;
  overflow: hidden;
}
table.repos th, table.repos td { padding: 10px 14px; text-align: left;
                                 border-bottom: 1px solid #27272a; vertical-align: middle; }
table.repos thead th { background: #18181c; color: #a1a1aa; font-weight: 600; font-size: 11px;
                       text-transform: uppercase; letter-spacing: 0.06em; }
table.repos tbody tr:last-child td { border-bottom: none; }
.repo-desc { color: #a1a1aa; font-size: 11px; margin-top: 4px; }
.findings-cell { min-width: 180px; }

.grade-chip {
  display: inline-block; min-width: 28px; text-align: center;
  font-size: 13px; font-weight: 700; padding: 2px 10px; border-radius: 6px;
  border: 1px solid; background: #18181c;
}
.sev-chip {
  display: inline-block; font-size: 10px; padding: 2px 7px; border-radius: 999px;
  border: 1px solid; background: #18181c;
  font-variant-numeric: tabular-nums; font-weight: 600;
}
.sev-chip.clean { color: #22c55e; border-color: rgba(34,197,94,0.4); }

.flag {
  display: inline-block; font-size: 10px; padding: 1px 7px; border-radius: 999px;
  border: 1px solid #3f3f46; background: #18181c; color: #a1a1aa;
  text-transform: uppercase; letter-spacing: 0.06em; margin-left: 4px;
}
.flag-priv { color: #a78bfa; border-color: rgba(167,139,250,0.4); }
.flag-arc { color: #f59e0b; border-color: rgba(245,158,11,0.4); }
.flag-fork { color: #6366f1; border-color: rgba(99,102,241,0.4); }
.flag-err { color: #ef4444; border-color: rgba(239,68,68,0.4); }

.panel { margin-top: 24px; }
.error-list { padding-left: 20px; color: #a1a1aa; font-size: 12px; }
.error-list code { font-size: 11px; }
.error { color: #fca5a5; }

@media print {
  body { background: #fff; color: #18181c; }
  table.repos { background: #fff; border-color: #e4e4e7; }
  table.repos thead th { background: #f4f4f5; color: #52525b; }
  table.repos th, table.repos td { border-bottom-color: #e4e4e7; }
  .dist-chip, .grade-chip, .sev-chip, .flag, code { background: #fff; }
  .repo-desc, .muted, .dist-label { color: #52525b; }
}
"""


def render(report: OrgAuditReport) -> str:
    sev = report.by_severity
    summary_bits = [
        f'<span class="summary-num">{report.repos_scanned}</span>'
        ' repos scanned',
        f'<span class="summary-num">{len(report.repos)}</span>'
        ' repos in scope',
        f'<span class="summary-num">{report.total_findings}</span>'
        ' findings',
        f'<span class="summary-num">{report.repos_with_findings}</span>'
        ' repos with findings',
    ]

    rows = "".join(_repo_row(r) for r in report.repos) or (
        '<tr><td colspan="5" class="muted" style="text-align:center;padding:32px;">'
        'no repos in scope after filtering</td></tr>'
    )

    skipped_bits: List[str] = []
    if report.skipped_archived:
        skipped_bits.append(
            f'{report.skipped_archived} archived'
        )
    if report.skipped_forks:
        skipped_bits.append(
            f'{report.skipped_forks} forks'
        )
    skipped_html = (
        f'<div class="meta">Skipped: {", ".join(skipped_bits)}</div>'
        if skipped_bits else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ciguard audit-org — {_html_escape(report.org)}</title>
  <style>{_CSS}</style>
</head>
<body>
  <h1>ciguard audit-org &mdash; {_html_escape(report.org)}</h1>
  <div class="meta">{_html_escape(report.scan_timestamp)} &middot; provider: {_html_escape(report.provider)}</div>
  <div class="summary-line">{" &middot; ".join(summary_bits)}</div>
  <div class="summary-line">
    {_severity_chips(sev)}
  </div>
  {skipped_html}

  <h2>Grade distribution</h2>
  <div class="dist-strip">{_grade_distribution_strip(report) or "<span class='muted'>no graded repos</span>"}</div>

  <h2>Platforms detected</h2>
  <div class="dist-strip">{_platforms_strip(report) or "<span class='muted'>no pipelines detected</span>"}</div>

  <h2>Repos ({len(report.repos)})</h2>
  <table class="repos">
    <thead><tr>
      <th>Repo</th><th>Grade</th><th>Findings</th><th>Total</th><th>Files</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>

  {_errors_panel(report)}
</body>
</html>
"""


def write_report(report: OrgAuditReport, output_path: Path) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render(report), encoding="utf-8")
    return output_path
