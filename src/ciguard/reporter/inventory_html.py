"""
Standalone HTML reporter for `ciguard inventory --format html`.

Self-contained dark-mode page reusing the visual vocabulary from
`html_interactive.py`: same colour palette, same chip styles, same
typography fallback. Print-friendly so an auditor can hand it over as
an attachment.

Why standalone (vs embedded in the per-pipeline visualiser): inventory
is per-organisation, the visualiser is per-pipeline. Embedding the same
inventory table in every pipeline's HTML duplicates the data N times
across N pipelines. The org-level audit (Slice 17) is where the two
will combine into one page.
"""
from __future__ import annotations

from pathlib import Path

from ..models.inventory import InventoryEntry, InventoryReport


_STATUS_COLOURS = {
    "ok":               "#22c55e",
    "approaching-eol":  "#f59e0b",
    "end-of-support":   "#f59e0b",
    "end-of-life":      "#ef4444",
    "error":            "#ef4444",
    "unconfigured":     "#71717a",
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


def _row(entry: InventoryEntry) -> str:
    status = entry.status
    status_colour = _STATUS_COLOURS.get(status, "#a1a1aa")
    notes_bits: list[str] = []
    if entry.eol_date:
        d = entry.days_until_eol
        if d is not None:
            label = (
                f"EOL {entry.eol_date} ({d} days)" if d >= 0
                else f"EOL {entry.eol_date} ({abs(d)} days past)"
            )
        else:
            label = f"EOL {entry.eol_date}"
        notes_bits.append(label)
    if entry.eos_date:
        notes_bits.append(f"EOS {entry.eos_date}")
    if entry.error:
        notes_bits.append(entry.error)
    notes_bits.extend(entry.notes)
    notes_html = "; ".join(_html_escape(n) for n in notes_bits) or "&nbsp;"
    base_url_html = (
        f'<span class="muted">{_html_escape(entry.base_url)}</span>'
        if entry.base_url else "&nbsp;"
    )
    return (
        "<tr>"
        f'<td class="tool"><strong>{_html_escape(entry.tool)}</strong>'
        f'<br>{base_url_html}</td>'
        f'<td class="version">{_html_escape(entry.version) or "&mdash;"}</td>'
        f'<td class="edition">{_html_escape(entry.edition) or "&mdash;"}</td>'
        f'<td class="status"><span class="badge" style="color:{status_colour};'
        f'border-color:{status_colour}40;">{_html_escape(status)}</span></td>'
        f'<td class="notes">{notes_html}</td>'
        "</tr>"
    )


def render(report: InventoryReport) -> str:
    """Build the self-contained inventory HTML document."""
    rows = "".join(_row(e) for e in report.entries)
    if not report.entries:
        body_block = (
            '<p class="empty">No probes registered. This is a build error '
            '— please report.</p>'
        )
    else:
        body_block = (
            '<table class="inventory">'
            '<thead><tr>'
            '<th>Tool</th><th>Version</th><th>Edition</th>'
            '<th>Status</th><th>Notes</th>'
            '</tr></thead>'
            f'<tbody>{rows}</tbody>'
            '</table>'
        )
    summary = (
        f"{report.configured_count} of {len(report.entries)} tools configured"
    )
    css = """
    :root { color-scheme: dark; }
    body {
      margin: 0; padding: 32px;
      background: #0a0a0a; color: #fafafa;
      font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Inter", "Geist Sans", sans-serif;
    }
    h1 { font-size: 22px; font-weight: 600; margin: 0 0 4px; }
    .meta { color: #a1a1aa; font-size: 12px; margin-bottom: 24px; }
    .muted { color: #71717a; font-size: 11px; font-family: ui-monospace, "SF Mono", Menlo, monospace; }
    table.inventory {
      width: 100%; border-collapse: collapse;
      background: #131316; border: 1px solid #27272a; border-radius: 8px;
      overflow: hidden;
    }
    table.inventory th, table.inventory td {
      padding: 10px 14px; text-align: left;
      border-bottom: 1px solid #27272a; vertical-align: top;
    }
    table.inventory thead th {
      background: #18181c; color: #a1a1aa;
      font-weight: 600; font-size: 11px;
      text-transform: uppercase; letter-spacing: 0.06em;
    }
    table.inventory tbody tr:last-child td { border-bottom: none; }
    table.inventory tbody tr:hover { background: #1a1a1f; }
    td.tool { width: 220px; }
    td.version, td.edition { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 13px; }
    td.notes { color: #a1a1aa; font-size: 12px; }
    .badge {
      display: inline-block;
      padding: 3px 10px;
      border-radius: 999px;
      font-size: 11px;
      border: 1px solid; background: #18181c;
      font-variant-numeric: tabular-nums;
    }
    .empty { color: #a1a1aa; }
    @media print {
      body { background: #fff; color: #18181c; }
      table.inventory { background: #fff; border-color: #e4e4e7; }
      table.inventory thead th { background: #f4f4f5; color: #52525b; }
      table.inventory th, table.inventory td { border-bottom-color: #e4e4e7; }
      .badge { background: #fff; }
      td.notes { color: #52525b; }
      .muted { color: #71717a; }
    }
    """
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ciguard infrastructure inventory</title>
  <style>{css}</style>
</head>
<body>
  <h1>ciguard infrastructure inventory</h1>
  <div class="meta">{_html_escape(summary)} &middot; scanned {_html_escape(report.scan_timestamp)}</div>
  {body_block}
</body>
</html>
"""


def write_report(report: InventoryReport, output_path: Path) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render(report), encoding="utf-8")
    return output_path
