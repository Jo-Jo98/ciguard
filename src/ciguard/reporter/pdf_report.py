"""
ciguard PDF report generator.

Produces a professional multi-section PDF report using ReportLab.
Requires: pip install reportlab

Sections:
  1. Cover page  — branding, scan date, target, grade badge
  2. Executive Summary — risk score dashboard + key metrics
  3. Category Scores — bar chart per category
  4. Pipeline Map — stage flow
  5. Findings by Severity — detailed findings table
  6. Policy Report — pass/fail per policy (if present)
  7. Compliance Mapping — ISO 27001 / SOC 2 / NIST references
  8. Remediation Roadmap — prioritised action list
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import List, Optional

from ..models.pipeline import Finding, Report, Severity

# Lazy import so the module can be imported without reportlab installed
# (graceful degradation — PDFReporter.write() raises ImportError if missing)
try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm, mm
    from reportlab.platypus import (
        HRFlowable,
        KeepTogether,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    _REPORTLAB_AVAILABLE = True
except ImportError:
    _REPORTLAB_AVAILABLE = False


# ---------------------------------------------------------------------------
# Brand colours
# ---------------------------------------------------------------------------

_DARK_BG    = colors.HexColor("#0f1117")
_ACCENT     = colors.HexColor("#6366f1")   # indigo
_CRITICAL   = colors.HexColor("#ef4444")
_HIGH       = colors.HexColor("#f97316")
_MEDIUM     = colors.HexColor("#eab308")
_LOW        = colors.HexColor("#22c55e")
_INFO_C     = colors.HexColor("#3b82f6")
_PASS_GREEN = colors.HexColor("#16a34a")
_FAIL_RED   = colors.HexColor("#dc2626")
_LIGHT_GREY = colors.HexColor("#f3f4f6")
_MID_GREY   = colors.HexColor("#d1d5db")
_DARK_TEXT  = colors.HexColor("#111827")
_SUB_TEXT   = colors.HexColor("#6b7280")

_SEV_COLOUR = {
    "Critical": _CRITICAL,
    "High":     _HIGH,
    "Medium":   _MEDIUM,
    "Low":      _LOW,
    "Info":     _INFO_C,
}

_GRADE_COLOUR = {
    "A": colors.HexColor("#16a34a"),
    "B": colors.HexColor("#22c55e"),
    "C": colors.HexColor("#eab308"),
    "D": colors.HexColor("#f97316"),
    "F": colors.HexColor("#ef4444"),
}


class PDFReporter:
    """Generates a professional multi-page PDF report."""

    def write(self, report: Report, output_path: Path) -> None:
        if not _REPORTLAB_AVAILABLE:
            raise ImportError(
                "reportlab is required for PDF export. "
                "Install it with: pip install reportlab"
            )

        styles = self._build_styles()
        story  = []

        story += self._cover_page(report, styles)
        story += self._executive_summary(report, styles)
        story += self._category_scores(report, styles)
        story += self._pipeline_map(report, styles)
        story += self._findings_table(report, styles)
        if report.policy_report:
            story += self._policy_section(report, styles)
        story += self._compliance_section(report, styles)
        story += self._remediation_roadmap(report, styles)

        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm,
            topMargin=2*cm, bottomMargin=2*cm,
            title=f"ciguard Report — {report.pipeline_name}",
            author="ciguard",
        )
        doc.build(story, onFirstPage=self._add_header_footer,
                  onLaterPages=self._add_header_footer)

    # ------------------------------------------------------------------
    # Cover page
    # ------------------------------------------------------------------

    def _cover_page(self, report: Report, styles) -> list:
        elements = []
        elements.append(Spacer(1, 4*cm))

        elements.append(Paragraph("ciguard", styles["CoverTitle"]))
        elements.append(Paragraph("CI/CD Pipeline Security Audit Report",
                                  styles["CoverSubtitle"]))
        elements.append(Spacer(1, 1*cm))

        # Divider
        elements.append(HRFlowable(width="100%", thickness=2, color=_ACCENT))
        elements.append(Spacer(1, 1*cm))

        # Pipeline info
        elements.append(Paragraph(
            f"<b>Pipeline:</b>  {_esc(report.pipeline_name)}", styles["CoverInfo"]
        ))
        scan_dt = report.scan_timestamp[:19].replace("T", "  ")
        elements.append(Paragraph(
            f"<b>Scan Date:</b>  {scan_dt} UTC", styles["CoverInfo"]
        ))
        elements.append(Paragraph(
            f"<b>Jobs / Stages:</b>  "
            f"{len(report.pipeline.jobs)} jobs, {len(report.pipeline.stages)} stages",
            styles["CoverInfo"]
        ))
        elements.append(Spacer(1, 2*cm))

        # Grade badge (large table cell)
        score = report.risk_score
        gc = _GRADE_COLOUR.get(score.grade, colors.grey)
        grade_table = Table(
            [[
                Paragraph(f"<b>{score.grade}</b>", styles["GradeLetter"]),
                Paragraph(
                    f"<b>{score.overall}/100</b><br/><font size=10 color='grey'>Risk Score</font>",
                    styles["GradeScore"]
                ),
            ]],
            colWidths=[3*cm, 6*cm],
            rowHeights=[2.5*cm],
        )
        grade_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), gc),
            ("BACKGROUND", (1, 0), (1, 0), _LIGHT_GREY),
            ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
            ("ROUNDEDCORNERS", [6]),
            ("BOX",        (0, 0), (-1, -1), 0, colors.white),
        ]))
        elements.append(grade_table)
        elements.append(PageBreak())
        return elements

    # ------------------------------------------------------------------
    # Executive summary
    # ------------------------------------------------------------------

    def _executive_summary(self, report: Report, styles) -> list:
        elements = [Paragraph("Executive Summary", styles["H1"]),
                    HRFlowable(width="100%", thickness=1, color=_MID_GREY),
                    Spacer(1, 0.4*cm)]

        sev_data = report.summary.get("by_severity", {})
        crits = sev_data.get("Critical", 0)
        highs = sev_data.get("High", 0)
        meds  = sev_data.get("Medium", 0)
        lows  = sev_data.get("Low", 0)
        total = report.summary.get("total", 0)

        summary_table = Table(
            [
                ["Total Findings", "Critical", "High", "Medium", "Low"],
                [str(total), str(crits), str(highs), str(meds), str(lows)],
            ],
            colWidths=[3.5*cm, 3*cm, 3*cm, 3*cm, 3*cm],
        )
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), _DARK_BG),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 10),
            ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_LIGHT_GREY, colors.white]),
            ("BACKGROUND", (1, 1), (1, 1), colors.HexColor("#fee2e2")),
            ("BACKGROUND", (2, 1), (2, 1), colors.HexColor("#ffedd5")),
            ("GRID",       (0, 0), (-1, -1), 0.5, _MID_GREY),
            ("ROWHEIGHT",  (0, 0), (-1, -1), 0.7*cm),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 0.5*cm))

        # Narrative
        if crits > 0:
            verdict = (
                f"<b>CRITICAL RISK</b>: The pipeline has {crits} critical finding(s) "
                "that require immediate remediation before deployment."
            )
            colour = "#fee2e2"
        elif highs > 0:
            verdict = (
                f"<b>HIGH RISK</b>: The pipeline has {highs} high-severity finding(s) "
                "that should be addressed urgently."
            )
            colour = "#ffedd5"
        else:
            verdict = (
                "The pipeline has no critical or high-severity findings. "
                "Address remaining findings as part of your normal sprint cycle."
            )
            colour = "#dcfce7"

        verdict_table = Table(
            [[Paragraph(verdict, styles["Normal"])]],
            colWidths=[16*cm],
        )
        verdict_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), colors.HexColor(colour)),
            ("BOX",        (0, 0), (0, 0), 1, _MID_GREY),
            ("LEFTPADDING", (0, 0), (0, 0), 10),
            ("RIGHTPADDING",(0, 0), (0, 0), 10),
            ("TOPPADDING",  (0, 0), (0, 0), 8),
            ("BOTTOMPADDING",(0, 0),(0, 0), 8),
        ]))
        elements.append(verdict_table)
        elements.append(Spacer(1, 0.5*cm))
        return elements

    # ------------------------------------------------------------------
    # Category scores
    # ------------------------------------------------------------------

    def _category_scores(self, report: Report, styles) -> list:
        elements = [Paragraph("Risk Score by Category", styles["H2"]),
                    Spacer(1, 0.3*cm)]

        score = report.risk_score
        cats = [
            ("Pipeline Integrity",  score.pipeline_integrity,  "25%"),
            ("Identity & Access",   score.identity_access,     "20%"),
            ("Runner Security",     score.runner_security,     "7.5%"),
            ("Artifact Handling",   score.artifact_handling,   "7.5%"),
            ("Deployment Gov.",     score.deployment_governance,"20%"),
            ("Supply Chain",        score.supply_chain,        "20%"),
        ]

        rows = [["Category", "Score", "Weight", "Bar"]]
        for name, s, weight in cats:
            filled = int(s / 5)   # 0-20 chars
            bar = "█" * filled + "░" * (20 - filled)
            bar_colour = _PASS_GREEN if s >= 75 else (_MEDIUM if s >= 50 else _FAIL_RED)
            rows.append([
                name, f"{s:.1f}/100", weight,
                Paragraph(f'<font color="{bar_colour.hexval()}">{bar}</font>',
                          styles["Mono"]),
            ])

        t = Table(rows, colWidths=[4.5*cm, 2.5*cm, 2*cm, 7*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), _DARK_BG),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_LIGHT_GREY, colors.white]),
            ("GRID",       (0, 0), (-1, -1), 0.5, _MID_GREY),
            ("ALIGN",      (1, 0), (2, -1), "CENTER"),
            ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
            ("ROWHEIGHT",  (0, 0), (-1, -1), 0.65*cm),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 0.8*cm))
        return elements

    # ------------------------------------------------------------------
    # Pipeline map
    # ------------------------------------------------------------------

    def _pipeline_map(self, report: Report, styles) -> list:
        stages = report.pipeline.stages
        if not stages:
            return []

        elements = [Paragraph("Pipeline Stage Map", styles["H2"]),
                    Spacer(1, 0.3*cm)]

        # Find worst severity per stage
        stage_severity: dict = {}
        for f in report.findings:
            job = next((j for j in report.pipeline.jobs if j.name == f.location), None)
            if job:
                stage = job.stage or "test"
                if stage not in stage_severity:
                    stage_severity[stage] = f.severity.value
                else:
                    order = ["Critical", "High", "Medium", "Low", "Info"]
                    if order.index(f.severity.value) < order.index(stage_severity[stage]):
                        stage_severity[stage] = f.severity.value

        cells = []
        for i, stage in enumerate(stages):
            sev = stage_severity.get(stage)
            bg = _SEV_COLOUR.get(sev, _PASS_GREEN) if sev else _PASS_GREEN
            cells.append(Paragraph(
                f'<font color="white"><b>{_esc(stage)}</b></font>',
                styles["StageLabel"]
            ))

        col_width = max(2*cm, min(4*cm, 16*cm / max(len(stages), 1)))
        row = [cells]
        t = Table(row, colWidths=[col_width] * len(stages))
        style_cmds = [
            ("ALIGN",   (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",  (0, 0), (-1, -1), "MIDDLE"),
            ("ROWHEIGHT",(0, 0),(-1, -1), 1*cm),
            ("FONTSIZE",(0, 0), (-1, -1), 9),
        ]
        for i, stage in enumerate(stages):
            sev = stage_severity.get(stage)
            bg = _SEV_COLOUR.get(sev, _PASS_GREEN) if sev else _PASS_GREEN
            style_cmds.append(("BACKGROUND", (i, 0), (i, 0), bg))
            if i < len(stages) - 1:
                style_cmds.append(("LINEAFTER", (i, 0), (i, 0), 2, colors.white))

        t.setStyle(TableStyle(style_cmds))
        elements.append(t)
        elements.append(Paragraph(
            "Stage colours indicate worst finding severity (green = clean)",
            styles["Caption"]
        ))
        elements.append(Spacer(1, 0.8*cm))
        return elements

    # ------------------------------------------------------------------
    # Findings table
    # ------------------------------------------------------------------

    def _findings_table(self, report: Report, styles) -> list:
        elements = [PageBreak(),
                    Paragraph("Security Findings", styles["H1"]),
                    HRFlowable(width="100%", thickness=1, color=_MID_GREY),
                    Spacer(1, 0.3*cm)]

        if not report.findings:
            elements.append(Paragraph("No findings detected.", styles["Normal"]))
            return elements

        for sev in Severity:
            findings = report.findings_by_severity(sev)
            if not findings:
                continue

            sev_col = _SEV_COLOUR.get(sev.value, colors.grey)
            elements.append(KeepTogether([
                Paragraph(
                    f'<font color="{sev_col.hexval()}"><b>{sev.value} '
                    f'({len(findings)})</b></font>',
                    styles["H3"]
                ),
                Spacer(1, 0.2*cm),
            ]))

            for f in findings:
                row_elements = [
                    Paragraph(
                        f"<b>[{f.rule_id}]</b>  {_esc(f.name)}  "
                        f"<font color='grey'>@ {_esc(f.location)}</font>",
                        styles["FindingTitle"]
                    ),
                    Paragraph(_esc(f.description), styles["Small"]),
                ]
                if f.evidence:
                    row_elements.append(
                        Paragraph(f"<b>Evidence:</b> <i>{_esc(f.evidence[:200])}</i>",
                                  styles["Small"])
                    )
                if f.remediation:
                    row_elements.append(
                        Paragraph(f"<b>Fix:</b> {_esc(f.remediation[:300])}",
                                  styles["Small"])
                    )

                box = Table([[row_elements]], colWidths=[16*cm])
                box.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (0, 0),
                     colors.HexColor("#fef2f2") if sev.value == "Critical"
                     else colors.HexColor("#fff7ed") if sev.value == "High"
                     else _LIGHT_GREY),
                    ("BOX",        (0, 0), (0, 0), 0.5, sev_col),
                    ("LEFTPADDING", (0, 0), (0, 0), 8),
                    ("TOPPADDING",  (0, 0), (0, 0), 6),
                    ("BOTTOMPADDING",(0, 0),(0, 0), 6),
                ]))
                elements.append(box)
                elements.append(Spacer(1, 0.2*cm))

        return elements

    # ------------------------------------------------------------------
    # Policy section
    # ------------------------------------------------------------------

    def _policy_section(self, report: Report, styles) -> list:
        pr = report.policy_report
        elements = [PageBreak(),
                    Paragraph("Policy Compliance", styles["H1"]),
                    HRFlowable(width="100%", thickness=1, color=_MID_GREY),
                    Spacer(1, 0.3*cm)]

        summary_colour = _PASS_GREEN if pr.failed == 0 else _FAIL_RED
        elements.append(Paragraph(
            f"<b>{pr.passed}</b> passed  /  "
            f'<font color="{summary_colour.hexval()}"><b>{pr.failed}</b></font> failed  '
            f"({pr.pass_rate:.0f}% pass rate)",
            styles["PolicySummary"]
        ))
        elements.append(Spacer(1, 0.4*cm))

        rows = [["ID", "Policy", "Severity", "Status", "Evidence"]]
        for r in pr.results:
            status = "PASS" if r.passed else "FAIL"
            sev_col = _POLICY_SEV_COLOUR_RL.get(r.policy.severity.value, colors.grey)
            rows.append([
                r.policy.id,
                Paragraph(_esc(r.policy.name), styles["Small"]),
                r.policy.severity.value.upper(),
                status,
                Paragraph(_esc(r.evidence[:150]), styles["Small"]),
            ])

        t = Table(rows, colWidths=[2.2*cm, 4.5*cm, 2*cm, 1.5*cm, 5.8*cm])
        row_styles = [
            ("BACKGROUND", (0, 0), (-1, 0), _DARK_BG),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 8),
            ("GRID",       (0, 0), (-1, -1), 0.5, _MID_GREY),
            ("VALIGN",     (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_LIGHT_GREY, colors.white]),
        ]
        for i, r in enumerate(pr.results, start=1):
            if not r.passed:
                row_styles.append(("BACKGROUND", (3, i), (3, i),
                                   colors.HexColor("#fee2e2")))
                row_styles.append(("TEXTCOLOR",  (3, i), (3, i), _FAIL_RED))
                row_styles.append(("FONTNAME",   (3, i), (3, i), "Helvetica-Bold"))
            else:
                row_styles.append(("TEXTCOLOR",  (3, i), (3, i), _PASS_GREEN))
                row_styles.append(("FONTNAME",   (3, i), (3, i), "Helvetica-Bold"))

        t.setStyle(TableStyle(row_styles))
        elements.append(t)
        elements.append(Spacer(1, 0.5*cm))
        return elements

    # ------------------------------------------------------------------
    # Compliance mapping
    # ------------------------------------------------------------------

    def _compliance_section(self, report: Report, styles) -> list:
        elements = [PageBreak(),
                    Paragraph("Compliance Mapping", styles["H1"]),
                    HRFlowable(width="100%", thickness=1, color=_MID_GREY),
                    Spacer(1, 0.3*cm),
                    Paragraph(
                        "Findings mapped to ISO 27001, SOC 2, and NIST CSF controls.",
                        styles["Normal"]
                    ),
                    Spacer(1, 0.4*cm)]

        # Aggregate compliance references from all findings
        iso_refs: set = set()
        soc2_refs: set = set()
        nist_refs: set = set()
        for f in report.findings:
            iso_refs.update(f.compliance.iso_27001)
            soc2_refs.update(f.compliance.soc2)
            nist_refs.update(f.compliance.nist)

        if not iso_refs and not soc2_refs and not nist_refs:
            elements.append(Paragraph("No compliance data — no findings.", styles["Normal"]))
            return elements

        frameworks = [
            ("ISO 27001", sorted(iso_refs)),
            ("SOC 2",     sorted(soc2_refs)),
            ("NIST CSF",  sorted(nist_refs)),
        ]
        rows = [["Framework", "Controls Impacted"]]
        for name, refs in frameworks:
            if refs:
                rows.append([name, ", ".join(refs)])

        t = Table(rows, colWidths=[4*cm, 12*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), _DARK_BG),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 9),
            ("GRID",       (0, 0), (-1, -1), 0.5, _MID_GREY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_LIGHT_GREY, colors.white]),
            ("VALIGN",     (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING",(0, 0),(-1, -1), 6),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 0.5*cm))
        return elements

    # ------------------------------------------------------------------
    # Remediation roadmap
    # ------------------------------------------------------------------

    def _remediation_roadmap(self, report: Report, styles) -> list:
        elements = [PageBreak(),
                    Paragraph("Remediation Roadmap", styles["H1"]),
                    HRFlowable(width="100%", thickness=1, color=_MID_GREY),
                    Spacer(1, 0.3*cm),
                    Paragraph(
                        "Prioritised actions ordered by severity. Address Critical "
                        "and High findings before the next production deployment.",
                        styles["Normal"]
                    ),
                    Spacer(1, 0.4*cm)]

        sorted_findings = report.sorted_findings()
        if not sorted_findings:
            elements.append(Paragraph("No remediation actions required.", styles["Normal"]))
            return elements

        rows = [["#", "Severity", "Rule", "Finding", "Action"]]
        for i, f in enumerate(sorted_findings, 1):
            sev_col = _SEV_COLOUR.get(f.severity.value, colors.grey)
            rows.append([
                str(i),
                Paragraph(
                    f'<font color="{sev_col.hexval()}"><b>{f.severity.value}</b></font>',
                    styles["Small"]
                ),
                f.rule_id,
                Paragraph(_esc(f.name), styles["Small"]),
                Paragraph(_esc(f.remediation[:200]), styles["Small"]),
            ])

        t = Table(rows, colWidths=[0.7*cm, 2*cm, 2*cm, 4*cm, 7.3*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), _DARK_BG),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 8),
            ("GRID",       (0, 0), (-1, -1), 0.5, _MID_GREY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_LIGHT_GREY, colors.white]),
            ("VALIGN",     (0, 0), (-1, -1), "TOP"),
            ("ALIGN",      (0, 0), (0, -1), "CENTER"),
        ]))
        elements.append(t)
        return elements

    # ------------------------------------------------------------------
    # Header / footer on every page
    # ------------------------------------------------------------------

    @staticmethod
    def _add_header_footer(canvas, doc):
        canvas.saveState()
        w, h = A4

        # Header bar
        canvas.setFillColor(_DARK_BG)
        canvas.rect(0, h - 1.2*cm, w, 1.2*cm, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(2*cm, h - 0.8*cm, "ciguard — CI/CD Security Audit")
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#9ca3af"))
        canvas.drawRightString(w - 2*cm, h - 0.8*cm, "CONFIDENTIAL")

        # Footer
        canvas.setFillColor(_SUB_TEXT)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(2*cm, 0.7*cm, f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC")
        canvas.drawRightString(w - 2*cm, 0.7*cm, f"Page {doc.page}")
        canvas.restoreState()

    # ------------------------------------------------------------------
    # Styles
    # ------------------------------------------------------------------

    @staticmethod
    def _build_styles():
        base = getSampleStyleSheet()
        styles = {}

        def add(name, **kw):
            styles[name] = ParagraphStyle(name, **kw)

        add("CoverTitle",   fontName="Helvetica-Bold", fontSize=36,
            textColor=_DARK_TEXT, alignment=TA_CENTER, spaceAfter=6)
        add("CoverSubtitle",fontName="Helvetica", fontSize=16,
            textColor=_SUB_TEXT, alignment=TA_CENTER, spaceAfter=4)
        add("CoverInfo",    fontName="Helvetica", fontSize=12,
            textColor=_DARK_TEXT, spaceAfter=4)
        add("GradeLetter",  fontName="Helvetica-Bold", fontSize=40,
            textColor=colors.white, alignment=TA_CENTER)
        add("GradeScore",   fontName="Helvetica-Bold", fontSize=18,
            textColor=_DARK_TEXT, alignment=TA_CENTER)
        add("H1",           fontName="Helvetica-Bold", fontSize=16,
            textColor=_DARK_TEXT, spaceBefore=10, spaceAfter=4)
        add("H2",           fontName="Helvetica-Bold", fontSize=13,
            textColor=_DARK_TEXT, spaceBefore=8, spaceAfter=3)
        add("H3",           fontName="Helvetica-Bold", fontSize=11,
            textColor=_DARK_TEXT, spaceBefore=6, spaceAfter=2)
        add("Normal",       fontName="Helvetica", fontSize=10,
            textColor=_DARK_TEXT, spaceAfter=4, leading=14)
        add("Small",        fontName="Helvetica", fontSize=8,
            textColor=_DARK_TEXT, spaceAfter=2, leading=11)
        add("Caption",      fontName="Helvetica", fontSize=8,
            textColor=_SUB_TEXT, spaceAfter=4)
        add("FindingTitle", fontName="Helvetica-Bold", fontSize=9,
            textColor=_DARK_TEXT, spaceAfter=2)
        add("Mono",         fontName="Courier", fontSize=8,
            textColor=_DARK_TEXT)
        add("PolicySummary",fontName="Helvetica-Bold", fontSize=12,
            textColor=_DARK_TEXT, spaceAfter=4)
        add("StageLabel",   fontName="Helvetica-Bold", fontSize=9,
            textColor=colors.white, alignment=TA_CENTER)
        return styles


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_POLICY_SEV_COLOUR_RL = {
    "critical": _CRITICAL,
    "high":     _HIGH,
    "medium":   _MEDIUM,
    "low":      _LOW,
}


def _esc(text: str) -> str:
    """Escape XML special chars for ReportLab Paragraph."""
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("'", "&#39;"))
