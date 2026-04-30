"""Tests for the v0.11.x interactive HTML reporter (Slice 14a Phase 1.1).

Asserts the structural invariants of the self-contained HTML output:

  - Document is well-formed HTML5 with the expected outer shape
  - The `ciguard-data` JSON blob round-trips through `json.loads`
  - The blob contains the expected meta, score, jobs, edges, findings
  - The vendored D3 v7 is inlined (no CDN reference at view-time)
  - Job-name slugs are stable + collision-free
  - GitLab `dependencies:` AND GitHub `needs:` both resolve to edges
  - Severity colour mapping is consistent
  - Service-identity field reserved (Slice 16/17 architecture commitment)

Phase 1.2+ additions to this file:
  - Click-to-side-panel asserts (DOM structure)
  - Diff-mode load asserts
  - Filter/focus interactive behaviour
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.models.pipeline import (  # noqa: E402
    Category,
    ComplianceMapping,
    Environment,
    Finding,
    Job,
    Pipeline,
    Report,
    RiskScore,
    Severity,
)
from ciguard.reporter import html_interactive  # noqa: E402


def _basic_report(*, jobs: list[Job], findings: list[Finding] | None = None) -> Report:
    return Report(
        pipeline_name="test-pipeline",
        platform="github-actions",
        scanner_version="0.11.0-test",
        pipeline=Pipeline(jobs=jobs),
        findings=findings or [],
        risk_score=RiskScore(
            overall=87.5, pipeline_integrity=90, identity_access=85,
            runner_security=90, artifact_handling=85, deployment_governance=80,
            supply_chain=95, grade="B",
        ),
    )


def _finding(rule_id: str, severity: Severity, location: str) -> Finding:
    return Finding(
        id=f"f-{rule_id}-{location}",
        rule_id=rule_id,
        name=f"Finding for {rule_id}",
        description="test finding",
        severity=severity,
        category=Category.IDENTITY_ACCESS,
        location=location,
        evidence="evidence string",
        remediation="fix it",
        compliance=ComplianceMapping(),
    )


# ===========================================================================
# Structural shape — the HTML wrapper
# ===========================================================================


def test_render_returns_well_formed_html5() -> None:
    report = _basic_report(jobs=[Job(name="build")])
    out = html_interactive.render(report)
    assert out.startswith("<!DOCTYPE html>")
    assert "<html lang=\"en\">" in out
    assert "</html>" in out
    assert "<script id=\"ciguard-data\" type=\"application/json\">" in out


def test_render_inlines_d3_not_cdn() -> None:
    """Self-contained-by-design: the vendored D3 is inlined; no
    `<script src=...>` reference loads JS from anywhere external at
    view-time. Single-file deliverable."""
    out = html_interactive.render(_basic_report(jobs=[Job(name="build")]))
    # Every <script> tag in the output must have no `src=` attribute —
    # they're all inline. (The D3 source itself contains URLs in comments,
    # which is fine; what matters is no runtime fetch.)
    script_tags = re.findall(r"<script[^>]*>", out)
    for tag in script_tags:
        assert "src=" not in tag, f"external script reference found: {tag}"
    # The vendored D3 banner comment ships with the file.
    assert "Mike Bostock" in out


def test_render_pipeline_name_in_title_and_header() -> None:
    report = _basic_report(jobs=[Job(name="build")])
    report.pipeline_name = "my-special-pipeline"
    out = html_interactive.render(report)
    assert "<title>ciguard — my-special-pipeline</title>" in out
    assert "my-special-pipeline" in out


def test_render_pipeline_name_html_escaped() -> None:
    """A pipeline_name containing HTML-special chars cannot inject."""
    report = _basic_report(jobs=[Job(name="build")])
    report.pipeline_name = "<script>alert(1)</script>"
    out = html_interactive.render(report)
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out


def test_render_grade_and_score_in_header() -> None:
    out = html_interactive.render(_basic_report(jobs=[Job(name="build")]))
    # Grade pill carries the letter as both class + text
    assert 'class="grade-pill B"' in out
    assert ">B</div>" in out
    # Score is rounded to integer in the header (compact display)
    assert ">88<" in out  # 87.5 rounds to 88
    assert ">/100<" in out


# ===========================================================================
# Embedded JSON — the data shape the viewer JS consumes
# ===========================================================================


def _extract_json(html: str) -> dict:
    """Pull the embedded ciguard-data blob out and `json.loads` it."""
    match = re.search(
        r'<script id="ciguard-data" type="application/json">(.*?)</script>',
        html, re.DOTALL,
    )
    assert match, "no ciguard-data script found"
    raw = match.group(1)
    # The reporter escapes `</` to `<\/` to defeat the close-tag breakout;
    # un-escape before parsing in tests.
    raw = raw.replace("<\\/", "</")
    return json.loads(raw)


def test_embedded_json_has_schema_version_and_meta() -> None:
    out = html_interactive.render(_basic_report(jobs=[Job(name="build")]))
    data = _extract_json(out)
    assert data["schema_version"] == 1
    assert data["meta"]["pipeline_name"] == "test-pipeline"
    assert data["meta"]["platform"] == "github-actions"
    assert data["meta"]["scanner_version"] == "0.11.0-test"
    assert data["meta"]["scan_timestamp"]


def test_embedded_json_reserves_service_identity_field() -> None:
    """Locked architecture commitment from the post-pivot audit-scope
    reference: every parsed pipeline must include a service_identity
    field for the Slice 16/17 multi-pipeline join. v1 leaves it null."""
    out = html_interactive.render(_basic_report(jobs=[Job(name="build")]))
    data = _extract_json(out)
    assert "service_identity" in data["meta"]
    assert data["meta"]["service_identity"] is None


def test_embedded_json_score_breakdown() -> None:
    out = html_interactive.render(_basic_report(jobs=[Job(name="build")]))
    score = _extract_json(out)["score"]
    assert score["overall"] == 87.5
    assert score["grade"] == "B"
    assert score["by_category"]["pipeline_integrity"] == 90
    assert score["by_category"]["supply_chain"] == 95


def test_embedded_json_jobs_emit_one_per_pipeline_job() -> None:
    jobs = [Job(name="build"), Job(name="test"), Job(name="deploy")]
    out = html_interactive.render(_basic_report(jobs=jobs))
    data = _extract_json(out)
    assert {j["name"] for j in data["jobs"]} == {"build", "test", "deploy"}


def test_jobs_get_stable_collision_free_slug_ids() -> None:
    """Two jobs with the same slugified name (e.g. "Build / Linux" and
    "build linux" both → "build-linux") must get distinct IDs."""
    jobs = [Job(name="Build / Linux"), Job(name="build linux"), Job(name="build-linux")]
    out = html_interactive.render(_basic_report(jobs=jobs))
    data = _extract_json(out)
    ids = [j["id"] for j in data["jobs"]]
    assert len(set(ids)) == len(ids), f"slug collision: {ids}"


def test_dependencies_and_needs_both_resolve_to_edges() -> None:
    jobs = [
        Job(name="build"),
        Job(name="lint", dependencies=["build"]),  # GitLab `dependencies:`
        Job(name="test", needs=["build"]),         # GitHub Actions `needs:`
        Job(name="deploy", needs=[{"job": "test"}]),  # GitLab `needs:` dict form
    ]
    out = html_interactive.render(_basic_report(jobs=jobs))
    data = _extract_json(out)
    edge_pairs = {(e["from"], e["to"]) for e in data["edges"]}
    name_to_id = {j["name"]: j["id"] for j in data["jobs"]}
    assert (name_to_id["build"], name_to_id["lint"]) in edge_pairs
    assert (name_to_id["build"], name_to_id["test"]) in edge_pairs
    assert (name_to_id["test"], name_to_id["deploy"]) in edge_pairs


def test_unknown_dep_names_silently_dropped() -> None:
    """A `needs:` reference to a job that doesn't exist (e.g. typo) must
    not crash the renderer. Edge is silently dropped."""
    jobs = [Job(name="build", needs=["does-not-exist"])]
    out = html_interactive.render(_basic_report(jobs=jobs))
    data = _extract_json(out)
    assert data["edges"] == []


def test_findings_attach_to_job_by_location_match() -> None:
    findings = [
        _finding("X-1", Severity.HIGH, "build"),         # bare job-name match
        _finding("X-2", Severity.MEDIUM, "build:42"),    # job:line match
        _finding("X-3", Severity.LOW, "deploy"),         # different job
        _finding("X-4", Severity.INFO, "global"),        # not a job
    ]
    jobs = [Job(name="build"), Job(name="deploy")]
    out = html_interactive.render(_basic_report(jobs=jobs, findings=findings))
    data = _extract_json(out)
    by_name = {j["name"]: j for j in data["jobs"]}
    assert {f["rule_id"] for f in by_name["build"]["findings"]} == {"X-1", "X-2"}
    assert {f["rule_id"] for f in by_name["deploy"]["findings"]} == {"X-3"}
    # `global` finding lands in the top-level `findings` list (side panel
    # use), not on any job.
    assert "X-4" in {f["rule_id"] for f in data["findings"]}


def test_highest_severity_picks_worst_per_job() -> None:
    findings = [
        _finding("X-1", Severity.LOW, "build"),
        _finding("X-2", Severity.CRITICAL, "build"),
        _finding("X-3", Severity.MEDIUM, "build"),
    ]
    jobs = [Job(name="build")]
    out = html_interactive.render(_basic_report(jobs=jobs, findings=findings))
    data = _extract_json(out)
    assert data["jobs"][0]["highest_severity"] == "Critical"


def test_no_findings_means_no_severity_label() -> None:
    out = html_interactive.render(_basic_report(jobs=[Job(name="build")]))
    data = _extract_json(out)
    assert data["jobs"][0]["highest_severity"] == ""


def test_environment_metadata_carried_through() -> None:
    jobs = [
        Job(
            name="deploy",
            environment=Environment(name="prod", deployment_tier="production"),
        ),
    ]
    out = html_interactive.render(_basic_report(jobs=jobs))
    data = _extract_json(out)
    j = data["jobs"][0]
    assert j["environment"] == "prod"
    assert j["targets_production"] is True
    assert j["is_deploy"] is True


# ===========================================================================
# Side-panel data — full finding list
# ===========================================================================


def test_findings_list_sorted_by_severity_descending() -> None:
    findings = [
        _finding("X-1", Severity.LOW, "build"),
        _finding("X-2", Severity.CRITICAL, "build"),
        _finding("X-3", Severity.HIGH, "build"),
        _finding("X-4", Severity.INFO, "build"),
    ]
    jobs = [Job(name="build")]
    out = html_interactive.render(_basic_report(jobs=jobs, findings=findings))
    data = _extract_json(out)
    severities = [f["severity"] for f in data["findings"]]
    assert severities == ["Critical", "High", "Low", "Info"]


def test_findings_carry_remediation_for_side_panel() -> None:
    """Phase 1.2 click-to-side-panel needs remediation in the data;
    ensure Phase 1.1 already includes it (no schema bump later)."""
    findings = [_finding("X-1", Severity.HIGH, "build")]
    jobs = [Job(name="build")]
    out = html_interactive.render(_basic_report(jobs=jobs, findings=findings))
    data = _extract_json(out)
    assert data["findings"][0]["remediation"] == "fix it"


def test_findings_carry_fingerprint() -> None:
    """Fingerprint is needed for diff-mode (Phase 1.2). Carry it now."""
    findings = [_finding("X-1", Severity.HIGH, "build")]
    jobs = [Job(name="build")]
    out = html_interactive.render(_basic_report(jobs=jobs, findings=findings))
    data = _extract_json(out)
    assert data["findings"][0]["fingerprint"]


# ===========================================================================
# Image pin-status detection (Slice 14c preview baked into 14a data)
# ===========================================================================


@pytest.mark.parametrize("image,expected", [
    (None, ""),
    ("alpine:latest", "mutable"),
    ("alpine", "mutable"),
    ("alpine:stable", "mutable"),
    ("nginx:edge", "mutable"),
    ("ubuntu:main", "mutable"),
    ("python:3.11.4", "tag"),
    ("python:3.11.4-slim", "tag"),
    ("ghcr.io/org/img:1.2.3", "tag"),
    ("python@sha256:" + "a" * 64, "digest"),
    ("ghcr.io/org/img:1.2.3@sha256:" + "b" * 64, "digest"),
])
def test_image_pin_status_classification(image: str | None, expected: str) -> None:
    assert html_interactive._image_pin_status(image) == expected


def test_pin_status_carried_through_to_node_data() -> None:
    jobs = [
        Job(name="build", image="python@sha256:" + "a" * 64),
        Job(name="test", image="python:3.11"),
        Job(name="deploy", image="alpine:latest"),
    ]
    out = html_interactive.render(_basic_report(jobs=jobs))
    data = _extract_json(out)
    by_name = {j["name"]: j for j in data["jobs"]}
    assert by_name["build"]["pin_status"] == "digest"
    assert by_name["test"]["pin_status"] == "tag"
    assert by_name["deploy"]["pin_status"] == "mutable"


# ===========================================================================
# Per-severity counts on each job (badge population)
# ===========================================================================


def test_findings_by_severity_per_job() -> None:
    findings = [
        _finding("X-1", Severity.CRITICAL, "build"),
        _finding("X-2", Severity.HIGH, "build"),
        _finding("X-3", Severity.HIGH, "build"),
        _finding("X-4", Severity.LOW, "build"),
    ]
    jobs = [Job(name="build")]
    out = html_interactive.render(_basic_report(jobs=jobs, findings=findings))
    data = _extract_json(out)
    counts = data["jobs"][0]["findings_by_severity"]
    assert counts == {"Critical": 1, "High": 2, "Low": 1}


# ===========================================================================
# Header / sidebar / legend HTML scaffold
# ===========================================================================


def test_header_renders_severity_chips_for_every_severity() -> None:
    out = html_interactive.render(_basic_report(jobs=[Job(name="build")]))
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        assert f"0 {sev}" in out


def test_findings_sidebar_present() -> None:
    out = html_interactive.render(_basic_report(jobs=[Job(name="build")]))
    assert 'id="side-panel"' in out
    assert 'id="findings-list"' in out
    assert 'class="filter-btn' in out
    assert 'data-sev="Critical"' in out


def test_legend_present_with_pin_vocabulary() -> None:
    out = html_interactive.render(_basic_report(jobs=[Job(name="build")]))
    assert "DIGEST" in out
    assert "MUTABLE" in out
    assert "PROD target" in out
    assert "Manual gate" in out


# ===========================================================================
# write_report file-system entry point
# ===========================================================================


def test_write_report_creates_parent_dir(tmp_path: Path) -> None:
    out = tmp_path / "deep" / "nested" / "map.html"
    written = html_interactive.write_report(
        _basic_report(jobs=[Job(name="build")]), out,
    )
    assert written == out
    assert out.exists()
    assert out.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
