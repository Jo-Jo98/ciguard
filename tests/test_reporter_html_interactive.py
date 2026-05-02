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
    # Case-insensitive `[Ss]` matching closes a `py/bad-tag-filter` alert;
    # we ship lowercase but the regex should still resist UPPERCASE inputs.
    script_tags = re.findall(r"<[Ss][Cc][Rr][Ii][Pp][Tt][^>]*>", out)
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
    # Slice 14c — extended mutable-tag set (synced with SCA-PIN-002).
    ("nginx:master", "mutable"),
    ("nginx:prod", "mutable"),
    ("nginx:production", "mutable"),
    ("nginx:dev", "mutable"),
    ("nginx:development", "mutable"),
    ("nginx:nightly", "mutable"),
    ("nginx:LATEST", "mutable"),         # case-insensitive
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


def test_visualiser_classifier_is_shared_with_sca_module() -> None:
    """Drift check — the visualiser must use the SAME classifier the SCA
    rule uses, otherwise a node coloured 'mutable' might not produce a
    SCA-PIN-002 finding (and vice versa). Importing through the reporter
    module name is fine; pointing at a local copy is the bug we're
    guarding against."""
    from ciguard.analyzer.sca.image_extractor import classify_pin_status
    assert html_interactive._image_pin_status is classify_pin_status


# ===========================================================================
# Pin-discipline aggregate (Slice 14c — header strip + embedded JSON)
# ===========================================================================


def test_pin_discipline_aggregate_in_embedded_json() -> None:
    jobs = [
        Job(name="a", image="python@sha256:" + "a" * 64),
        Job(name="b", image="python@sha256:" + "b" * 64),
        Job(name="c", image="python:3.11"),
        Job(name="d", image="alpine:latest"),
        Job(name="e", image="alpine:edge"),
        Job(name="f", image="alpine:nightly"),
        Job(name="no-image"),
    ]
    out = html_interactive.render(_basic_report(jobs=jobs))
    data = _extract_json(out)
    pin = data["score"]["pin_discipline"]
    assert pin == {"digest": 2, "tag": 1, "mutable": 3}


def test_pin_discipline_strip_renders_when_images_present() -> None:
    jobs = [Job(name="a", image="alpine:latest"), Job(name="b", image="python:3.11")]
    out = html_interactive.render(_basic_report(jobs=jobs))
    assert 'class="summary-strip pin-strip"' in out
    assert "pin-chip mutable" in out
    assert "pin-chip tag" in out


def test_pin_discipline_strip_omitted_when_no_images() -> None:
    out = html_interactive.render(_basic_report(jobs=[Job(name="a"), Job(name="b")]))
    assert 'class="summary-strip pin-strip"' not in out


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
# Phase 1.3 — click-to-job-detail panel + YAML + remediation + search
# ===========================================================================


def test_per_job_yaml_excerpt_renders() -> None:
    """Each job carries a re-serialised YAML excerpt for the detail panel."""
    jobs = [
        Job(
            name="build",
            stage="build",
            image="python:3.11",
            script=["pip install .", "pytest"],
        ),
    ]
    out = html_interactive.render(_basic_report(jobs=jobs))
    data = _extract_json(out)
    yaml_text = data["jobs"][0]["yaml"]
    assert "name: build" in yaml_text
    assert "image: python:3.11" in yaml_text
    assert "stage: build" in yaml_text
    assert "pip install" in yaml_text


def test_yaml_excerpt_strips_default_empty_fields() -> None:
    """No `dependencies: []` / `tags: []` walls — the excerpt stays
    focused on what's actually configured."""
    out = html_interactive.render(_basic_report(jobs=[Job(name="build")]))
    data = _extract_json(out)
    yaml_text = data["jobs"][0]["yaml"]
    # Empty defaults from the model shouldn't appear
    assert "dependencies: []" not in yaml_text
    assert "tags: []" not in yaml_text
    assert "variables: {}" not in yaml_text


def test_job_detail_panel_scaffolding_present() -> None:
    """The HTML wrapper ships both panels — global findings + job detail.
    JS toggles between them on click."""
    out = html_interactive.render(_basic_report(jobs=[Job(name="build")]))
    assert 'id="findings-view"' in out
    assert 'id="job-detail"' in out
    assert 'id="back-to-findings"' in out
    assert 'id="yaml-block"' in out
    assert 'id="gates-summary"' in out
    assert 'id="findings-on-job"' in out


def test_findings_search_input_present() -> None:
    """Phase 1.3 filter polish: text-search input above severity filter."""
    out = html_interactive.render(_basic_report(jobs=[Job(name="build")]))
    assert 'id="findings-search"' in out
    assert 'placeholder="Search rule id, message, location' in out


def test_job_with_environment_serialises_full_block() -> None:
    """The Environment sub-model should round-trip through the YAML
    so an auditor sees the whole environment block in the detail panel."""
    from ciguard.models.pipeline import Environment
    jobs = [
        Job(
            name="deploy",
            environment=Environment(name="prod", deployment_tier="production"),
        ),
    ]
    out = html_interactive.render(_basic_report(jobs=jobs))
    data = _extract_json(out)
    yaml_text = data["jobs"][0]["yaml"]
    assert "environment:" in yaml_text
    assert "name: prod" in yaml_text
    assert "production" in yaml_text


def test_render_job_yaml_handles_minimal_job() -> None:
    """A job with only a name shouldn't emit walls of empty defaults."""
    yaml_text = html_interactive._render_job_yaml(Job(name="bare-job"))
    assert "name: bare-job" in yaml_text
    # No dump of empty lists / dicts / None values
    assert "[]" not in yaml_text
    assert "{}" not in yaml_text or yaml_text.count("\n") <= 2


# ===========================================================================
# Phase 1.4 — print mode + a11y + diff mode scaffolding
# ===========================================================================


def test_print_mode_css_present() -> None:
    """Print stylesheet hides interactive controls + forces light mode."""
    out = html_interactive.render(_basic_report(jobs=[Job(name="build")]))
    assert "@media print" in out
    # Print-only banner that appears in the printed deliverable
    assert 'class="print-banner"' in out
    # Interactive controls must be hidden when printed
    assert ".panel-search, .panel-filter, .compare-btn" in out


def test_skip_link_for_keyboard_users() -> None:
    """Standard a11y skip-link to jump from header to graph."""
    out = html_interactive.render(_basic_report(jobs=[Job(name="build")]))
    assert 'class="skip-link"' in out
    assert 'href="#graph-container"' in out


def test_keyboard_focus_styles_present() -> None:
    """Focus ring on nodes + finding items."""
    out = html_interactive.render(_basic_report(jobs=[Job(name="build")]))
    assert ":focus" in out
    # Reduced-motion preference respected
    assert "prefers-reduced-motion" in out


def test_compare_button_and_diff_banner_present() -> None:
    """Diff-mode entry point + status banner scaffolding."""
    out = html_interactive.render(_basic_report(jobs=[Job(name="build")]))
    assert 'id="compare-btn"' in out
    assert 'id="compare-file"' in out
    assert 'id="diff-banner"' in out
    assert 'id="diff-added"' in out
    assert 'id="diff-resolved"' in out
    assert 'id="diff-clear"' in out


def test_diff_status_classes_in_css() -> None:
    """The visual vocabulary for NEW / RESOLVED / UNCHANGED status pills
    must ship in the stylesheet."""
    out = html_interactive.render(_basic_report(jobs=[Job(name="build")]))
    assert ".diff-status.NEW" in out
    assert ".diff-status.RESOLVED" in out
    assert ".diff-status.UNCHANGED" in out


def test_aria_live_region_on_diff_banner() -> None:
    """Banner announces diff results to screen readers when it appears."""
    out = html_interactive.render(_basic_report(jobs=[Job(name="build")]))
    assert 'role="status"' in out
    assert 'aria-live="polite"' in out


def test_findings_attach_to_job_via_sca_location_format() -> None:
    """SCA rules emit `job[<name>].image` — must attach to that job."""
    findings = [
        _finding("SCA-EOL-001", Severity.CRITICAL, "job[approve-production].image"),
        _finding("X-2", Severity.HIGH, "job[approve-production]"),  # bare bracket form
    ]
    jobs = [Job(name="approve-production"), Job(name="other")]
    out = html_interactive.render(_basic_report(jobs=jobs, findings=findings))
    data = _extract_json(out)
    by_name = {j["name"]: j for j in data["jobs"]}
    rule_ids = {f["rule_id"] for f in by_name["approve-production"]["findings"]}
    assert "SCA-EOL-001" in rule_ids
    assert "X-2" in rule_ids
    assert by_name["other"]["findings"] == []


def test_findings_attach_to_job_via_gha_jobs_dot_format() -> None:
    """GHA rules emit `jobs.<id>.runs-on` — must attach to that job."""
    findings = [
        _finding("GHA-IAM-005", Severity.HIGH, "jobs.build.runs-on"),
        _finding("GHA-IAM-006", Severity.MEDIUM, "jobs.build.steps[2]"),
    ]
    jobs = [Job(name="build"), Job(name="test")]
    out = html_interactive.render(_basic_report(jobs=jobs, findings=findings))
    data = _extract_json(out)
    by_name = {j["name"]: j for j in data["jobs"]}
    rule_ids = {f["rule_id"] for f in by_name["build"]["findings"]}
    assert "GHA-IAM-005" in rule_ids
    assert "GHA-IAM-006" in rule_ids


def test_findings_attach_to_stage_via_jenkins_format() -> None:
    """Jenkins rules emit `stage[<name>].steps`. Same matcher applies
    (jobs and stages are visualised as nodes interchangeably)."""
    findings = [_finding("JKN-RUN-001", Severity.MEDIUM, "stage[Test].steps.script")]
    jobs = [Job(name="Test")]
    out = html_interactive.render(_basic_report(jobs=jobs, findings=findings))
    data = _extract_json(out)
    assert {f["rule_id"] for f in data["jobs"][0]["findings"]} == {"JKN-RUN-001"}


def test_humanised_location_reads_well() -> None:
    """The display_location field is what shows up in the side-panel
    list — should be readable, not cryptic."""
    findings = [
        _finding("X-1", Severity.HIGH, "job[deploy].image"),
        _finding("X-2", Severity.HIGH, "global.variables"),
        _finding("X-3", Severity.HIGH, "global"),
        _finding("X-4", Severity.HIGH, "jobs.build.runs-on"),
        _finding("X-5", Severity.HIGH, "stage[Test].steps.script"),
        _finding("X-6", Severity.HIGH, "pipeline.image"),
    ]
    jobs = [Job(name="deploy"), Job(name="build"), Job(name="Test")]
    out = html_interactive.render(_basic_report(jobs=jobs, findings=findings))
    data = _extract_json(out)
    by_rule = {f["rule_id"]: f for f in data["findings"]}
    assert by_rule["X-1"]["display_location"] == "deploy · image"
    assert by_rule["X-2"]["display_location"] == "Pipeline · variables"
    assert by_rule["X-3"]["display_location"] == "Pipeline (global)"
    assert by_rule["X-4"]["display_location"] == "build · runs-on"
    assert by_rule["X-5"]["display_location"] == "Test · steps.script"
    assert by_rule["X-6"]["display_location"] == "Pipeline · image"


def test_findings_carry_owning_job_for_click_navigation() -> None:
    """The side-panel click handler uses `owning_job` to find which job
    to highlight. Locations that don't resolve to a job (global,
    pipeline-level) get null."""
    findings = [
        _finding("X-1", Severity.HIGH, "job[deploy].image"),  # → "deploy"
        _finding("X-2", Severity.HIGH, "global.variables"),    # → null
    ]
    jobs = [Job(name="deploy")]
    out = html_interactive.render(_basic_report(jobs=jobs, findings=findings))
    data = _extract_json(out)
    by_rule = {f["rule_id"]: f for f in data["findings"]}
    assert by_rule["X-1"]["owning_job"] == "deploy"
    assert by_rule["X-2"]["owning_job"] is None


def test_no_unescaped_close_script_inside_inline_scripts() -> None:
    """Regression for the Phase 1.4 bug: a comment in the viewer JS
    contained the literal `</script>` string, which the HTML parser
    treated as the close tag for the surrounding inline script,
    silently breaking the page.

    The defensive escape at render time replaces any literal close tag
    inside `<script>...</script>` blocks. This test asserts the only
    `</script>` occurrences in the rendered output are the ACTUAL close
    tags, not stray ones inside script bodies."""
    out = html_interactive.render(_basic_report(jobs=[Job(name="build")]))
    # Every occurrence of `</script>` must be at a tag-boundary position.
    # Test by stripping all properly-paired script blocks and asserting
    # nothing's left over. The `[\s>]` after `script` matches both
    # `</script>` and `</script >` per HTML spec — closes a CodeQL
    # `py/bad-tag-filter` alert without changing what we test.
    stripped = re.sub(
        r"<script[^>]*>[\s\S]*?</script\s*>", "", out,
        flags=re.IGNORECASE,
    )
    assert "</script>" not in stripped, (
        "stray </script> outside a script-block boundary indicates "
        "the inline JS may have terminated its container script early"
    )


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
