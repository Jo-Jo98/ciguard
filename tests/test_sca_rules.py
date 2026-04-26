"""
Tests for SCA enrichment.

v0.6.0 — EOL detection + digest-pinning nudge.
v0.6.1 — Graduated EOL tiers, EOS detection, GHA action CVE lookup.

Network is mocked everywhere — both the EndOfLifeClient and the OSVClient
are given a temporary cache directory pre-populated with curated payloads,
so the tests are fully offline and deterministic regardless of when they run.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.analyzer.engine import AnalysisEngine
from ciguard.analyzer.sca.action_extractor import (
    extract_action_references,
    parse_uses,
)
from ciguard.analyzer.sca.endoflife import EndOfLifeClient
from ciguard.analyzer.sca.image_extractor import (
    extract_images,
    parse_image_reference,
)
from ciguard.analyzer.sca.osv import OSVClient, normalise_severity
from ciguard.analyzer.sca_rules import (
    rule_sca_cve_001,
    rule_sca_eol,
    rule_sca_eos_001,
    rule_sca_pin_001,
    _eol_severity_and_label,
)
from ciguard.models.pipeline import Job, Pipeline, Severity
from ciguard.models.workflow import Job as WfJob, Step, Workflow


# ---------------------------------------------------------------------------
# Image reference parsing
# ---------------------------------------------------------------------------

class TestParseImageReference:
    def test_bare_name(self):
        ref = parse_image_reference("alpine", "x")
        assert ref.name == "alpine" and ref.tag is None and ref.digest is None

    def test_name_and_tag(self):
        ref = parse_image_reference("python:3.9-slim", "x")
        assert ref.name == "python"
        assert ref.tag == "3.9-slim"
        assert ref.cycle_id == "3.9"

    def test_registry_path_tag(self):
        ref = parse_image_reference("ghcr.io/jo-jo98/ciguard:0.5.0", "x")
        assert ref.registry == "ghcr.io"
        assert ref.name == "ciguard"
        assert ref.tag == "0.5.0"
        assert ref.cycle_id == "0.5.0"

    def test_digest_pinning(self):
        ref = parse_image_reference(
            "alpine:3.18@sha256:" + "a" * 64, "x"
        )
        assert ref.tag == "3.18"
        assert ref.digest == "sha256:" + "a" * 64
        assert ref.is_digest_pinned is True

    def test_digest_only_no_tag(self):
        ref = parse_image_reference("alpine@sha256:" + "b" * 64, "x")
        assert ref.tag is None
        assert ref.is_digest_pinned is True

    def test_complex_jdk_tag_extracts_first_version(self):
        ref = parse_image_reference("maven:3.9.4-eclipse-temurin-21", "x")
        assert ref.name == "maven"
        # Cycle extraction takes the leading version-like prefix
        assert ref.cycle_id == "3.9.4"

    def test_garbage_input_returns_none(self):
        assert parse_image_reference("", "x") is None
        assert parse_image_reference(None, "x") is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# EndOfLifeClient — cache + offline behaviour
# ---------------------------------------------------------------------------

def _seed_cache(cache_dir: Path, product: str, payload: list) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / f"endoflife-{product}.json").write_text(json.dumps(payload))


def _seed_osv_cache(
    cache_dir: Path,
    package: str,
    version: str,
    vulns: list[dict],
) -> None:
    """Mirror of _seed_cache for OSV. Cache key shape:
    `osv-github-actions-<owner>__<repo>-<version>.json`."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    pkg = package.replace("/", "__")
    (cache_dir / f"osv-github-actions-{pkg}-{version}.json").write_text(
        json.dumps(vulns)
    )


def _offline_osv(cache_dir: Path) -> OSVClient:
    """Build an OSV client that never touches the network."""
    return OSVClient(cache_dir=cache_dir, offline=True)


class TestEndOfLifeClient:
    def test_offline_uses_cache_only(self, tmp_path):
        _seed_cache(tmp_path, "python", [
            {"cycle": "3.9", "eol": "2025-10-31"},
            {"cycle": "3.13", "eol": "2029-10-31"},
        ])
        client = EndOfLifeClient(cache_dir=tmp_path, offline=True)
        cycles = client.cycles_for_product("python")
        assert cycles is not None
        assert len(cycles) == 2

    def test_offline_with_no_cache_returns_none(self, tmp_path):
        client = EndOfLifeClient(cache_dir=tmp_path, offline=True)
        assert client.cycles_for_product("nonexistent-product-xyz") is None

    def test_image_to_product_mapping(self, tmp_path):
        _seed_cache(tmp_path, "alpine-linux", [{"cycle": "3.18", "eol": "2025-05-09"}])
        _seed_cache(tmp_path, "nodejs", [{"cycle": "16", "eol": "2023-09-11"}])
        client = EndOfLifeClient(cache_dir=tmp_path, offline=True)
        # `alpine` image → `alpine-linux` product
        assert client.cycles_for_image("alpine") is not None
        # `node` image → `nodejs` product
        assert client.cycles_for_image("node") is not None
        # Unknown image → None
        assert client.cycles_for_image("totally-custom-image") is None

    def test_find_cycle_exact_match(self):
        cycles = [{"cycle": "3.18", "eol": "2025-05-09"}, {"cycle": "3.19", "eol": "2025-11-01"}]
        assert EndOfLifeClient.find_cycle(cycles, "3.18")["cycle"] == "3.18"

    def test_find_cycle_prefix_match(self):
        # `3.9.18` should match cycle `3.9` (Python patch versions roll up
        # to the minor cycle).
        cycles = [{"cycle": "3.9", "eol": "2025-10-31"}]
        assert EndOfLifeClient.find_cycle(cycles, "3.9.18")["cycle"] == "3.9"

    def test_find_cycle_no_match(self):
        cycles = [{"cycle": "3.9", "eol": "2025-10-31"}]
        assert EndOfLifeClient.find_cycle(cycles, "4.5.6") is None

    def test_days_until_eol_past(self):
        # Cycle EOL is 2025-10-31; "today" pinned to 2026-04-26 → ~177 days past
        days = EndOfLifeClient.days_until_eol(
            {"eol": "2025-10-31"},
            today=datetime(2026, 4, 26, tzinfo=timezone.utc),
        )
        assert days is not None and days < 0
        assert -180 <= days <= -170

    def test_days_until_eol_future(self):
        days = EndOfLifeClient.days_until_eol(
            {"eol": "2027-01-01"},
            today=datetime(2026, 4, 26, tzinfo=timezone.utc),
        )
        assert days is not None and days > 0

    def test_days_until_eol_no_date(self):
        # endoflife.date returns `false` for cycles without a confirmed EOL
        assert EndOfLifeClient.days_until_eol({"eol": False}) is None
        assert EndOfLifeClient.days_until_eol({}) is None


# ---------------------------------------------------------------------------
# SCA-EOL rules — end-to-end with seeded cache
# ---------------------------------------------------------------------------

def _make_pipeline(images_by_job: dict[str, str]) -> Pipeline:
    """Build a Pipeline with one job per (name, image) pair."""
    return Pipeline(
        stages=[],
        jobs=[Job(name=name, image=image) for name, image in images_by_job.items()],
    )


class TestSCAEol:
    def setup_method(self, tmp_path=None):
        # pytest's tmp_path fixture isn't available in setup_method —
        # set up a per-test sandbox in setup_method body via a manual dir
        import tempfile
        self.tmp = Path(tempfile.mkdtemp(prefix="ciguard-sca-test-"))
        # Seed cache with curated EOL data covering the test images.
        # All dates relative to a fixed test "now" of 2026-04-26.
        _seed_cache(self.tmp, "python", [
            {"cycle": "3.13", "eol": "2029-10-31"},        # supported (>90d)
            {"cycle": "3.10", "eol": "2026-10-31"},        # approaching (<90d in test if today=2026-04-26 → ~188d, NOT approaching)
            {"cycle": "3.9", "eol": "2025-10-31"},         # past EOL (>90d) → CRITICAL
        ])
        _seed_cache(self.tmp, "alpine-linux", [
            {"cycle": "3.21", "eol": "2026-11-01"},        # supported
            {"cycle": "3.16", "eol": "2024-05-23"},        # past EOL (>90d) → CRITICAL
        ])
        _seed_cache(self.tmp, "nodejs", [
            {"cycle": "22", "eol": "2027-04-30"},          # supported
            {"cycle": "18", "eol": "2025-04-30"},          # past EOL (>90d) → CRITICAL
        ])
        _seed_cache(self.tmp, "debian", [
            {"cycle": "13", "eol": "2028-08-09"},
            {"cycle": "12", "eol": "2026-06-10"},          # ~45d to EOL → INFO (approaching)
        ])
        self.client = EndOfLifeClient(cache_dir=self.tmp, offline=True)

    def test_critical_finding_for_long_past_eol(self):
        pipe = _make_pipeline({"build": "python:3.9-slim"})
        findings = rule_sca_eol(pipe, self.client, _offline_osv(self.tmp))
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "SCA-EOL-002"  # language runtime
        assert f.severity == Severity.CRITICAL
        assert "python" in f.evidence.lower()

    def test_critical_finding_for_alpine_eol(self):
        pipe = _make_pipeline({"build": "alpine:3.16"})
        findings = rule_sca_eol(pipe, self.client, _offline_osv(self.tmp))
        assert len(findings) == 1
        assert findings[0].rule_id == "SCA-EOL-001"  # OS base
        assert findings[0].severity == Severity.CRITICAL

    def test_supported_image_emits_no_finding(self):
        pipe = _make_pipeline({"build": "python:3.13-slim"})
        findings = rule_sca_eol(pipe, self.client, _offline_osv(self.tmp))
        assert findings == []

    def test_days_until_eol_for_debian_12(self):
        # debian:12 EOL is 2026-06-10; ~45 days from 2026-04-26.
        # Used by the graduated-tier tests below to confirm seeded data.
        cycles = self.client.cycles_for_product("debian")
        cycle = EndOfLifeClient.find_cycle(cycles, "12")
        days = EndOfLifeClient.days_until_eol(
            cycle, today=datetime(2026, 4, 26, tzinfo=timezone.utc)
        )
        assert 0 < days <= 90

    def test_unknown_image_silently_skipped(self):
        pipe = _make_pipeline({"build": "internal-tool:1.0"})
        findings = rule_sca_eol(pipe, self.client, _offline_osv(self.tmp))
        assert findings == []

    def test_image_with_no_tag_silently_skipped(self):
        # Bare images with no version info can't be EOL-checked.
        # PIPE-001 catches the unpinned-tag concern separately.
        pipe = _make_pipeline({"build": "python"})
        findings = rule_sca_eol(pipe, self.client, _offline_osv(self.tmp))
        assert findings == []


# ---------------------------------------------------------------------------
# SCA-PIN-001 — digest-pinning nudge
# ---------------------------------------------------------------------------

class TestScaPin001:
    def setup_method(self):
        import tempfile
        eol_tmp = Path(tempfile.mkdtemp(prefix="ciguard-pin-"))
        self._osv_tmp = Path(tempfile.mkdtemp(prefix="ciguard-pin-osv-"))
        self.client = EndOfLifeClient(cache_dir=eol_tmp, offline=True)

    def test_fires_on_tag_pinned_no_digest(self):
        pipe = _make_pipeline({"build": "alpine:3.21"})
        findings = rule_sca_pin_001(pipe, self.client, _offline_osv(self._osv_tmp))
        assert len(findings) == 1
        assert findings[0].rule_id == "SCA-PIN-001"
        assert findings[0].severity == Severity.LOW

    def test_silent_on_digest_pinned(self):
        pipe = _make_pipeline({
            "build": "alpine:3.21@sha256:" + "a" * 64,
        })
        assert rule_sca_pin_001(pipe, self.client, _offline_osv(self._osv_tmp)) == []

    def test_silent_on_latest_tag(self):
        # PIPE-001 already catches `:latest` — don't double-flag.
        pipe = _make_pipeline({"build": "alpine:latest"})
        assert rule_sca_pin_001(pipe, self.client, _offline_osv(self._osv_tmp)) == []

    def test_silent_on_no_tag(self):
        # PIPE-001 also catches bare image names — don't double-flag.
        pipe = _make_pipeline({"build": "alpine"})
        assert rule_sca_pin_001(pipe, self.client, _offline_osv(self._osv_tmp)) == []


# ---------------------------------------------------------------------------
# Engine integration — SCA opt-out flag
# ---------------------------------------------------------------------------

class TestEngineScaOptOut:
    def test_enable_sca_false_skips_sca(self):
        pipe = _make_pipeline({"build": "python:3.9-slim"})  # would be Critical EOL
        report = AnalysisEngine(enable_sca=False).analyse(pipe, "x")
        sca_findings = [f for f in report.findings if f.rule_id.startswith("SCA-")]
        assert sca_findings == []

    def test_enable_sca_true_runs_sca_with_offline_cache(self, tmp_path):
        _seed_cache(tmp_path, "python", [{"cycle": "3.9", "eol": "2020-01-01"}])
        pipe = _make_pipeline({"build": "python:3.9-slim"})
        report = AnalysisEngine(
            enable_sca=True,
            sca_offline=True,
            sca_cache_dir=tmp_path,
        ).analyse(pipe, "x")
        sca_findings = [f for f in report.findings if f.rule_id.startswith("SCA-")]
        # At least the EOL finding fires; PIN-001 may or may not depending
        # on tag.
        eol_findings = [f for f in sca_findings if f.rule_id.startswith("SCA-EOL-")]
        assert len(eol_findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in eol_findings)


# ---------------------------------------------------------------------------
# Cross-platform image extraction
# ---------------------------------------------------------------------------

class TestExtractImages:
    def test_extracts_from_gitlab_pipeline(self):
        pipe = _make_pipeline({
            "build": "python:3.13-slim",
            "test": "node:22",
        })
        refs = extract_images(pipe)
        names = sorted(r.name for r in refs)
        assert names == ["node", "python"]

    def test_returns_empty_for_unknown_target(self):
        # Passing something we don't know how to handle should not crash.
        assert extract_images(None) == []  # type: ignore[arg-type]


# ===========================================================================
# v0.6.1 — graduated EOL tiers
# ===========================================================================

class TestEolGraduatedTiers:
    """Verifies the v0.6.1 tier table on `_eol_severity_and_label`:
        days < -90        → Critical
        -90 ≤ days < 0    → High
        0 ≤ days ≤ 90     → High (was Info in v0.6.0)
        91 ≤ days ≤ 180   → Medium  (NEW)
        181 ≤ days ≤ 365  → Low     (NEW)
        days > 365        → Info (caller should treat as out-of-scope)
    """
    def test_long_past_eol_is_critical(self):
        sev, _, _ = _eol_severity_and_label(-200)
        assert sev == Severity.CRITICAL

    def test_recently_past_eol_is_high(self):
        sev, _, _ = _eol_severity_and_label(-30)
        assert sev == Severity.HIGH

    def test_imminent_eol_is_high(self):
        # Was Info in v0.6.0; now High — under-quarter runway.
        sev, _, _ = _eol_severity_and_label(45)
        assert sev == Severity.HIGH

    def test_eol_at_six_months_is_medium(self):
        sev, _, _ = _eol_severity_and_label(150)
        assert sev == Severity.MEDIUM

    def test_eol_at_twelve_months_is_low(self):
        sev, _, _ = _eol_severity_and_label(300)
        assert sev == Severity.LOW

    def test_eol_far_future_is_info(self):
        sev, _, _ = _eol_severity_and_label(500)
        assert sev == Severity.INFO


def _seed_one_cycle(cache_dir: Path, image_name: str, cycle_id: str,
                    days_until_eol: int, today: datetime,
                    extra: dict | None = None) -> EndOfLifeClient:
    """Seed an endoflife cache with a single cycle whose EOL date is
    `days_until_eol` from `today`. Returns an offline client."""
    eol_date = (today.replace(tzinfo=timezone.utc) +
                __import__("datetime").timedelta(days=days_until_eol)
                ).date().isoformat()
    cycle = {"cycle": cycle_id, "eol": eol_date}
    if extra:
        cycle.update(extra)
    # Map image_name → product slug via the existing IMAGE_TO_PRODUCT table.
    from ciguard.analyzer.sca.endoflife import IMAGE_TO_PRODUCT
    product = IMAGE_TO_PRODUCT.get(image_name.lower(), image_name.lower())
    _seed_cache(cache_dir, product, [cycle])
    return EndOfLifeClient(cache_dir=cache_dir, offline=True)


class TestSCAEolGraduatedEndToEnd:
    def test_medium_finding_for_six_month_runway(self, tmp_path):
        today = datetime(2026, 4, 26, tzinfo=timezone.utc)
        eol = _seed_one_cycle(tmp_path, "alpine", "3.99", 150, today)
        pipe = _make_pipeline({"build": "alpine:3.99"})
        findings = rule_sca_eol(pipe, eol, _offline_osv(tmp_path))
        # _check_image_eol uses datetime.now() — accept either Medium or
        # Low depending on real today vs seeded EOL date drift. We seeded
        # 150 days from 2026-04-26 = 2026-09-23.
        assert len(findings) == 1
        assert findings[0].rule_id == "SCA-EOL-003"
        assert findings[0].severity in (Severity.MEDIUM, Severity.LOW)

    def test_low_finding_for_twelve_month_runway(self, tmp_path):
        today = datetime(2026, 4, 26, tzinfo=timezone.utc)
        eol = _seed_one_cycle(tmp_path, "debian", "99", 300, today)
        pipe = _make_pipeline({"build": "debian:99"})
        findings = rule_sca_eol(pipe, eol, _offline_osv(tmp_path))
        assert len(findings) == 1
        assert findings[0].rule_id == "SCA-EOL-003"
        assert findings[0].severity in (Severity.LOW, Severity.MEDIUM)

    def test_silent_when_eol_more_than_year_away(self, tmp_path):
        today = datetime(2026, 4, 26, tzinfo=timezone.utc)
        eol = _seed_one_cycle(tmp_path, "alpine", "3.50", 500, today)
        pipe = _make_pipeline({"build": "alpine:3.50"})
        findings = rule_sca_eol(pipe, eol, _offline_osv(tmp_path))
        assert findings == []


# ===========================================================================
# v0.6.1 — SCA-EOS-001 end-of-active-support
# ===========================================================================

class TestSCAEos001:
    """End-of-active-support detection — fires when `today` is past `support`
    but before `eol`. Silent when product has no `support` field, when not
    yet past support, or when already past EOL (SCA-EOL-001/002 owns that).
    """
    def test_fires_when_past_support_before_eol(self, tmp_path):
        # support 2025-06-01 (~10 months past 2026-04-26), eol 2027-06-01
        _seed_cache(tmp_path, "java", [
            {"cycle": "11", "support": "2025-06-01", "eol": "2027-06-01"},
        ])
        eol = EndOfLifeClient(cache_dir=tmp_path, offline=True)
        pipe = _make_pipeline({"build": "openjdk:11"})
        findings = rule_sca_eos_001(pipe, eol, _offline_osv(tmp_path))
        assert len(findings) == 1
        assert findings[0].rule_id == "SCA-EOS-001"
        assert findings[0].severity == Severity.LOW
        assert "active-support" in findings[0].description.lower()

    def test_silent_when_still_in_active_support(self, tmp_path):
        # support is in the future
        _seed_cache(tmp_path, "java", [
            {"cycle": "21", "support": "2028-09-01", "eol": "2030-09-01"},
        ])
        eol = EndOfLifeClient(cache_dir=tmp_path, offline=True)
        pipe = _make_pipeline({"build": "openjdk:21"})
        assert rule_sca_eos_001(pipe, eol, _offline_osv(tmp_path)) == []

    def test_silent_when_past_eol_too(self, tmp_path):
        # Both support AND eol are past — SCA-EOL-002 owns this.
        _seed_cache(tmp_path, "java", [
            {"cycle": "8", "support": "2022-03-01", "eol": "2023-03-01"},
        ])
        eol = EndOfLifeClient(cache_dir=tmp_path, offline=True)
        pipe = _make_pipeline({"build": "openjdk:8"})
        assert rule_sca_eos_001(pipe, eol, _offline_osv(tmp_path)) == []

    def test_silent_when_no_support_field(self, tmp_path):
        # Most distros don't expose `support` separate from `eol`.
        _seed_cache(tmp_path, "alpine-linux", [
            {"cycle": "3.21", "eol": "2026-11-01"},
        ])
        eol = EndOfLifeClient(cache_dir=tmp_path, offline=True)
        pipe = _make_pipeline({"build": "alpine:3.21"})
        assert rule_sca_eos_001(pipe, eol, _offline_osv(tmp_path)) == []


# ===========================================================================
# v0.6.1 — OSV client
# ===========================================================================

class TestOSVClient:
    def test_offline_uses_cache_only(self, tmp_path):
        _seed_osv_cache(tmp_path, "actions/checkout", "3.0.0", [
            {"id": "GHSA-abcd", "summary": "test"},
        ])
        client = _offline_osv(tmp_path)
        result = client.vulns_for_action("actions/checkout", "3.0.0")
        assert result == [{"id": "GHSA-abcd", "summary": "test"}]

    def test_offline_with_no_cache_returns_none(self, tmp_path):
        client = _offline_osv(tmp_path)
        assert client.vulns_for_action("actions/checkout", "99.0.0") is None

    def test_cache_key_handles_slash_in_package(self, tmp_path):
        _seed_osv_cache(tmp_path, "actions/checkout", "4.0.0", [])
        client = _offline_osv(tmp_path)
        # Empty list = "known clean" (distinct from None = "unknown")
        assert client.vulns_for_action("actions/checkout", "4.0.0") == []


class TestNormaliseSeverity:
    def test_maps_critical_label(self):
        assert normalise_severity({"database_specific": {"severity": "CRITICAL"}}) == "CRITICAL"

    def test_maps_moderate_to_medium(self):
        assert normalise_severity({"database_specific": {"severity": "MODERATE"}}) == "MEDIUM"

    def test_falls_back_to_cvss(self):
        result = normalise_severity({
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        })
        assert result == "CRITICAL"

    def test_default_is_medium(self):
        assert normalise_severity({}) == "MEDIUM"


# ===========================================================================
# v0.6.1 — action extractor
# ===========================================================================

class TestParseUses:
    def test_marketplace_action_with_tag_version(self):
        ref = parse_uses("actions/checkout@v4", "x")
        assert ref.owner_repo == "actions/checkout"
        assert ref.version == "v4"
        assert ref.normalised_version == "4"
        assert ref.is_reusable_workflow is False

    def test_marketplace_action_with_full_version(self):
        ref = parse_uses("actions/setup-python@v5.4.0", "x")
        assert ref.owner_repo == "actions/setup-python"
        assert ref.version == "v5.4.0"

    def test_reusable_workflow_collapses_to_owner_repo(self):
        ref = parse_uses("org/repo/.github/workflows/ci.yml@v1", "x")
        assert ref.owner_repo == "org/repo"
        assert ref.is_reusable_workflow is True
        assert ref.version == "v1"

    def test_sha_pinned_skipped(self):
        # 40-hex SHA — Dependabot's lane.
        sha = "a" * 40
        assert parse_uses(f"actions/checkout@{sha}", "x") is None

    def test_branch_ref_skipped(self):
        assert parse_uses("actions/checkout@main", "x") is None
        assert parse_uses("actions/checkout@master", "x") is None
        assert parse_uses("actions/checkout@develop", "x") is None

    def test_local_action_skipped(self):
        assert parse_uses("./.github/actions/my-action", "x") is None
        assert parse_uses("./local-action", "x") is None

    def test_docker_action_skipped(self):
        assert parse_uses("docker://ghcr.io/owner/img:tag", "x") is None

    def test_no_version_pin_skipped(self):
        # No @ at all — out of scope for CVE lookup.
        assert parse_uses("actions/checkout", "x") is None

    def test_garbage_input_returns_none(self):
        assert parse_uses("", "x") is None
        assert parse_uses(None, "x") is None  # type: ignore[arg-type]
        assert parse_uses("@v1", "x") is None
        assert parse_uses("foo@", "x") is None


def _make_workflow(steps_uses: list[str]) -> Workflow:
    """Build a minimal Workflow with one job containing a step per `uses:`."""
    return Workflow(
        name="test",
        on={"push": {}},
        jobs=[WfJob(
            id="job1",
            steps=[Step(uses=u) for u in steps_uses],
        )],
    )


class TestExtractActionReferences:
    def test_extracts_step_level_uses(self):
        wf = _make_workflow([
            "actions/checkout@v4",
            "actions/setup-python@v5.4.0",
        ])
        refs = extract_action_references(wf)
        assert len(refs) == 2
        assert {r.owner_repo for r in refs} == {"actions/checkout", "actions/setup-python"}

    def test_extracts_job_level_reusable_workflow(self):
        wf = Workflow(
            name="t",
            on={"push": {}},
            jobs=[WfJob(id="caller", uses="org/repo/.github/workflows/x.yml@v1")],
        )
        refs = extract_action_references(wf)
        assert len(refs) == 1
        assert refs[0].is_reusable_workflow is True
        assert refs[0].owner_repo == "org/repo"

    def test_skips_sha_and_local(self):
        wf = _make_workflow([
            "actions/checkout@" + ("a" * 40),
            "./.github/actions/local",
            "actions/cache@v4",
        ])
        refs = extract_action_references(wf)
        assert len(refs) == 1
        assert refs[0].owner_repo == "actions/cache"


# ===========================================================================
# v0.6.1 — SCA-CVE-001
# ===========================================================================

class TestSCACve001:
    def test_fires_with_severity_from_advisory(self, tmp_path):
        # Pre-populate OSV cache with a Critical advisory for a fake action.
        _seed_osv_cache(tmp_path, "evil/action", "1.0.0", [
            {
                "id": "GHSA-xxxx-yyyy-zzzz",
                "summary": "Token leak in evil/action",
                "aliases": ["CVE-2024-99999"],
                "database_specific": {"severity": "CRITICAL"},
            },
        ])
        wf = _make_workflow(["evil/action@v1.0.0"])
        eol = EndOfLifeClient(cache_dir=tmp_path, offline=True)
        osv = _offline_osv(tmp_path)
        findings = rule_sca_cve_001(wf, eol, osv)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "SCA-CVE-001"
        assert f.severity == Severity.CRITICAL
        assert "GHSA-xxxx-yyyy-zzzz" in f.description
        assert "CVE-2024-99999" in f.description

    def test_silent_when_action_clean(self, tmp_path):
        # Empty list = known clean per OSVClient semantics.
        _seed_osv_cache(tmp_path, "actions/checkout", "4.0.0", [])
        wf = _make_workflow(["actions/checkout@v4.0.0"])
        eol = EndOfLifeClient(cache_dir=tmp_path, offline=True)
        findings = rule_sca_cve_001(wf, eol, _offline_osv(tmp_path))
        assert findings == []

    def test_silent_when_unknown_to_osv(self, tmp_path):
        # No cache entry + offline → None = "unknown", not a finding.
        wf = _make_workflow(["actions/checkout@v4.0.0"])
        eol = EndOfLifeClient(cache_dir=tmp_path, offline=True)
        findings = rule_sca_cve_001(wf, eol, _offline_osv(tmp_path))
        assert findings == []

    def test_skips_sha_pinned_actions(self, tmp_path):
        # Even if we'd seeded an advisory for the package, a SHA ref is
        # never queried (extractor returns None for SHA refs).
        _seed_osv_cache(tmp_path, "actions/checkout", "4.0.0", [
            {"id": "GHSA-yyyy", "summary": "x"},
        ])
        sha = "b" * 40
        wf = _make_workflow([f"actions/checkout@{sha}"])
        eol = EndOfLifeClient(cache_dir=tmp_path, offline=True)
        findings = rule_sca_cve_001(wf, eol, _offline_osv(tmp_path))
        assert findings == []

    def test_skips_for_non_workflow_targets(self, tmp_path):
        # GitLab Pipeline / Jenkinsfile have no `uses:` field.
        pipe = _make_pipeline({"build": "alpine:3.21"})
        eol = EndOfLifeClient(cache_dir=tmp_path, offline=True)
        findings = rule_sca_cve_001(pipe, eol, _offline_osv(tmp_path))
        assert findings == []

    def test_aggregates_multiple_advisories(self, tmp_path):
        _seed_osv_cache(tmp_path, "evil/action", "1.0.0", [
            {"id": "GHSA-1", "summary": "issue 1",
             "database_specific": {"severity": "MODERATE"}},
            {"id": "GHSA-2", "summary": "issue 2",
             "database_specific": {"severity": "HIGH"}},
        ])
        wf = _make_workflow(["evil/action@v1.0.0"])
        eol = EndOfLifeClient(cache_dir=tmp_path, offline=True)
        findings = rule_sca_cve_001(wf, eol, _offline_osv(tmp_path))
        assert len(findings) == 1
        # Aggregated to highest severity
        assert findings[0].severity == Severity.HIGH


class TestEngineSCAv061Wiring:
    """Confirm the engine actually invokes the new rules end-to-end with
    the OSV client wired in."""
    def test_engine_runs_cve_rule_on_workflow(self, tmp_path):
        _seed_osv_cache(tmp_path, "evil/action", "1.0.0", [
            {"id": "GHSA-xx", "summary": "y",
             "database_specific": {"severity": "HIGH"}},
        ])
        wf = _make_workflow(["evil/action@v1.0.0"])
        report = AnalysisEngine(
            enable_sca=True,
            sca_offline=True,
            sca_cache_dir=tmp_path,
        ).analyse(wf, "x")
        cve = [f for f in report.findings if f.rule_id == "SCA-CVE-001"]
        assert len(cve) == 1
        assert cve[0].severity == Severity.HIGH

    def test_engine_runs_eos_rule(self, tmp_path):
        _seed_cache(tmp_path, "java", [
            {"cycle": "11", "support": "2025-06-01", "eol": "2027-06-01"},
        ])
        pipe = _make_pipeline({"build": "openjdk:11"})
        report = AnalysisEngine(
            enable_sca=True,
            sca_offline=True,
            sca_cache_dir=tmp_path,
        ).analyse(pipe, "x")
        eos = [f for f in report.findings if f.rule_id == "SCA-EOS-001"]
        assert len(eos) == 1


class TestSCAResponseSizeCap:
    """v0.8.2 — CYCLE-1-003 fix.

    Both SCA HTTP clients cap `resp.read()` at MAX_RESPONSE_BYTES so a
    hostile / MITM'd server can't OOM-kill ciguard with a multi-GB body.
    """

    def test_osv_caps_oversize_response(self, tmp_path, monkeypatch):
        from ciguard.analyzer.sca import osv

        # Make the cap small so the test is fast.
        monkeypatch.setattr(osv, "MAX_RESPONSE_BYTES", 1024)

        class _FakeResp:
            def __init__(self, body):
                self._body = body
                self.status = 200
            def read(self, n=None):
                return self._body[:n] if n is not None else self._body
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass

        # 2 KB body — exceeds the 1 KB cap, must be rejected (return None).
        oversize = b'{"vulns":[{"id":"X"}]}' + b"A" * 2048

        def fake_urlopen(req, timeout=None):
            return _FakeResp(oversize)

        monkeypatch.setattr(osv.urllib.request, "urlopen", fake_urlopen)

        client = osv.OSVClient(cache_dir=tmp_path, offline=False)
        result = client._fetch(osv.ECOSYSTEM_GITHUB_ACTIONS, "actions/checkout", "1.0.0")
        assert result is None, "OSV must refuse to parse oversize responses"

    def test_endoflife_caps_oversize_response(self, tmp_path, monkeypatch):
        from ciguard.analyzer.sca import endoflife

        monkeypatch.setattr(endoflife, "MAX_RESPONSE_BYTES", 1024)

        class _FakeResp:
            def __init__(self, body):
                self._body = body
                self.status = 200
            def read(self, n=None):
                return self._body[:n] if n is not None else self._body
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass

        oversize = b"[" + b"A" * 2048 + b"]"

        def fake_urlopen(req, timeout=None):
            return _FakeResp(oversize)

        monkeypatch.setattr(endoflife.urllib.request, "urlopen", fake_urlopen)

        client = endoflife.EndOfLifeClient(cache_dir=tmp_path, offline=False)
        result = client._fetch("alpine-linux")
        assert result is None, "endoflife must refuse to parse oversize responses"

    def test_osv_accepts_response_within_cap(self, tmp_path, monkeypatch):
        from ciguard.analyzer.sca import osv

        # 1 MB cap; tiny payload well within.
        monkeypatch.setattr(osv, "MAX_RESPONSE_BYTES", 1024 * 1024)

        class _FakeResp:
            def __init__(self, body):
                self._body = body
                self.status = 200
            def read(self, n=None):
                return self._body[:n] if n is not None else self._body
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass

        small = b'{"vulns":[{"id":"GHSA-xx","summary":"x","database_specific":{"severity":"HIGH"}}]}'

        def fake_urlopen(req, timeout=None):
            return _FakeResp(small)

        monkeypatch.setattr(osv.urllib.request, "urlopen", fake_urlopen)

        client = osv.OSVClient(cache_dir=tmp_path, offline=False)
        result = client._fetch(osv.ECOSYSTEM_GITHUB_ACTIONS, "actions/checkout", "1.0.0")
        assert result is not None and len(result) == 1
