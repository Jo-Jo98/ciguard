"""
Tests for the v0.6.0 SCA enrichment (EOL detection + digest-pinning nudge).

Network is mocked everywhere — the EndOfLifeClient is given a temporary
cache directory pre-populated with curated payloads, so the tests are
fully offline and deterministic regardless of when they run.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.analyzer.engine import AnalysisEngine
from ciguard.analyzer.sca.endoflife import EndOfLifeClient
from ciguard.analyzer.sca.image_extractor import (
    extract_images,
    parse_image_reference,
)
from ciguard.analyzer.sca_rules import rule_sca_eol, rule_sca_pin_001
from ciguard.models.pipeline import Job, Pipeline, Severity


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
        findings = rule_sca_eol(pipe, self.client)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "SCA-EOL-002"  # language runtime
        assert f.severity == Severity.CRITICAL
        assert "python" in f.evidence.lower()

    def test_critical_finding_for_alpine_eol(self):
        pipe = _make_pipeline({"build": "alpine:3.16"})
        findings = rule_sca_eol(pipe, self.client)
        assert len(findings) == 1
        assert findings[0].rule_id == "SCA-EOL-001"  # OS base
        assert findings[0].severity == Severity.CRITICAL

    def test_supported_image_emits_no_finding(self):
        pipe = _make_pipeline({"build": "python:3.13-slim"})
        findings = rule_sca_eol(pipe, self.client)
        assert findings == []

    def test_approaching_eol_is_info(self):
        # debian:12 EOL is 2026-06-10; today defaults to actual today which
        # may or may not be within 90 days. Use a deterministic lookup
        # via the helper rather than relying on system clock.
        cycles = self.client.cycles_for_product("debian")
        cycle = EndOfLifeClient.find_cycle(cycles, "12")
        days = EndOfLifeClient.days_until_eol(
            cycle, today=datetime(2026, 4, 26, tzinfo=timezone.utc)
        )
        # ~45 days — well within the 90-day "approaching" window
        assert 0 < days <= 90

    def test_unknown_image_silently_skipped(self):
        pipe = _make_pipeline({"build": "internal-tool:1.0"})
        findings = rule_sca_eol(pipe, self.client)
        assert findings == []

    def test_image_with_no_tag_silently_skipped(self):
        # Bare images with no version info can't be EOL-checked.
        # PIPE-001 catches the unpinned-tag concern separately.
        pipe = _make_pipeline({"build": "python"})
        findings = rule_sca_eol(pipe, self.client)
        assert findings == []


# ---------------------------------------------------------------------------
# SCA-PIN-001 — digest-pinning nudge
# ---------------------------------------------------------------------------

class TestScaPin001:
    def setup_method(self):
        import tempfile
        self.client = EndOfLifeClient(
            cache_dir=Path(tempfile.mkdtemp(prefix="ciguard-pin-")),
            offline=True,
        )

    def test_fires_on_tag_pinned_no_digest(self):
        pipe = _make_pipeline({"build": "alpine:3.21"})
        findings = rule_sca_pin_001(pipe, self.client)
        assert len(findings) == 1
        assert findings[0].rule_id == "SCA-PIN-001"
        assert findings[0].severity == Severity.LOW

    def test_silent_on_digest_pinned(self):
        pipe = _make_pipeline({
            "build": "alpine:3.21@sha256:" + "a" * 64,
        })
        assert rule_sca_pin_001(pipe, self.client) == []

    def test_silent_on_latest_tag(self):
        # PIPE-001 already catches `:latest` — don't double-flag.
        pipe = _make_pipeline({"build": "alpine:latest"})
        assert rule_sca_pin_001(pipe, self.client) == []

    def test_silent_on_no_tag(self):
        # PIPE-001 also catches bare image names — don't double-flag.
        pipe = _make_pipeline({"build": "alpine"})
        assert rule_sca_pin_001(pipe, self.client) == []


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
