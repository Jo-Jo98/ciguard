"""
Tests for the standalone inventory HTML reporter (Slice 14b session 2).

The reporter is a pure function over `InventoryReport` — easy to unit
test on the rendered string directly. We don't run a headless browser
because the page is single-purpose with no JavaScript.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.models.inventory import InventoryEntry, InventoryReport
from ciguard.reporter import inventory_html


def _entry(**kwargs) -> InventoryEntry:
    defaults = dict(tool="jenkins", configured=True, version="2.426")
    defaults.update(kwargs)
    return InventoryEntry(**defaults)


class TestRender:
    def test_returns_html5_document(self):
        out = inventory_html.render(InventoryReport(entries=[_entry()]))
        assert out.startswith("<!DOCTYPE html>")
        assert "</html>" in out
        assert "<title>ciguard infrastructure inventory</title>" in out

    def test_renders_one_row_per_entry(self):
        report = InventoryReport(entries=[
            _entry(tool="jenkins", version="2.500"),
            _entry(tool="gitlab-self-host", version="16.5.0", edition="EE"),
            _entry(tool="harbor", configured=False),
        ])
        out = inventory_html.render(report)
        # Each tool name should appear once in the rendered table.
        for name in ("jenkins", "gitlab-self-host", "harbor"):
            assert name in out

    def test_status_badge_uses_severity_colour_for_eol(self):
        report = InventoryReport(entries=[
            _entry(tool="jenkins", version="2.300",
                   eol_date="2024-01-01", days_until_eol=-365),
        ])
        out = inventory_html.render(report)
        # Red (#ef4444) means end-of-life.
        assert "#ef4444" in out
        assert "end-of-life" in out

    def test_unconfigured_entry_shows_dim_badge(self):
        report = InventoryReport(entries=[_entry(tool="harbor", configured=False)])
        out = inventory_html.render(report)
        assert "unconfigured" in out
        assert "#71717a" in out          # dim grey

    def test_summary_line_shows_configured_count(self):
        report = InventoryReport(entries=[
            _entry(tool="a", configured=True, version="1"),
            _entry(tool="b", configured=False),
            _entry(tool="c", configured=True, version="2"),
        ])
        out = inventory_html.render(report)
        assert "2 of 3 tools configured" in out

    def test_html_escapes_evil_input(self):
        report = InventoryReport(entries=[
            _entry(tool="jenkins", version='<img src=x>', error='</td><script>alert(1)</script>'),
        ])
        out = inventory_html.render(report)
        # No raw script tag; escaped form is fine.
        assert "<script>alert(1)</script>" not in out
        assert "&lt;script&gt;" in out

    def test_empty_entries_shows_helpful_message(self):
        out = inventory_html.render(InventoryReport(entries=[]))
        assert "No probes registered" in out

    def test_eol_notes_include_days_remaining(self):
        report = InventoryReport(entries=[
            _entry(tool="jenkins", version="2.426",
                   eol_date="2027-01-01", days_until_eol=200),
        ])
        out = inventory_html.render(report)
        assert "EOL 2027-01-01 (200 days)" in out

    def test_eol_notes_include_days_past_when_negative(self):
        report = InventoryReport(entries=[
            _entry(tool="jenkins", version="2.300",
                   eol_date="2024-01-01", days_until_eol=-100),
        ])
        out = inventory_html.render(report)
        assert "100 days past" in out

    def test_print_media_block_present(self):
        # Print media query should switch to a light-theme palette so the
        # PDF export an auditor sees doesn't waste ink on the dark bg.
        out = inventory_html.render(InventoryReport(entries=[_entry()]))
        assert "@media print" in out


class TestWriteReport:
    def test_creates_parent_dir(self, tmp_path):
        nested = tmp_path / "deep" / "inventory.html"
        result = inventory_html.write_report(
            InventoryReport(entries=[_entry()]),
            nested,
        )
        assert result == nested
        assert nested.exists()
        assert nested.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
