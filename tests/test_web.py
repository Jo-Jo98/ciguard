"""
Tests for the ciguard FastAPI web app.

Requires: httpx (async test client for FastAPI)
Run with: pytest tests/test_web.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.web.app import app

FIXTURES = Path(__file__).parent / "fixtures"

client = TestClient(app)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

class TestHealth:
    def test_health_returns_200(self):
        r = client.get("/api/health")
        assert r.status_code == 200

    def test_health_has_status(self):
        data = client.get("/api/health").json()
        assert data["status"] == "ok"
        assert "version" in data


# ---------------------------------------------------------------------------
# Upload / scan
# ---------------------------------------------------------------------------

class TestScan:
    def _scan(self, fixture: str):
        path = FIXTURES / fixture
        with open(path, "rb") as fh:
            return client.post("/api/scan", files={"file": (fixture, fh, "text/yaml")})

    def test_scan_bad_pipeline(self):
        r = self._scan("bad_pipeline.yml")
        assert r.status_code == 200
        data = r.json()
        assert "scan_id" in data
        assert data["total_findings"] > 0
        assert data["grade"] in ("D", "F")

    def test_scan_good_pipeline(self):
        r = self._scan("good_pipeline.yml")
        assert r.status_code == 200
        data = r.json()
        assert data["grade"] in ("A", "B")

    def test_scan_typical_pipeline(self):
        r = self._scan("typical_pipeline.yml")
        assert r.status_code == 200

    def test_scan_complex_pipeline(self):
        r = self._scan("complex_pipeline.yml")
        assert r.status_code == 200

    def test_scan_invalid_yaml(self):
        r = client.post(
            "/api/scan",
            files={"file": ("bad.yml", b": : : }{", "text/yaml")},
        )
        assert r.status_code == 422

    def test_scan_empty_filename(self):
        r = client.post(
            "/api/scan",
            files={"file": ("", b"stages: [test]", "text/yaml")},
        )
        # Starlette may reject the empty filename at the framework level (422)
        # before our handler runs (400) — both are correct rejections.
        assert r.status_code in (400, 422)

    def test_scan_response_shape(self):
        r = self._scan("bad_pipeline.yml")
        data = r.json()
        for key in ("scan_id", "pipeline_name", "overall_score", "grade",
                    "total_findings", "by_severity"):
            assert key in data, f"Missing key: {key}"


# ---------------------------------------------------------------------------
# Report retrieval
# ---------------------------------------------------------------------------

class TestReport:
    def _do_scan(self, fixture="bad_pipeline.yml"):
        path = FIXTURES / fixture
        with open(path, "rb") as fh:
            r = client.post("/api/scan", files={"file": (fixture, fh, "text/yaml")})
        return r.json()["scan_id"]

    def test_json_report(self):
        scan_id = self._do_scan()
        r = client.get(f"/api/report/{scan_id}")
        assert r.status_code == 200
        data = r.json()
        assert "findings" in data
        assert "risk_score" in data
        assert "pipeline" in data

    def test_html_report(self):
        scan_id = self._do_scan()
        r = client.get(f"/api/report/{scan_id}/html")
        assert r.status_code == 200
        assert "ciguard" in r.text
        assert "<!DOCTYPE html>" in r.text.lower() or "<html" in r.text.lower()

    def test_report_not_found(self):
        r = client.get("/api/report/00000000-0000-0000-0000-000000000000")
        assert r.status_code == 404

    def test_html_report_not_found(self):
        r = client.get("/api/report/00000000-0000-0000-0000-000000000000/html")
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# UI routes
# ---------------------------------------------------------------------------

class TestUI:
    def test_upload_page(self):
        r = client.get("/")
        assert r.status_code == 200
        assert "ciguard" in r.text

    def test_results_page(self):
        r = client.get("/report/test-scan-id")
        assert r.status_code == 200
        assert "test-scan-id" in r.text  # scan_id injected via Jinja2
