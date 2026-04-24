"""
ciguard Web API + UI.

Start with:
  uvicorn src.web.app:app --host 0.0.0.0 --port 8080
  python -m src.web.app   (same, with auto-reload in dev)

Endpoints:
  GET  /                       Upload UI
  GET  /report/{scan_id}       Results UI
  POST /api/scan               Upload + scan a pipeline file
  GET  /api/report/{scan_id}   Full JSON report
  GET  /api/report/{scan_id}/html  Self-contained HTML report
  GET  /api/health             Health check
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

# Allow running as `python -m src.web.app` from the project root
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from ciguard.analyzer.engine import AnalysisEngine
from ciguard.parser.gitlab_parser import GitLabCIParser
from ciguard.reporter.html_report import HTMLReporter
from ciguard.web.scan_store import get_store

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

app = FastAPI(
    title="ciguard",
    description="CI/CD Pipeline Security Auditor",
    version="0.3.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

_parser = GitLabCIParser()
_engine = AnalysisEngine()
_reporter = HTMLReporter()


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

@app.get("/api/health", tags=["api"])
def api_health():
    """Health check — returns 200 when the service is ready."""
    return {"status": "ok", "version": "0.3.0", "scans_in_memory": len(get_store())}


@app.post("/api/scan", tags=["api"])
async def api_scan(file: UploadFile = File(..., description="The .gitlab-ci.yml file to scan")):
    """Upload and scan a GitLab CI pipeline file.

    Returns a ``scan_id`` and high-level summary. Use
    ``GET /api/report/{scan_id}`` for the full JSON report.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided.")

    content = await file.read()

    if len(content) > GitLabCIParser.MAX_FILE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum is {GitLabCIParser.MAX_FILE_BYTES // 1024} KB.",
        )

    # Write to temp file so the parser can stat/open it normally
    suffix = Path(file.filename).suffix or ".yml"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        pipeline = _parser.parse_file(tmp_path)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    finally:
        tmp_path.unlink(missing_ok=True)

    report = _engine.analyse(pipeline, pipeline_name=file.filename)
    scan_id = get_store().put(report)

    by_sev = report.summary.get("by_severity", {})
    return {
        "scan_id": scan_id,
        "pipeline_name": report.pipeline_name,
        "scan_timestamp": report.scan_timestamp,
        "overall_score": report.risk_score.overall,
        "grade": report.risk_score.grade,
        "total_findings": report.summary.get("total", 0),
        "by_severity": {k: v for k, v in by_sev.items() if v > 0},
        "stages": report.pipeline.stages,
        "job_count": len(report.pipeline.jobs),
    }


@app.get("/api/report/{scan_id}", tags=["api"])
def api_report_json(scan_id: str):
    """Return the full scan report as JSON."""
    report = get_store().get(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail="Scan not found. Results are kept in memory and lost on server restart.")
    return report.model_dump(mode="json")


@app.get("/api/report/{scan_id}/html", tags=["api"], response_class=HTMLResponse)
def api_report_html(scan_id: str):
    """Return the self-contained HTML report."""
    report = get_store().get(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return HTMLResponse(content=_reporter.render(report))


# ---------------------------------------------------------------------------
# UI routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def ui_upload(request: Request):
    # Starlette 1.x: request is first positional arg, then name, then context
    return templates.TemplateResponse(request, "upload.html", {})


@app.get("/report/{scan_id}", response_class=HTMLResponse, include_in_schema=False)
def ui_report(request: Request, scan_id: str):
    return templates.TemplateResponse(request, "results.html", {"scan_id": scan_id})


# ---------------------------------------------------------------------------
# Dev runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.web.app:app", host="0.0.0.0", port=8080, reload=True)
