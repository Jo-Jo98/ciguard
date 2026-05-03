"""FastAPI factory + lifecycle wiring for the ciguard GitHub App.

Threat model: `Project ciguard/THREAT_MODEL.md` Surface 9. This module
is where the v0.10.0 design commitments are turned into a running
service:

  - Webhook router from `webhook.py` (HMAC + 202 ack + replay defence)
  - Scheduler from `scheduler.py` (idempotency + bounded queue + per-
    repo lock) attached to `app.state.scheduler` so the webhook
    handler reaches it via `request.app.state.scheduler.enqueue(...)`.
  - Scan executor injected at startup. v0.11.1 default is the real
    `clone_and_scan_executor`: fetches the repo tarball at head SHA via
    the installation token, extracts under a `tempfile.TemporaryDirectory`,
    runs `repo_scan.scan_repo(include_findings=True)` against it,
    translates the result to the PR-comment-renderer shape. Tests
    inject a stub by passing `scan_executor=` to `create_app()`.

History:
  - v0.10.0 shipped the receiver wiring with `_stub_scan_executor`
    (returned a placeholder result so Check Run + PR comment plumbing
    was verifiable end-to-end without yet cloning repos).
  - v0.11.1 replaces the default with `clone_and_scan_executor`. The
    stub remains exported for tests + as a safety fallback for any
    deployment that hasn't yet wired App credentials (the stub doesn't
    need a token).
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional

from fastapi import FastAPI

from .clone_executor import clone_and_scan_executor
from .scan_runner import run_scan
from .scheduler import ScanJob, ScanScheduler
from .webhook import router as webhook_router

logger = logging.getLogger("ciguard.app.factory")


# ---- Stub scan executor (kept for tests + as a safety fallback) -----------


async def _stub_scan_executor(job: ScanJob) -> dict[str, Any]:
    """Placeholder scan result for tests + deployments without App
    credentials. v0.10.0 used this as the default; v0.11.1 promotes
    `clone_and_scan_executor` to the default. Tests still inject this
    via `create_app(scan_executor=_stub_scan_executor)` to keep
    Check Run + PR comment plumbing tests independent of the network."""
    logger.info(
        "stub executor handling job (installation=%d repo=%s head=%s)",
        job.installation_id, job.repo_full_name, job.head_sha[:7],
    )
    return {
        "risk_score": 100,
        "grade": "A",
        "findings": [],
        "summary": (
            "ciguard receiver wired with stub executor. Inject a real "
            "executor via create_app(scan_executor=...) for production."
        ),
    }


# ---- Lifespan / lifecycle --------------------------------------------------


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """FastAPI lifespan — start scheduler at app startup, drain on
    shutdown. Replaces the deprecated @app.on_event hooks."""
    executor = getattr(app.state, "scan_executor", None) or clone_and_scan_executor

    async def scan_fn(job: ScanJob) -> None:
        await run_scan(job, executor)

    scheduler = ScanScheduler(scan_fn)
    await scheduler.start()
    app.state.scheduler = scheduler
    logger.info("ciguard app started")
    try:
        yield
    finally:
        logger.info("ciguard app shutting down — draining scheduler")
        await scheduler.shutdown()


# ---- Factory ---------------------------------------------------------------


def create_app(
    *,
    scan_executor: Optional[Any] = None,
) -> FastAPI:
    """Build a FastAPI instance ready for `uvicorn` to serve.

    Args:
      scan_executor: Optional injection point. Defaults to
        `clone_and_scan_executor` (v0.11.1, fetches tarball + runs
        `repo_scan.scan_repo`). Tests pass `_stub_scan_executor` or a
        custom mock to keep network-free.
    """
    app = FastAPI(
        title="ciguard GitHub App",
        description=(
            "Receives GitHub webhooks, scans CI/CD pipeline configs, "
            "posts results as Check Runs + PR comments. See "
            "https://github.com/Jo-Jo98/ciguard for rules + threat model."
        ),
        version="0.10.0",
        # Disable the docs surface by default — this is a webhook
        # receiver, not a public REST API. Operators can re-enable
        # by mounting their own `/docs` if they want.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=_lifespan,
    )
    if scan_executor is not None:
        app.state.scan_executor = scan_executor

    app.include_router(webhook_router)

    @app.get("/healthz")
    def _healthz() -> dict[str, str]:
        """Liveness probe — no auth, no scheduler interaction. Designed
        for k8s/container-platform health checks. Returns 200 even if
        the scheduler is shutting down so the platform doesn't kill us
        mid-drain."""
        return {"status": "ok"}

    return app
