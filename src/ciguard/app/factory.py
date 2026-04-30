"""FastAPI factory + lifecycle wiring for the ciguard GitHub App.

Threat model: `Project ciguard/THREAT_MODEL.md` Surface 9. This module
is where the v0.10.0 design commitments are turned into a running
service:

  - Webhook router from `webhook.py` (HMAC + 202 ack + replay defence)
  - Scheduler from `scheduler.py` (idempotency + bounded queue + per-
    repo lock) attached to `app.state.scheduler` so the webhook
    handler reaches it via `request.app.state.scheduler.enqueue(...)`.
  - Scan executor injected at startup. v0.10.0 ships a STUB executor
    (returns a "scan-not-yet-implemented" result that still posts a
    Check Run + PR comment so the receiver wiring is verifiable end-
    to-end). v0.10.1 wires the real executor that clones the repo via
    the installation token and runs `ciguard scan-repo` against it.

The stub is honest about its scope: every scan posts a comment that
explicitly says "ciguard receiver wired; scan execution lands in
v0.10.1" so installers can confirm the App is reachable without being
misled into thinking they're getting real findings yet.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional

from fastapi import FastAPI

from .scan_runner import run_scan
from .scheduler import ScanJob, ScanScheduler
from .webhook import router as webhook_router

logger = logging.getLogger("ciguard.app.factory")


# ---- Stub scan executor (v0.10.0) ------------------------------------------


async def _stub_scan_executor(job: ScanJob) -> dict[str, Any]:
    """Returns a placeholder scan result so v0.10.0 can demonstrate
    end-to-end webhook → Check Run + PR comment plumbing without yet
    cloning repos or running real scans. Replaced in v0.10.1 by the
    real executor (clone via installation token; run ciguard scan-repo
    against the local checkout)."""
    logger.info(
        "stub executor handling job (installation=%d repo=%s head=%s)",
        job.installation_id, job.repo_full_name, job.head_sha[:7],
    )
    return {
        "risk_score": 100,
        "grade": "A",
        "findings": [],
        "summary": (
            "ciguard receiver wired; actual scan execution lands in "
            "v0.10.1. The Check Run + PR comment plumbing on this PR "
            "is real — only the rule-evaluation step is stubbed."
        ),
    }


# ---- Lifespan / lifecycle --------------------------------------------------


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """FastAPI lifespan — start scheduler at app startup, drain on
    shutdown. Replaces the deprecated @app.on_event hooks."""
    executor = getattr(app.state, "scan_executor", None) or _stub_scan_executor

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
      scan_executor: Optional injection point. Defaults to the v0.10.0
        stub. Tests pass their own; v0.10.1 will pass a real
        clone-and-scan executor.
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
