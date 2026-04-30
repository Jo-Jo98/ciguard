"""Tests for the v0.10.0 GitHub App FastAPI factory.

Verifies the lifespan hook wires the scheduler onto app.state and
drains it on shutdown. The webhook → scheduler → scan_runner flow is
covered end-to-end by injecting a sentinel scan_executor that records
the ScanJob it received.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sys
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.app import config, factory  # noqa: E402

WEBHOOK_SECRET = "factory-test-secret"


def _sign(body: bytes) -> str:
    return "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode(), body, hashlib.sha256
    ).hexdigest()


def test_create_app_returns_fastapi_with_lifespan(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv(config.WEBHOOK_SECRET_ENV, WEBHOOK_SECRET)
    config.reset_delivery_cache_for_tests()
    app = factory.create_app()
    # Lifespan must be wired (TestClient enters/exits it).
    with TestClient(app) as client:
        # Healthz endpoint always returns 200.
        resp = client.get("/healthz")
        assert resp.status_code == 200
        # Scheduler attached to app.state during the lifespan window.
        assert app.state.scheduler is not None


def test_webhook_dispatches_via_factory_wired_scheduler(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """End-to-end: a webhook arrives at an app produced by create_app(),
    the stub executor records the job. (Drain semantics on shutdown
    are tested directly in test_app_scheduler.py — calling .join() on
    a different event loop than the queue's deadlocks, so we don't
    repeat that assertion here.)"""
    import time

    from ciguard.app import checks

    monkeypatch.setenv(config.WEBHOOK_SECRET_ENV, WEBHOOK_SECRET)
    config.reset_delivery_cache_for_tests()
    # Stub the GitHub HTTP surface — `run_scan` calls into `checks` after
    # the executor returns; without these stubs it tries to mint a real
    # JWT and the test ends up depending on env config.
    monkeypatch.setattr(checks, "create_check_run", lambda **kw: 1)
    monkeypatch.setattr(checks, "complete_check_run", lambda **kw: None)
    monkeypatch.setattr(checks, "set_check_run_failed", lambda **kw: None)
    monkeypatch.setattr(
        checks, "post_or_update_pr_comment", lambda **kw: 1
    )

    seen_jobs: list[Any] = []

    async def recording_executor(job) -> dict[str, Any]:  # type: ignore[no-untyped-def]
        seen_jobs.append(job)
        return {"risk_score": 100, "grade": "A", "findings": []}

    app = factory.create_app(scan_executor=recording_executor)
    payload = {
        "installation": {"id": 12345},
        "repository": {"full_name": "owner/repo"},
        "after": "deadbeef" * 5,
    }
    body = json.dumps(payload).encode()

    with TestClient(app) as client:
        resp = client.post(
            "/webhook",
            content=body,
            headers={
                "X-Hub-Signature-256": _sign(body),
                "X-GitHub-Event": "push",
                "X-GitHub-Delivery": "factory-test-1",
            },
        )
        assert resp.status_code == 202

        # Give the worker a brief window to dequeue + reach the
        # executor stub. Polling is cheaper than a sleep + more
        # robust under load.
        deadline = time.time() + 2.0
        while not seen_jobs and time.time() < deadline:
            time.sleep(0.02)

    assert len(seen_jobs) >= 1
    job = seen_jobs[0]
    assert job.installation_id == 12345
    assert job.repo_full_name == "owner/repo"


def test_app_metadata_advertises_v0_10_0(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Sanity check that the version string in factory.create_app()
    stays in sync with releases — easy to forget at ship time."""
    monkeypatch.setenv(config.WEBHOOK_SECRET_ENV, WEBHOOK_SECRET)
    app = factory.create_app()
    assert app.version == "0.10.0"


def test_docs_endpoints_disabled_by_default(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Webhook receiver is not a public REST API — hide the docs
    routes so they don't become an information-disclosure footgun."""
    monkeypatch.setenv(config.WEBHOOK_SECRET_ENV, WEBHOOK_SECRET)
    app = factory.create_app()
    with TestClient(app) as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404
