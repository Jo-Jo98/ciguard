"""Tests for the v0.10.0 GitHub App webhook receiver.

Covers the three Surface 9 STRIDE rows that THIS file's code is meant to
close (per `Project ciguard/THREAT_MODEL.md`):
  - Webhook signature bypass (Highest, DREAD 21)
  - Webhook replay (High, DREAD 18)
  - Webhook handler DoS — large payload (High, DREAD 18)

Plus structural assertions so the design commitments can't silently regress:
  - HMAC computed over RAW bytes, not a parsed-then-reserialised body
  - `hmac.compare_digest` on the path (no `==` slip)
  - Logger never emits the supplied signature, secret, or token strings
  - Webhook secret read from env on every call (no module-level cache)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.app import config, webhook  # noqa: E402

WEBHOOK_SECRET = "test-secret-for-app-webhook-do-not-use-in-prod"


def _sign(body: bytes, secret: bytes = WEBHOOK_SECRET.encode()) -> str:
    """Mirror GitHub's signature format — `sha256=<hex>` over raw body."""
    return "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv(config.WEBHOOK_SECRET_ENV, WEBHOOK_SECRET)
    config.reset_delivery_cache_for_tests()
    app = FastAPI()
    app.include_router(webhook.router)
    return TestClient(app)


# ---- Happy path -------------------------------------------------------------


def test_valid_signature_returns_202(client: TestClient) -> None:
    body = b'{"action":"opened","number":1}'
    resp = client.post(
        "/webhook",
        content=body,
        headers={
            "X-Hub-Signature-256": _sign(body),
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": "11111111-1111-1111-1111-111111111111",
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 202
    assert resp.json()["status"] == "accepted"


# ---- Signature bypass — STRIDE row "Webhook signature bypass" ---------------


def test_missing_signature_header_returns_401(client: TestClient) -> None:
    resp = client.post(
        "/webhook", content=b"{}", headers={"X-GitHub-Delivery": "a"}
    )
    assert resp.status_code == 401
    assert "Missing" in resp.json()["detail"]


def test_malformed_signature_prefix_returns_401(client: TestClient) -> None:
    """Anything not starting with `sha256=` is rejected — including
    `sha1=...` (GitHub's old + insecure header)."""
    resp = client.post(
        "/webhook",
        content=b"{}",
        headers={
            "X-Hub-Signature-256": "sha1=deadbeef",
            "X-GitHub-Delivery": "a",
        },
    )
    assert resp.status_code == 401
    assert "Malformed" in resp.json()["detail"]


def test_wrong_signature_returns_401(client: TestClient) -> None:
    body = b'{"action":"opened"}'
    bogus = "sha256=" + "0" * 64
    resp = client.post(
        "/webhook",
        content=body,
        headers={"X-Hub-Signature-256": bogus, "X-GitHub-Delivery": "a"},
    )
    assert resp.status_code == 401
    assert "mismatch" in resp.json()["detail"].lower()


def test_signature_computed_over_raw_bytes_not_reserialised(
    client: TestClient,
) -> None:
    """A body GitHub sends as `{"a":1}` (no whitespace) re-serialised
    by us as `{"a": 1}` (with space) would have a different HMAC and
    would silently fail. Guard against any future code path that calls
    `await request.json()` before verifying."""
    body = b'{"a":1,"b":2}'  # exactly these bytes — no whitespace
    resp = client.post(
        "/webhook",
        content=body,
        headers={"X-Hub-Signature-256": _sign(body), "X-GitHub-Delivery": "a"},
    )
    assert resp.status_code == 202


def test_secret_unset_returns_500_not_default_accept(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If `CIGUARD_APP_WEBHOOK_SECRET` is unset, the handler MUST refuse —
    not silently fall through to "accept-without-verification"."""
    monkeypatch.delenv(config.WEBHOOK_SECRET_ENV, raising=False)
    config.reset_delivery_cache_for_tests()
    app = FastAPI()
    app.include_router(webhook.router)
    c = TestClient(app)
    body = b"{}"
    resp = c.post(
        "/webhook",
        content=body,
        headers={"X-Hub-Signature-256": _sign(body), "X-GitHub-Delivery": "a"},
    )
    assert resp.status_code == 500


def test_secret_read_per_request_supports_rotation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rotating the secret without app restart must work — that's the
    point of reading env on every verify."""
    monkeypatch.setenv(config.WEBHOOK_SECRET_ENV, "secret-A")
    config.reset_delivery_cache_for_tests()
    app = FastAPI()
    app.include_router(webhook.router)
    c = TestClient(app)
    body = b"{}"

    # Round 1 — signed with secret-A, env has secret-A → 202.
    sig_a = _sign(body, b"secret-A")
    r1 = c.post(
        "/webhook",
        content=body,
        headers={"X-Hub-Signature-256": sig_a, "X-GitHub-Delivery": "d1"},
    )
    assert r1.status_code == 202

    # Operator rotates the env — same body still signed with secret-A,
    # now-current secret is secret-B → 401 (signature mismatch).
    monkeypatch.setenv(config.WEBHOOK_SECRET_ENV, "secret-B")
    r2 = c.post(
        "/webhook",
        content=body,
        headers={"X-Hub-Signature-256": sig_a, "X-GitHub-Delivery": "d2"},
    )
    assert r2.status_code == 401


def test_constant_time_compare_used(monkeypatch: pytest.MonkeyPatch) -> None:
    """Source-level assertion: the verifier must call `hmac.compare_digest`,
    NOT `==`. Hard to detect timing attacks via behaviour, so guard via the
    code path being exercised — replace `compare_digest` with a spy and
    assert it ran."""
    monkeypatch.setenv(config.WEBHOOK_SECRET_ENV, WEBHOOK_SECRET)
    config.reset_delivery_cache_for_tests()
    calls: list[tuple] = []
    real = hmac.compare_digest

    def spy(a, b):  # type: ignore[no-untyped-def]
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(webhook.hmac, "compare_digest", spy)
    app = FastAPI()
    app.include_router(webhook.router)
    c = TestClient(app)
    body = b"{}"
    c.post(
        "/webhook",
        content=body,
        headers={"X-Hub-Signature-256": _sign(body), "X-GitHub-Delivery": "a"},
    )
    assert len(calls) == 1


# ---- Replay defence — STRIDE row "Webhook replay" ---------------------------


def test_duplicate_delivery_id_acks_without_dispatch(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    body = b'{"action":"opened"}'
    headers = {
        "X-Hub-Signature-256": _sign(body),
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "deadbeef-1234-1234-1234-deadbeefcafe",
    }

    with caplog.at_level(logging.INFO, logger="ciguard.app.webhook"):
        r1 = client.post("/webhook", content=body, headers=headers)
        r2 = client.post("/webhook", content=body, headers=headers)

    assert r1.status_code == 202
    assert r1.json()["status"] == "accepted"
    assert r2.status_code == 200  # ack-and-skip — not 202
    assert r2.json()["status"] == "duplicate"

    accepted_log = [r for r in caplog.records if "accepted webhook" in r.message]
    skipped_log = [r for r in caplog.records if "ack-and-skip" in r.message]
    assert len(accepted_log) == 1
    assert len(skipped_log) == 1


# ---- DoS defence — STRIDE row "Webhook handler DoS" -------------------------


def test_oversized_body_returns_413(client: TestClient) -> None:
    huge = b"x" * (webhook.MAX_BODY_BYTES + 1)
    resp = client.post(
        "/webhook",
        content=huge,
        headers={"X-Hub-Signature-256": _sign(huge), "X-GitHub-Delivery": "a"},
    )
    assert resp.status_code == 413


# ---- Logger hygiene — defence-in-depth on token / secret leakage ------------


def test_log_injection_via_header_crlf_is_defeated(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    """Attacker-controlled header values must be CR/LF-stripped before
    they hit the logger, otherwise a forged delivery ID like
    `aaa\\nERROR fake-line` ends up as a separate-looking log entry."""
    config.reset_delivery_cache_for_tests()
    body = b'{"a":1}'
    sneaky_delivery = "aaa\r\nERROR fake-injected-line"

    with caplog.at_level(logging.INFO, logger="ciguard.app.webhook"):
        client.post(
            "/webhook",
            content=body,
            headers={
                "X-Hub-Signature-256": _sign(body),
                "X-GitHub-Delivery": sneaky_delivery,
                "X-GitHub-Event": "push",
            },
        )

    # Each individual log message must contain no real CR/LF — the
    # sanitiser replaces them with `?`. That alone defeats the attack
    # (an attacker can no longer make their content appear on a fresh
    # line that downstream log parsers would treat as a separate entry).
    for record in caplog.records:
        assert "\r" not in record.message
        assert "\n" not in record.message
    # The sanitised replacement landed.
    text = " | ".join(r.message for r in caplog.records)
    assert "aaa??ERROR" in text


# ---- Dispatch — installation_id derived from VERIFIED payload --------------


def _client_with_scheduler(monkeypatch):  # type: ignore[no-untyped-def]
    """Build a client whose app has a stub scheduler on app.state."""
    from unittest.mock import AsyncMock, MagicMock
    from ciguard.app.scheduler import EnqueueOutcome

    monkeypatch.setenv(config.WEBHOOK_SECRET_ENV, WEBHOOK_SECRET)
    config.reset_delivery_cache_for_tests()

    scheduler = MagicMock()
    scheduler.enqueue = AsyncMock(
        return_value=EnqueueOutcome(accepted=True, reason="enqueued")
    )

    app = FastAPI()
    app.include_router(webhook.router)
    app.state.scheduler = scheduler
    return TestClient(app), scheduler


def test_pull_request_event_dispatches_with_installation_from_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The headline IDOR-defence test at the API boundary. A
    well-formed pull_request webhook payload carries an
    `installation.id` — that's the one the dispatcher must use.
    Caller-controlled headers / URL params MUST NOT influence it."""
    client, scheduler = _client_with_scheduler(monkeypatch)
    payload = {
        "action": "opened",
        "number": 42,
        "installation": {"id": 88888},
        "repository": {"full_name": "owner/repo"},
        "pull_request": {
            "number": 42,
            "head": {"sha": "deadbeef" * 5},
        },
    }
    body = json.dumps(payload).encode()
    resp = client.post(
        "/webhook",
        content=body,
        headers={
            "X-Hub-Signature-256": _sign(body),
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": "abc-1",
            # Caller plants a DIFFERENT installation_id in a URL-style
            # header — the dispatcher MUST ignore it.
            "X-Caller-Installation-Id": "11111",
        },
    )
    assert resp.status_code == 202
    scheduler.enqueue.assert_awaited_once()
    job = scheduler.enqueue.call_args.args[0]
    assert job.installation_id == 88888  # from payload, not header
    assert job.repo_full_name == "owner/repo"
    assert job.head_sha == "deadbeef" * 5
    assert job.pr_number == 42
    assert job.event == "pull_request"


def test_push_event_dispatches_with_after_sha(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, scheduler = _client_with_scheduler(monkeypatch)
    payload = {
        "ref": "refs/heads/main",
        "after": "cafebabe" * 5,
        "installation": {"id": 99999},
        "repository": {"full_name": "owner/repo"},
    }
    body = json.dumps(payload).encode()
    resp = client.post(
        "/webhook",
        content=body,
        headers={
            "X-Hub-Signature-256": _sign(body),
            "X-GitHub-Event": "push",
            "X-GitHub-Delivery": "push-1",
        },
    )
    assert resp.status_code == 202
    job = scheduler.enqueue.call_args.args[0]
    assert job.installation_id == 99999
    assert job.head_sha == "cafebabe" * 5
    assert job.pr_number is None
    assert job.event == "push"


def test_payload_without_installation_does_not_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Events without an installation block (ping, some App-config
    events) — acknowledge cleanly, don't enqueue."""
    client, scheduler = _client_with_scheduler(monkeypatch)
    body = json.dumps({"zen": "Approachable is better than simple."}).encode()
    resp = client.post(
        "/webhook",
        content=body,
        headers={
            "X-Hub-Signature-256": _sign(body),
            "X-GitHub-Event": "ping",
            "X-GitHub-Delivery": "ping-1",
        },
    )
    assert resp.status_code == 202
    scheduler.enqueue.assert_not_called()


def test_queue_full_surfaces_as_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bounded-queue backpressure — webhook handler returns 503 so
    GitHub retries; design commitment from THREAT_MODEL Surface 9
    'Webhook handler DoS' row."""
    from unittest.mock import AsyncMock, MagicMock
    from ciguard.app.scheduler import EnqueueOutcome

    monkeypatch.setenv(config.WEBHOOK_SECRET_ENV, WEBHOOK_SECRET)
    config.reset_delivery_cache_for_tests()

    scheduler = MagicMock()
    scheduler.enqueue = AsyncMock(
        return_value=EnqueueOutcome(accepted=False, reason="queue_full")
    )
    app = FastAPI()
    app.include_router(webhook.router)
    app.state.scheduler = scheduler
    client = TestClient(app)

    payload = {
        "installation": {"id": 1},
        "repository": {"full_name": "o/r"},
        "after": "a" * 40,
    }
    body = json.dumps(payload).encode()
    resp = client.post(
        "/webhook",
        content=body,
        headers={
            "X-Hub-Signature-256": _sign(body),
            "X-GitHub-Event": "push",
            "X-GitHub-Delivery": "qf-1",
        },
    )
    assert resp.status_code == 503
    assert "queue full" in resp.json()["detail"].lower()


def test_no_scheduler_on_app_state_returns_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If a deployment forgets to use the factory's lifespan,
    surface a 503 rather than a 500 — the App is up but not ready."""
    monkeypatch.setenv(config.WEBHOOK_SECRET_ENV, WEBHOOK_SECRET)
    config.reset_delivery_cache_for_tests()

    app = FastAPI()
    app.include_router(webhook.router)
    # Note: app.state.scheduler intentionally NOT set.
    client = TestClient(app)

    payload = {
        "installation": {"id": 1},
        "repository": {"full_name": "o/r"},
        "after": "a" * 40,
    }
    body = json.dumps(payload).encode()
    resp = client.post(
        "/webhook",
        content=body,
        headers={
            "X-Hub-Signature-256": _sign(body),
            "X-GitHub-Event": "push",
            "X-GitHub-Delivery": "ns-1",
        },
    )
    assert resp.status_code == 503


def test_logger_never_emits_secret_or_supplied_signature(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    """Run a happy path and a 401 path; assert no log line contains the
    secret material or the full presented signature. (The 6-char prefix
    is allowed — that's intentional for forensics.)"""
    config.reset_delivery_cache_for_tests()
    body = b'{"action":"opened"}'
    bogus = "sha256=" + "f" * 64

    with caplog.at_level(logging.DEBUG, logger="ciguard.app.webhook"):
        client.post(
            "/webhook",
            content=body,
            headers={
                "X-Hub-Signature-256": _sign(body),
                "X-GitHub-Delivery": "ok-1",
            },
        )
        client.post(
            "/webhook",
            content=body,
            headers={"X-Hub-Signature-256": bogus, "X-GitHub-Delivery": "bad"},
        )

    text = "\n".join(r.message for r in caplog.records)
    assert WEBHOOK_SECRET not in text
    # Full presented signature must not be logged; only a 6-char prefix.
    assert "f" * 64 not in text
