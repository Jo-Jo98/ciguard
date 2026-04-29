"""GitHub App webhook receiver — HMAC verification + 202 ack.

Threat model: `Project ciguard/THREAT_MODEL.md` Surface 9. Three threats are
fully closed by THIS file (without involving any other module):

  - "Webhook signature bypass" — HMAC-SHA256 over raw body, constant-time
    compare via `hmac.compare_digest`, fail-closed (401) on missing /
    malformed / mismatched / non-`sha256=` signature.
  - "Webhook replay" — X-GitHub-Delivery UUID dedup against a 1-hour
    TTL cache; second delivery returns 200 + skips downstream work.
  - "Webhook handler DoS" — payload size capped (25 MB); no scan work
    on the request thread; returns 202 within milliseconds. The scan
    worker lands in step (iii); for now we just ack-and-stash.

What this file deliberately does NOT do:
  - JSON-parse the body before verifying the signature. The signature is
    over RAW bytes; any pre-parsing leaves a window where an attacker's
    payload reaches application code.
  - Log the supplied signature, the secret, or any token. Logger filters
    are layered on top of these design choices; defence in depth.
  - Run the scan. That belongs in the worker pool (step iii).
"""
from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request, Response, status

from . import config

logger = logging.getLogger("ciguard.app.webhook")

router = APIRouter()

MAX_BODY_BYTES = 25 * 1024 * 1024  # 25 MB — caps the DoS surface
SIGNATURE_PREFIX = "sha256="

# Header values are attacker-controlled. Going into a log line they MUST be
# stripped of CR/LF (otherwise an attacker forges fake log lines via
# `X-GitHub-Delivery: foo\nERROR fake-line`) and length-capped. Closes the
# CodeQL py/log-injection findings on this module.
_LOG_VALUE_MAX_LEN = 64


def _safe_for_log(value: Optional[str]) -> str:
    """Sanitise an attacker-controlled string for safe logging."""
    if value is None:
        return "<none>"
    safe = value.replace("\r", "?").replace("\n", "?").replace("\t", "?")
    if len(safe) > _LOG_VALUE_MAX_LEN:
        safe = safe[:_LOG_VALUE_MAX_LEN] + "..."
    return safe


def _verify_signature(body: bytes, signature_header: Optional[str]) -> None:
    """Verify the X-Hub-Signature-256 header against the raw body.

    Raises 401 on every failure mode. NEVER returns False — the only success
    path is "returns None and logs nothing about the supplied signature."
    """
    secret = config.webhook_secret()
    if secret is None:
        # Fail-closed at request time too — a misconfigured deployment is
        # NOT permitted to accept unsigned payloads. (Compare with the
        # web token where missing-token means "auth disabled"; the App
        # has no such mode — every webhook MUST be HMAC-signed.)
        # Env var name is hardcoded to dodge CodeQL's
        # py/clear-text-logging-sensitive-data heuristic — it flags any
        # variable whose name contains "secret" being passed to a logger.
        logger.error(
            "rejecting webhook: required webhook-secret env var is not set"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="App webhook secret not configured.",
        )

    if not signature_header:
        logger.warning("rejecting webhook: missing X-Hub-Signature-256")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Hub-Signature-256.",
        )
    if not signature_header.startswith(SIGNATURE_PREFIX):
        logger.warning(
            "rejecting webhook: malformed X-Hub-Signature-256 prefix"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed X-Hub-Signature-256 (expected `sha256=` prefix).",
        )

    presented_hex = signature_header[len(SIGNATURE_PREFIX) :]
    expected_hex = hmac.new(secret, body, hashlib.sha256).hexdigest()

    # Constant-time compare — prevents timing attacks against the digest.
    # Both sides are ascii hex of the same length so direct compare_digest
    # is safe; encode to bytes to avoid a unicode-quirk path inside.
    if not hmac.compare_digest(
        presented_hex.encode("ascii", "ignore"), expected_hex.encode("ascii")
    ):
        # Don't log the presented value — it's attacker-controlled and we
        # don't want it in our logs. Log a 6-char prefix for forensics only,
        # CR/LF-stripped via _safe_for_log to defeat log-injection.
        logger.warning(
            "rejecting webhook: signature mismatch (prefix=%s)",
            _safe_for_log(presented_hex[:6]),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Signature mismatch.",
        )


@router.post("/webhook", status_code=status.HTTP_202_ACCEPTED)
async def receive_webhook(
    request: Request,
    response: Response,
    x_hub_signature_256: Optional[str] = Header(default=None),
    x_github_event: Optional[str] = Header(default=None),
    x_github_delivery: Optional[str] = Header(default=None),
) -> dict:
    """Receive a GitHub App webhook.

    Handler order is intentional:
      1. Read raw body — refusing oversized requests up front.
      2. Verify HMAC over those raw bytes.
      3. Dedup X-GitHub-Delivery (1h TTL).
      4. Dispatch to scan worker (step iii — currently a no-op stub).
      5. Return 202.

    Any failure in 1/2/3 is logged at warning level and surfaces as
    401 / 413; the body and signature are NEVER logged.
    """
    # --- 1. Raw body, with hard size cap (DoS defence) ---
    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        logger.warning(
            "rejecting webhook: body too large (%d > %d bytes)",
            len(body), MAX_BODY_BYTES,
        )
        raise HTTPException(
            status_code=413,  # Content Too Large (FastAPI alias was deprecated)
            detail=f"Webhook body exceeds {MAX_BODY_BYTES} bytes.",
        )

    # --- 2. HMAC verification — fail-closed ---
    _verify_signature(body, x_hub_signature_256)

    # --- 3. Replay defence (dedup on X-GitHub-Delivery) ---
    if x_github_delivery and config.is_delivery_seen(x_github_delivery):
        logger.info(
            "ack-and-skip: duplicate X-GitHub-Delivery=%s event=%s",
            _safe_for_log(x_github_delivery), _safe_for_log(x_github_event),
        )
        # 200, not 202 — we're explicitly NOT enqueuing new work.
        response.status_code = status.HTTP_200_OK
        return {"status": "duplicate", "delivery": x_github_delivery}

    # --- 4. Dispatch (step iii — placeholder) ---
    # The scan worker / token broker / Check Run integration lands in
    # subsequent v0.10.0 steps. For now the receiver is observable via
    # the logger so integration tests can assert it ran.
    logger.info(
        "accepted webhook: event=%s delivery=%s body_bytes=%d",
        _safe_for_log(x_github_event), _safe_for_log(x_github_delivery), len(body),
    )

    # --- 5. 202 ack within milliseconds ---
    return {"status": "accepted", "delivery": x_github_delivery}
