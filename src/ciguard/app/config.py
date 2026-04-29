"""Environment-driven config for the ciguard GitHub App.

Mirrors the `src/ciguard/web/auth.py` pattern from v0.9.1 deployment hardening:
read on every call (no module-level cache) so tests can monkey-patch and
operators can rotate without restart.
"""
from __future__ import annotations

import os
import time
from typing import Optional

WEBHOOK_SECRET_ENV = "CIGUARD_APP_WEBHOOK_SECRET"


def webhook_secret() -> Optional[bytes]:
    """Return the webhook secret as bytes, or None when unset.

    GitHub HMAC-signs the raw body bytes with this secret; we verify on every
    delivery. Reading from env on every call lets `kubectl set env` / systemd
    reloads pick up the new value without restart, the same property
    `CIGUARD_WEB_TOKEN` has.
    """
    raw = os.environ.get(WEBHOOK_SECRET_ENV)
    if not raw or not raw.strip():
        return None
    return raw.strip().encode("utf-8")


# ---- Delivery-ID dedup cache -----------------------------------------------
#
# GitHub retries webhook deliveries up to 3× on 5xx + non-2xx-within-10s.
# Every retry carries the same X-GitHub-Delivery UUID; this in-memory cache
# is what keeps replays / honest-retries from triggering duplicate downstream
# work (idempotency requirement from THREAT_MODEL.md Surface 9 row "Webhook
# replay").
#
# Scope of this cache: a single Python process. A multi-replica deployment
# needs an external store (Redis / DynamoDB) — wired in a later v0.10.x
# release; the function shape below stays stable.

_DELIVERY_TTL_SECONDS = 60 * 60  # 1 hour — covers GitHub's retry envelope
_seen_deliveries: dict[str, float] = {}


def _purge_expired(now: float) -> None:
    cutoff = now - _DELIVERY_TTL_SECONDS
    stale = [k for k, ts in _seen_deliveries.items() if ts < cutoff]
    for k in stale:
        _seen_deliveries.pop(k, None)


def is_delivery_seen(delivery_id: str) -> bool:
    """Has this X-GitHub-Delivery UUID been processed within the TTL window?

    Returns False on first sight + records the timestamp; returns True on any
    subsequent call within TTL. Caller decides what 'seen' means downstream
    (we currently 200-ack and skip work — see webhook.py)."""
    if not delivery_id:
        return False
    now = time.time()
    _purge_expired(now)
    if delivery_id in _seen_deliveries:
        return True
    _seen_deliveries[delivery_id] = now
    return False


def reset_delivery_cache_for_tests() -> None:
    """Test-only — clear the in-memory dedup cache between cases."""
    _seen_deliveries.clear()
