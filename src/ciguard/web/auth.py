"""Optional bearer-token auth for the ciguard web API (v0.9.1).

Default: no auth (unchanged from v0.9.0 — keeps the local-dev path frictionless).
Set `CIGUARD_WEB_TOKEN` in the environment to require `Authorization: Bearer <token>`
on every `/api/*` and `/report/*` request. Designed for the case where someone
hosts ciguard publicly: was an explicit deployment-boundary gap flagged in the
external code review (issue #9 / GHSA private-vuln-reporting candidate).

Why an env var, not a config file:
  - Single switch (on/off + value); a config file's loader/precedence/schema
    machinery would be unjustified weight.
  - Plays nicely with container `--env`, systemd `Environment=`, MDM, k8s
    Secret env vars — every operator already has a path for this.
"""
from __future__ import annotations

import os
import secrets
from typing import Optional

from fastapi import Header, HTTPException, status


_WEB_TOKEN_ENV = "CIGUARD_WEB_TOKEN"


def _configured_token() -> Optional[str]:
    """Read the token from env on every call so tests can monkey-patch
    `os.environ` without restarting the FastAPI app."""
    raw = os.environ.get(_WEB_TOKEN_ENV)
    return raw.strip() if raw and raw.strip() else None


async def require_token(authorization: Optional[str] = Header(default=None)) -> None:
    """FastAPI dependency. No-op when CIGUARD_WEB_TOKEN is unset.

    Constant-time compare prevents timing-based token-recovery attacks against
    the (unlikely but possible) public deployment with a short token.
    """
    expected = _configured_token()
    if expected is None:
        return  # auth disabled — preserve existing behaviour

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header (expected `Bearer <token>`).",
            headers={"WWW-Authenticate": "Bearer"},
        )
    presented = authorization[len("Bearer ") :].strip()
    if not secrets.compare_digest(presented, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


def is_token_configured() -> bool:
    """True iff CIGUARD_WEB_TOKEN is set non-empty in the environment."""
    return _configured_token() is not None


def warn_if_public_bind_unauthenticated(host: str) -> Optional[str]:
    """Return a warning string when binding to a non-loopback host without a
    token configured. The dev `python -m ciguard.web.app` runner uses this to
    print the warning at startup; the message format matches the FastAPI uvicorn
    log style so operators see it inline.

    Returns None when there's nothing to warn about (loopback bind OR token set).
    """
    loopback = {"127.0.0.1", "::1", "localhost"}
    if host in loopback:
        return None
    if is_token_configured():
        return None
    return (
        "ciguard web is binding to a non-loopback address "
        f"(host={host!r}) with NO authentication configured. Anyone who can reach "
        "this host can upload pipeline configs and view previously-scanned "
        f"reports. Set {_WEB_TOKEN_ENV}=<random secret> to gate access, or "
        "restrict --host to 127.0.0.1 for local-only use."
    )
