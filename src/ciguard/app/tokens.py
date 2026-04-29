"""GitHub App JWT minting + installation-scoped token broker.

Threat model: `Project ciguard/THREAT_MODEL.md` Surface 9. Three threats are
fully closed by THIS file:

  - "Installation token leakage in logs" — logger emits prefix-only
    fingerprints (`ghs_abc1…`); never the full token, JWT, or private key.
  - "App private key exposure at rest" — key loaded from env on first call,
    never written to disk by ciguard, never logged. Loader emits byte-count
    + sha256 fingerprint only.
  - "Cached installation token used after revocation" — `invalidate_token()`
    is the contract every API caller honours on 401; the next webhook
    reproves the install before a fresh token is minted.

Design commitments from THREAT_MODEL.md "v0.10.0 design rationale":

  1. JWT signing only inside `_mint_jwt()` — no other code path touches the
     private key. JWTs are short-lived (10 min); we never persist them.
  2. Token cache keyed by `installation_id`; cache value redacted on log.
     Default TTL trimmed to 30 minutes (GitHub's installation-token default
     is 1 hour; we shorten to bound the post-revocation exposure window).
  3. Any 401 from a downstream GitHub API call → caller invalidates the
     cached token; next get_token() re-mints a JWT + re-exchanges.

Required environment:

  - `CIGUARD_APP_ID` — the numeric App ID from GitHub.
  - `CIGUARD_APP_PRIVATE_KEY` (PEM bytes inline) OR
    `CIGUARD_APP_PRIVATE_KEY_PATH` (path to .pem on disk; for dev only).

The `_PATH` form is deliberately the worse-ergonomics option. Production
deployments should keep the key in a secret manager (KMS / Vault / k8s
Secret env var); the env-bytes path is the canonical way in.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

import jwt  # PyJWT — only available with the [app] extra installed

logger = logging.getLogger("ciguard.app.tokens")

APP_ID_ENV = "CIGUARD_APP_ID"
PRIVATE_KEY_ENV = "CIGUARD_APP_PRIVATE_KEY"
PRIVATE_KEY_PATH_ENV = "CIGUARD_APP_PRIVATE_KEY_PATH"

# GitHub installation tokens are issued with a 1h TTL by default. We trim
# our cache TTL to 30 min — half of that — so a revoked install can't keep
# using a cached token for the full hour. (Caller-side 401 handling closes
# the rest of the window.)
INSTALLATION_TOKEN_TTL_SECONDS = 30 * 60

# JWT for the App-level identity. GitHub accepts up to 10 min; we use 9m
# to stay clear of clock-skew edge cases.
JWT_LIFETIME_SECONDS = 9 * 60
# Backdate `iat` slightly in case GitHub's clock is a few seconds ahead.
JWT_IAT_OFFSET_SECONDS = -30

GITHUB_API_BASE = "https://api.github.com"

MAX_RESPONSE_BYTES = 64 * 1024  # GitHub's token-exchange response is small


def _redact(token: str, *, prefix: int = 6) -> str:
    """`ghs_a3df_long_token...` → `ghs_a3…` for safe forensic logging."""
    if not token:
        return "<empty>"
    return f"{token[:prefix]}…"


# ---- Config loaders --------------------------------------------------------


def _load_app_id() -> int:
    raw = os.environ.get(APP_ID_ENV)
    if not raw or not raw.strip():
        raise RuntimeError(
            f"{APP_ID_ENV} is not set — required to mint App JWTs."
        )
    try:
        return int(raw.strip())
    except ValueError as exc:
        raise RuntimeError(
            f"{APP_ID_ENV} must be an integer (got {raw!r})."
        ) from exc


def _load_private_key() -> bytes:
    """Load the App's RS256 private key from env, fallback to PATH.

    Logs only `(byte_count, sha256_fingerprint)` — never the key material
    itself, never the path beyond a leaf-name redaction.
    """
    inline = os.environ.get(PRIVATE_KEY_ENV)
    if inline and inline.strip():
        key_bytes = inline.encode("utf-8")
        _log_key_loaded(source="env", key_bytes=key_bytes)
        return key_bytes

    path = os.environ.get(PRIVATE_KEY_PATH_ENV)
    if path and path.strip():
        try:
            with open(path.strip(), "rb") as f:
                key_bytes = f.read()
        except OSError as exc:
            raise RuntimeError(
                f"failed to read {PRIVATE_KEY_PATH_ENV}: {exc.strerror}"
            ) from exc
        # Strip CR/LF defensively — env values are operator-controlled and
        # therefore trusted, but a basename can still carry stray newlines
        # if the operator's env injection has them. Defeats CodeQL's
        # py/log-injection heuristic and any downstream log-parser confusion.
        leaf = os.path.basename(path).replace("\r", "?").replace("\n", "?")
        _log_key_loaded(source=f"path:{leaf}", key_bytes=key_bytes)
        return key_bytes

    raise RuntimeError(
        f"neither {PRIVATE_KEY_ENV} nor {PRIVATE_KEY_PATH_ENV} is set — "
        "App private key is required to mint JWTs."
    )


def _log_key_loaded(*, source: str, key_bytes: bytes) -> None:
    fingerprint = hashlib.sha256(key_bytes).hexdigest()[:12]
    logger.info(
        "loaded App private key (source=%s len=%d sha256=%s…)",
        source, len(key_bytes), fingerprint,
    )


# ---- JWT minting (the ONLY place the private key is touched) -------------


def _mint_jwt(*, now: Optional[float] = None) -> str:
    """Sign a 9-min App-level JWT with iss=app_id, RS256.

    This is the ONLY function that handles the private key bytes. Every
    other path goes through the installation-token cache below.
    """
    if now is None:
        now = time.time()
    app_id = _load_app_id()
    key = _load_private_key()
    payload = {
        "iat": int(now) + JWT_IAT_OFFSET_SECONDS,
        "exp": int(now) + JWT_LIFETIME_SECONDS,
        "iss": str(app_id),  # PyJWT 2.x requires string `iss`
    }
    token = jwt.encode(payload, key, algorithm="RS256")
    # PyJWT 2.x returns str; older versions returned bytes — normalise.
    if isinstance(token, bytes):
        token = token.decode("ascii")
    logger.debug("minted JWT (iss=%d exp=%d)", app_id, payload["exp"])
    return token


# ---- Installation-token cache --------------------------------------------


@dataclass
class _CacheEntry:
    token: str
    expires_at: float  # local epoch seconds


_token_cache: dict[int, _CacheEntry] = {}


def invalidate_token(installation_id: int) -> None:
    """Drop the cached token for an installation. Callers MUST invoke this
    on any 401 from a GitHub API call (THREAT_MODEL row "Cached
    installation token used after revocation")."""
    if installation_id in _token_cache:
        entry = _token_cache.pop(installation_id)
        logger.info(
            "invalidated cached token (installation=%d prefix=%s)",
            installation_id, _redact(entry.token),
        )


def reset_token_cache_for_tests() -> None:
    """Test-only — wipe every cached entry."""
    _token_cache.clear()


def get_installation_token(
    installation_id: int, *, now: Optional[float] = None
) -> str:
    """Return a fresh `ghs_…` token scoped to the given installation.

    Cache-first; on miss (or expiry) mints a JWT and exchanges it via
    `POST /app/installations/{id}/access_tokens`. Trims the effective
    TTL to 30 min regardless of GitHub's stated `expires_at` so revoked
    installs can't keep a cached token for the full hour.
    """
    if now is None:
        now = time.time()
    cached = _token_cache.get(installation_id)
    if cached and cached.expires_at > now:
        logger.debug(
            "token cache hit (installation=%d prefix=%s)",
            installation_id, _redact(cached.token),
        )
        return cached.token

    # Miss / expired → mint a fresh JWT + exchange.
    app_jwt = _mint_jwt(now=now)
    token = _exchange_jwt_for_installation_token(app_jwt, installation_id)
    _token_cache[installation_id] = _CacheEntry(
        token=token,
        expires_at=now + INSTALLATION_TOKEN_TTL_SECONDS,
    )
    logger.info(
        "minted installation token (installation=%d prefix=%s ttl=%ds)",
        installation_id, _redact(token), INSTALLATION_TOKEN_TTL_SECONDS,
    )
    return token


# ---- HTTP exchange --------------------------------------------------------


def _exchange_jwt_for_installation_token(app_jwt: str, installation_id: int) -> str:
    """Call `POST /app/installations/{id}/access_tokens`.

    Stdlib urllib.request — same pattern as the SCA EOL/CVE clients. The
    URL is hardcoded HTTPS to api.github.com; B310 nosec'd on that line.
    """
    url = f"{GITHUB_API_BASE}/app/installations/{installation_id}/access_tokens"
    req = urllib.request.Request(
        url,
        method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {app_jwt}",
            "User-Agent": "ciguard-app",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        data=b"",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
            body = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise RuntimeError("token-exchange response exceeded size cap")
            payload = json.loads(body.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # Don't log the body — GitHub error responses sometimes echo the
        # request, and the request had our JWT in the Authorization header.
        raise RuntimeError(
            f"GitHub token exchange failed: HTTP {exc.code}"
        ) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"GitHub token exchange failed: {exc}") from exc

    token = payload.get("token")
    if not isinstance(token, str) or not token:
        raise RuntimeError("token-exchange response missing `token` field")
    return token
