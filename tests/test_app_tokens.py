"""Tests for the v0.10.0 GitHub App JWT + installation-token broker.

Covers the three Surface 9 STRIDE rows that THIS file's code is meant to
close (per `Project ciguard/THREAT_MODEL.md`):

  - Installation token leakage in logs (High, DREAD 17)
  - App private key exposure at rest (High, DREAD 17)
  - Cached installation token used after revocation (Low, DREAD 13)

Plus structural assertions matching the threat model's design rationale:
  - JWT signing only inside `_mint_jwt()` — no other path touches the key
  - Per-`installation_id` cache; no bleed between tenants
  - 30-min effective TTL (shorter than GitHub's 1h default)
  - Logger emits prefix-only fingerprints, never the full token / JWT / key
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from unittest.mock import patch

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.app import tokens  # noqa: E402


# ---- Test fixtures ----------------------------------------------------------


@pytest.fixture
def rsa_key_pair() -> tuple[bytes, bytes]:
    """Generate a throwaway RSA key pair for JWT signing in tests."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


@pytest.fixture
def app_env(
    monkeypatch: pytest.MonkeyPatch, rsa_key_pair: tuple[bytes, bytes]
) -> tuple[bytes, bytes]:
    """Set the App-ID + private-key env vars and clear any cached tokens."""
    private_pem, public_pem = rsa_key_pair
    monkeypatch.setenv(tokens.APP_ID_ENV, "12345")
    monkeypatch.setenv(tokens.PRIVATE_KEY_ENV, private_pem.decode())
    tokens.reset_token_cache_for_tests()
    return private_pem, public_pem


# ---- JWT minting ------------------------------------------------------------


def test_jwt_minted_with_correct_claims_and_rs256(
    app_env: tuple[bytes, bytes]
) -> None:
    _, public_pem = app_env
    token = tokens._mint_jwt(now=1_000_000)
    decoded = jwt.decode(
        token, public_pem, algorithms=["RS256"],
        options={"verify_exp": False},  # we assert exp structurally below
    )
    assert decoded["iss"] == "12345"
    # iat backdated by 30s; exp 9 minutes from now.
    assert decoded["iat"] == 1_000_000 + tokens.JWT_IAT_OFFSET_SECONDS
    assert decoded["exp"] == 1_000_000 + tokens.JWT_LIFETIME_SECONDS
    # exp - iat must be within GitHub's 10-min ceiling.
    assert decoded["exp"] - decoded["iat"] <= 10 * 60


def test_jwt_lifetime_is_under_githubs_10min_ceiling(
    app_env: tuple[bytes, bytes]
) -> None:
    """If anyone bumps JWT_LIFETIME_SECONDS past 10 min, GitHub will
    reject every JWT we mint — guard the constant."""
    assert tokens.JWT_LIFETIME_SECONDS <= 10 * 60


def test_missing_app_id_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(tokens.APP_ID_ENV, raising=False)
    monkeypatch.setenv(tokens.PRIVATE_KEY_ENV, "irrelevant")
    with pytest.raises(RuntimeError, match=tokens.APP_ID_ENV):
        tokens._mint_jwt()


def test_missing_private_key_fails_closed(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(tokens.APP_ID_ENV, "12345")
    monkeypatch.delenv(tokens.PRIVATE_KEY_ENV, raising=False)
    monkeypatch.delenv(tokens.PRIVATE_KEY_PATH_ENV, raising=False)
    with pytest.raises(RuntimeError, match="private key is required"):
        tokens._mint_jwt()


def test_private_key_path_form_works(
    monkeypatch: pytest.MonkeyPatch,
    rsa_key_pair: tuple[bytes, bytes],
    tmp_path: Path,
) -> None:
    """The _PATH form (load from disk) is documented as worse-ergonomics
    but must still work for dev. Verify it does."""
    private_pem, public_pem = rsa_key_pair
    keyfile = tmp_path / "app.pem"
    keyfile.write_bytes(private_pem)

    monkeypatch.setenv(tokens.APP_ID_ENV, "12345")
    monkeypatch.delenv(tokens.PRIVATE_KEY_ENV, raising=False)
    monkeypatch.setenv(tokens.PRIVATE_KEY_PATH_ENV, str(keyfile))
    tokens.reset_token_cache_for_tests()

    minted = tokens._mint_jwt(now=2_000_000)
    decoded = jwt.decode(
        minted, public_pem, algorithms=["RS256"],
        options={"verify_exp": False},
    )
    assert decoded["iss"] == "12345"


# ---- Sensitive-data hygiene (THREAT_MODEL row "private key at rest") -------


def test_loader_logs_byte_count_and_fingerprint_not_key_material(
    app_env: tuple[bytes, bytes],
    caplog: pytest.LogCaptureFixture,
) -> None:
    private_pem, _ = app_env
    with caplog.at_level(logging.INFO, logger="ciguard.app.tokens"):
        tokens._mint_jwt()

    text = "\n".join(r.message for r in caplog.records)
    # The full PEM must not appear in any log message.
    assert "BEGIN PRIVATE KEY" not in text
    assert "END PRIVATE KEY" not in text
    assert private_pem.decode() not in text
    # But a byte-count + fingerprint line must.
    assert "loaded App private key" in text
    assert f"len={len(private_pem)}" in text
    assert "sha256=" in text


# ---- Token cache + 401 invalidation -----------------------------------------


def test_token_cache_hit_returns_cached_value_without_minting(
    app_env: tuple[bytes, bytes]
) -> None:
    """Second call within TTL must NOT mint a new JWT or call GitHub."""
    with patch.object(
        tokens, "_exchange_jwt_for_installation_token",
        return_value="ghs_first_token",
    ) as exchange:
        token1 = tokens.get_installation_token(installation_id=42, now=100.0)
        token2 = tokens.get_installation_token(installation_id=42, now=200.0)
    assert token1 == token2 == "ghs_first_token"
    assert exchange.call_count == 1  # cache hit on second call


def test_token_cache_keyed_per_installation_no_bleed(
    app_env: tuple[bytes, bytes]
) -> None:
    """Two different installations must get independent tokens — the
    multi-tenant data-isolation guarantee starts here."""
    side_effect = ["ghs_inst_111", "ghs_inst_222"]
    with patch.object(
        tokens, "_exchange_jwt_for_installation_token",
        side_effect=side_effect,
    ):
        t1 = tokens.get_installation_token(installation_id=111, now=100.0)
        t2 = tokens.get_installation_token(installation_id=222, now=100.0)
    assert t1 == "ghs_inst_111"
    assert t2 == "ghs_inst_222"


def test_token_ttl_trimmed_to_30_min_under_githubs_default(
    app_env: tuple[bytes, bytes]
) -> None:
    """Cache TTL is 30 min — half of GitHub's 1h installation-token TTL.
    Past the 30 min mark the cache evicts and a new token is minted."""
    assert tokens.INSTALLATION_TOKEN_TTL_SECONDS == 30 * 60

    with patch.object(
        tokens, "_exchange_jwt_for_installation_token",
        side_effect=["ghs_first", "ghs_second"],
    ) as exchange:
        # Mint at t=0.
        tokens.get_installation_token(installation_id=42, now=0.0)
        # Within TTL — cache hit.
        tokens.get_installation_token(installation_id=42, now=29 * 60)
        assert exchange.call_count == 1
        # Past TTL — re-mint.
        t3 = tokens.get_installation_token(installation_id=42, now=31 * 60)
    assert t3 == "ghs_second"
    assert exchange.call_count == 2


def test_invalidate_token_purges_cache_and_forces_re_mint(
    app_env: tuple[bytes, bytes]
) -> None:
    """The contract every API caller honours on 401: invalidate, then the
    next get_installation_token() call MUST mint a fresh token."""
    with patch.object(
        tokens, "_exchange_jwt_for_installation_token",
        side_effect=["ghs_first", "ghs_after_revoke"],
    ) as exchange:
        first = tokens.get_installation_token(installation_id=42, now=0.0)
        tokens.invalidate_token(42)
        second = tokens.get_installation_token(installation_id=42, now=10.0)

    assert first == "ghs_first"
    assert second == "ghs_after_revoke"
    assert exchange.call_count == 2


def test_invalidate_token_for_unknown_installation_is_noop(
    app_env: tuple[bytes, bytes]
) -> None:
    """Calling invalidate_token(unknown) must not raise — common at the
    request boundary where any 401 triggers a defensive purge."""
    tokens.invalidate_token(installation_id=99_999)


# ---- Logger hygiene (THREAT_MODEL row "token leakage in logs") -------------


def test_logger_never_emits_full_token_or_jwt(
    app_env: tuple[bytes, bytes],
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake_token = "ghs_supersecret_full_token_value_12345"
    with patch.object(
        tokens, "_exchange_jwt_for_installation_token",
        return_value=fake_token,
    ):
        with caplog.at_level(logging.DEBUG, logger="ciguard.app.tokens"):
            tokens.get_installation_token(installation_id=42, now=0.0)
            # Trigger an explicit invalidate-log too.
            tokens.invalidate_token(42)

    text = "\n".join(r.message for r in caplog.records)
    assert fake_token not in text
    # Prefix-only redaction (`ghs_su…`) must be present.
    assert "ghs_su" in text
    # The full JWT signature is never logged either — the JWT is short-
    # lived and only present in the request to GitHub.
    assert ".eyJ" not in text  # base64url JWT body marker
