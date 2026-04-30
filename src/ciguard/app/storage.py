"""Per-installation storage for the ciguard GitHub App.

Threat model: `Project ciguard/THREAT_MODEL.md` Surface 9. Closes the
two **Highest** threats on the entire App surface:

  - "IDOR on installation_id" (DREAD 21) — every read/write requires
    a `verified_installation_id` keyword argument; positional / string /
    zero / negative values raise TypeError or ValueError. Caller-
    controlled values (e.g. `installation_id` from a request URL)
    must NEVER reach this module — only server-side-verified ints
    that came from a webhook signature or JWT-validated session.

  - "Multi-tenant baseline.json bleed" (DREAD 20) — every storage path
    starts with `<installation_id>/<repo_full_name>/...`. Path
    construction sanitises `repo_full_name` (alphanumeric + `_` `-` `.`
    only; explicit `..` reject); the resolved path is asserted to stay
    under the storage root. Reading installation A's baseline while
    holding installation B's id returns None — there's no fall-through
    to a `repo_full_name`-only key.

Design commitment from THREAT_MODEL.md "v0.10.0 design rationale":

    Any code path that reads from storage must hold a verified
    `installation_id`. A storage helper enforces this with a runtime
    assert; reads keyed only by `repo_full_name` are a `TypeError`.

This module IS that storage helper. Future per-`installation_id`
namespaces (e.g. delivery-ID idempotency, token cache) will live as
sibling subdirectories under the same prefix; the in-memory caches in
`scheduler.py` + `tokens.py` already enforce the same isolation.
"""
from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("ciguard.app.storage")

DEFAULT_STORAGE_ROOT_ENV = "CIGUARD_APP_STORAGE_ROOT"
DEFAULT_STORAGE_ROOT = "./var/ciguard-app"

# `owner/repo` format: GitHub allows owner ASCII alphanumerics + `-`;
# repo names allow alphanumerics + `_-.`. We're stricter than necessary
# (rejecting some valid edge-case repo names with leading dots) — the
# alternative is letting `..` slip through path-construction checks.
_OWNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")
_REPO_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$")


# ===========================================================================
# Verified-id type guards
# ===========================================================================


def _assert_verified_installation_id(value: Any) -> int:
    """Raise TypeError unless `value` is a strictly-positive int.

    `bool` is a subclass of `int` in Python — explicitly reject it so
    a `True` passed by mistake doesn't sail through as `1`.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(
            f"installation_id must be an int (got {type(value).__name__}); "
            "callers must NEVER pass strings or other types — only "
            "server-side-verified ints from a webhook signature or "
            "JWT-validated session."
        )
    if value <= 0:
        raise ValueError(
            f"installation_id must be a positive int (got {value})"
        )
    return value


def _validate_repo_full_name(repo_full_name: Any) -> tuple[str, str]:
    """Parse + validate `owner/repo`. Reject any path-traversal shape."""
    if not isinstance(repo_full_name, str):
        raise TypeError(
            f"repo_full_name must be str (got {type(repo_full_name).__name__})"
        )
    if "/" not in repo_full_name:
        raise ValueError(
            f"repo_full_name must be `owner/repo` (got {repo_full_name!r})"
        )
    owner, _, repo = repo_full_name.partition("/")
    if not _OWNER_RE.fullmatch(owner):
        raise ValueError(
            f"invalid owner segment in repo_full_name: {repo_full_name!r}"
        )
    if not _REPO_RE.fullmatch(repo):
        raise ValueError(
            f"invalid repo segment in repo_full_name: {repo_full_name!r}"
        )
    # Defensive sweep — should already be caught above, but the Highest-
    # severity threat earns belt-and-braces.
    if ".." in repo_full_name or repo_full_name.startswith("/"):
        raise ValueError(
            f"path traversal attempt in repo_full_name: {repo_full_name!r}"
        )
    return owner, repo


# ===========================================================================
# Storage root resolution
# ===========================================================================


def _storage_root() -> Path:
    raw = os.environ.get(DEFAULT_STORAGE_ROOT_ENV) or DEFAULT_STORAGE_ROOT
    return Path(raw).expanduser().resolve()


# ===========================================================================
# Path construction
# ===========================================================================


def _baseline_path(
    *, verified_installation_id: int, repo_full_name: str
) -> Path:
    """Construct the baseline path AND assert it stays under the
    storage root. The assertion catches any future refactor that
    forgets the alphanumeric repo-name check."""
    install_id = _assert_verified_installation_id(verified_installation_id)
    owner, repo = _validate_repo_full_name(repo_full_name)
    root = _storage_root()
    target = root / str(install_id) / owner / repo / "baseline.json"
    resolved = target.resolve()
    if not str(resolved).startswith(str(root) + os.sep) and resolved != root:
        # Belt-and-braces: the validators above already prevent this,
        # but the Highest-severity threat earns runtime confirmation.
        raise ValueError(
            f"computed baseline path escapes storage root: {resolved}"
        )
    return resolved


# ===========================================================================
# Public surface — every read + write requires `verified_installation_id`
# ===========================================================================


def read_baseline(
    *, verified_installation_id: int, repo_full_name: str
) -> Optional[dict[str, Any]]:
    """Return the baseline dict for this installation+repo, or None if
    not present. NEVER falls back to a repo-only key."""
    path = _baseline_path(
        verified_installation_id=verified_installation_id,
        repo_full_name=repo_full_name,
    )
    if not path.exists():
        return None
    try:
        with open(path, "rb") as f:
            return json.loads(f.read().decode("utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.exception(
            "failed to read baseline (installation=%d repo=%s)",
            verified_installation_id, repo_full_name,
        )
        return None


def write_baseline(
    *, verified_installation_id: int, repo_full_name: str,
    baseline: dict[str, Any],
) -> None:
    """Atomically write the baseline. Uses write-to-temp + rename to
    avoid half-written files on crash + concurrent-reader races."""
    path = _baseline_path(
        verified_installation_id=verified_installation_id,
        repo_full_name=repo_full_name,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(baseline, sort_keys=True, separators=(",", ":"))
    # Write to a temp file in the same directory + rename — atomic on
    # POSIX. Tempfile is created with mode 0600 by default (mkstemp),
    # so even between create and rename the bytes aren't world-readable.
    fd, tmp_path = tempfile.mkstemp(
        prefix=".baseline.", suffix=".json.tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tmp:
            tmp.write(payload)
        os.replace(tmp_path, path)
    except Exception:
        # On error, clean up the tmp file rather than leaving litter.
        # Cleanup is best-effort: if it fails (e.g. the disk-full error
        # that triggered the original Exception also blocks unlink),
        # log + continue so we surface the ORIGINAL failure unmodified.
        try:
            os.unlink(tmp_path)
        except OSError as cleanup_exc:
            logger.debug(
                "tmp-file cleanup failed during write_baseline error path: %s",
                cleanup_exc,
            )
        raise
    logger.info(
        "wrote baseline (installation=%d repo=%s bytes=%d)",
        verified_installation_id, repo_full_name, len(payload),
    )


def delete_baseline(
    *, verified_installation_id: int, repo_full_name: str
) -> bool:
    """Remove the baseline file. Returns True if a file was deleted,
    False if it didn't exist. Doesn't recursively clean parent dirs —
    leaving the empty `<install>/<owner>/<repo>/` shell is harmless."""
    path = _baseline_path(
        verified_installation_id=verified_installation_id,
        repo_full_name=repo_full_name,
    )
    try:
        path.unlink()
        logger.info(
            "deleted baseline (installation=%d repo=%s)",
            verified_installation_id, repo_full_name,
        )
        return True
    except FileNotFoundError:
        return False


def baseline_exists(
    *, verified_installation_id: int, repo_full_name: str
) -> bool:
    return _baseline_path(
        verified_installation_id=verified_installation_id,
        repo_full_name=repo_full_name,
    ).exists()
