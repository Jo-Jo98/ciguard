"""Tests for the v0.10.0 GitHub App per-installation storage layer.

Closes the two **Highest** Surface 9 STRIDE rows from THREAT_MODEL.md:

  - IDOR on installation_id (DREAD 21) — every read/write requires a
    keyword-only `verified_installation_id` int; positional args,
    strings, bools, zero, negative — all reject. A read with the
    wrong installation_id MUST return None even if a baseline file
    exists for the same repo under a different installation.

  - Multi-tenant baseline.json bleed (DREAD 20) — storage paths are
    namespaced under `<installation_id>/<owner>/<repo>/`; path-
    traversal attempts in `repo_full_name` are rejected; the resolved
    path is asserted to stay under the storage root.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.app import storage  # noqa: E402


@pytest.fixture
def storage_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setenv(storage.DEFAULT_STORAGE_ROOT_ENV, str(tmp_path))
    return tmp_path.resolve()


SAMPLE_BASELINE = {
    "version": 1,
    "fingerprints": ["a" * 16, "b" * 16],
    "scanner_version": "0.10.0",
}


# ===========================================================================
# Round-trip
# ===========================================================================


def test_round_trip_write_then_read(storage_root: Path) -> None:
    storage.write_baseline(
        verified_installation_id=42,
        repo_full_name="owner/repo",
        baseline=SAMPLE_BASELINE,
    )
    got = storage.read_baseline(
        verified_installation_id=42,
        repo_full_name="owner/repo",
    )
    assert got == SAMPLE_BASELINE


def test_read_returns_none_when_no_baseline(storage_root: Path) -> None:
    got = storage.read_baseline(
        verified_installation_id=42, repo_full_name="owner/repo",
    )
    assert got is None


def test_baseline_exists_round_trip(storage_root: Path) -> None:
    assert storage.baseline_exists(
        verified_installation_id=42, repo_full_name="owner/repo",
    ) is False
    storage.write_baseline(
        verified_installation_id=42, repo_full_name="owner/repo",
        baseline=SAMPLE_BASELINE,
    )
    assert storage.baseline_exists(
        verified_installation_id=42, repo_full_name="owner/repo",
    ) is True


def test_delete_baseline_removes_file(storage_root: Path) -> None:
    storage.write_baseline(
        verified_installation_id=42, repo_full_name="owner/repo",
        baseline=SAMPLE_BASELINE,
    )
    deleted = storage.delete_baseline(
        verified_installation_id=42, repo_full_name="owner/repo",
    )
    assert deleted is True
    assert storage.read_baseline(
        verified_installation_id=42, repo_full_name="owner/repo",
    ) is None


def test_delete_nonexistent_returns_false(storage_root: Path) -> None:
    assert storage.delete_baseline(
        verified_installation_id=42, repo_full_name="owner/repo",
    ) is False


# ===========================================================================
# THREAT: IDOR — wrong installation_id MUST NOT see other tenant's data
# ===========================================================================


def test_idor_reading_with_wrong_installation_returns_none(
    storage_root: Path,
) -> None:
    """The headline test for the Highest threat. Tenant A writes; tenant
    B reads with the same repo name; B MUST get None — not A's data."""
    storage.write_baseline(
        verified_installation_id=111, repo_full_name="owner/repo",
        baseline=SAMPLE_BASELINE,
    )
    leaked = storage.read_baseline(
        verified_installation_id=222, repo_full_name="owner/repo",
    )
    assert leaked is None


def test_idor_two_installations_with_same_repo_isolated(
    storage_root: Path,
) -> None:
    """Same repo path, different baselines, two installations — neither
    sees the other's content."""
    a = {**SAMPLE_BASELINE, "fingerprints": ["aaaa"]}
    b = {**SAMPLE_BASELINE, "fingerprints": ["bbbb"]}
    storage.write_baseline(
        verified_installation_id=111, repo_full_name="owner/repo", baseline=a,
    )
    storage.write_baseline(
        verified_installation_id=222, repo_full_name="owner/repo", baseline=b,
    )
    got_a = storage.read_baseline(
        verified_installation_id=111, repo_full_name="owner/repo",
    )
    got_b = storage.read_baseline(
        verified_installation_id=222, repo_full_name="owner/repo",
    )
    assert got_a == a
    assert got_b == b
    # Disk layout: two distinct directories under the storage root.
    install_dirs = sorted(p.name for p in storage_root.iterdir() if p.is_dir())
    assert install_dirs == ["111", "222"]


def test_storage_paths_start_with_installation_id(
    storage_root: Path,
) -> None:
    """Defence-in-depth check: the on-disk layout reflects the namespace.
    If this assertion ever changes, that's a flag for a refactor that
    might have broken multi-tenant isolation."""
    storage.write_baseline(
        verified_installation_id=42, repo_full_name="owner/repo",
        baseline=SAMPLE_BASELINE,
    )
    expected = storage_root / "42" / "owner" / "repo" / "baseline.json"
    assert expected.exists()


# ===========================================================================
# THREAT: type discipline on installation_id
# ===========================================================================


def test_installation_id_must_be_int_not_string(storage_root: Path) -> None:
    """Caller might accidentally pass a string from a request URL —
    that MUST fail loudly, not silently namespace under a stringified
    int that breaks comparisons."""
    with pytest.raises(TypeError, match="installation_id must be an int"):
        storage.read_baseline(
            verified_installation_id="42",  # type: ignore[arg-type]
            repo_full_name="owner/repo",
        )


def test_installation_id_must_not_be_bool(storage_root: Path) -> None:
    """`bool` is an `int` subclass in Python — `True` would otherwise
    sail through as `1` and create a shared-tenant directory."""
    with pytest.raises(TypeError, match="installation_id must be an int"):
        storage.read_baseline(
            verified_installation_id=True,  # type: ignore[arg-type]
            repo_full_name="owner/repo",
        )


def test_installation_id_must_be_positive(storage_root: Path) -> None:
    for bad in (0, -1, -42):
        with pytest.raises(ValueError, match="positive"):
            storage.read_baseline(
                verified_installation_id=bad,
                repo_full_name="owner/repo",
            )


def test_installation_id_must_be_keyword_only(storage_root: Path) -> None:
    """Positional invocation is not allowed — guards against argument-
    order swaps that would mix up installation_id and repo_full_name.

    Indirect invocation through `*args` so CodeQL doesn't see a literal
    positional-call signature mismatch (`py/call/wrong-arguments`) —
    we WANT the runtime TypeError, that's the test's whole point."""
    fn = storage.read_baseline
    bad_args: tuple = (42, "owner/repo")
    with pytest.raises(TypeError):
        fn(*bad_args)


# ===========================================================================
# THREAT: path traversal in repo_full_name
# ===========================================================================


@pytest.mark.parametrize("evil", [
    "owner/../etc/passwd",
    "../../etc/passwd",
    "owner/..",
    "../sibling-install/owner/repo",
    "/absolute/path",
    "owner//double-slash",
    "owner/repo/../../escape",
])
def test_path_traversal_in_repo_name_is_rejected(
    storage_root: Path, evil: str,
) -> None:
    with pytest.raises(ValueError):
        storage.read_baseline(
            verified_installation_id=42, repo_full_name=evil,
        )


@pytest.mark.parametrize("bad", [
    "no-slash",
    "owner/",
    "/repo",
    "owner/repo/extra",
    "owner with space/repo",
    "owner/repo with space",
    "/etc/passwd",
])
def test_invalid_repo_name_shapes_rejected(
    storage_root: Path, bad: str,
) -> None:
    with pytest.raises(ValueError):
        storage.write_baseline(
            verified_installation_id=42,
            repo_full_name=bad, baseline=SAMPLE_BASELINE,
        )


def test_repo_full_name_must_be_string(storage_root: Path) -> None:
    with pytest.raises(TypeError):
        storage.read_baseline(
            verified_installation_id=42,
            repo_full_name=42,  # type: ignore[arg-type]
        )


def test_attacker_repo_name_with_traversal_does_not_escape_root(
    storage_root: Path, tmp_path: Path,
) -> None:
    """Belt-and-braces: even if a future refactor weakens the alphanumeric
    check, the resolved-path-under-root assertion catches the escape.
    Demonstrate by trying to overwrite a sentinel file outside the root."""
    sentinel = tmp_path.parent / "should-never-be-touched"
    sentinel.write_text("untouched")
    with pytest.raises(ValueError):
        storage.write_baseline(
            verified_installation_id=42,
            repo_full_name="../../should-never-be-touched/x",
            baseline=SAMPLE_BASELINE,
        )
    assert sentinel.read_text() == "untouched"


# ===========================================================================
# Atomic write semantics
# ===========================================================================


def test_atomic_write_no_partial_file_on_crash(
    storage_root: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Force os.replace to raise — the temp file must be cleaned up so
    a future read doesn't see corruption + the parent dir doesn't have
    leftover .tmp files."""
    target_dir = storage_root / "42" / "owner" / "repo"
    target_dir.mkdir(parents=True, exist_ok=True)

    def boom(src: str, dst: str) -> None:
        raise OSError("simulated disk full")

    monkeypatch.setattr(storage.os, "replace", boom)
    with pytest.raises(OSError, match="simulated disk full"):
        storage.write_baseline(
            verified_installation_id=42, repo_full_name="owner/repo",
            baseline=SAMPLE_BASELINE,
        )

    # No leftover .tmp files in the target dir.
    leftover = list(target_dir.glob(".baseline.*.json.tmp"))
    assert leftover == []
    # Target file was never created.
    assert not (target_dir / "baseline.json").exists()


def test_atomic_write_overwrites_existing_baseline(
    storage_root: Path,
) -> None:
    storage.write_baseline(
        verified_installation_id=42, repo_full_name="owner/repo",
        baseline={"version": 1, "fingerprints": ["old"]},
    )
    storage.write_baseline(
        verified_installation_id=42, repo_full_name="owner/repo",
        baseline={"version": 1, "fingerprints": ["new"]},
    )
    got = storage.read_baseline(
        verified_installation_id=42, repo_full_name="owner/repo",
    )
    assert got == {"version": 1, "fingerprints": ["new"]}


# ===========================================================================
# Robustness
# ===========================================================================


def test_corrupt_baseline_file_returns_none_not_raises(
    storage_root: Path,
) -> None:
    """A truncated / hand-edited baseline must not crash the worker —
    return None so the next scan starts a fresh baseline."""
    target = storage_root / "42" / "owner" / "repo" / "baseline.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("{ this is not json")
    got = storage.read_baseline(
        verified_installation_id=42, repo_full_name="owner/repo",
    )
    assert got is None


def test_storage_root_env_var_honoured(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """`CIGUARD_APP_STORAGE_ROOT` must be the source of truth for the
    namespace prefix — no module-level cache that ignores rotation."""
    custom = tmp_path / "custom-root"
    monkeypatch.setenv(storage.DEFAULT_STORAGE_ROOT_ENV, str(custom))
    storage.write_baseline(
        verified_installation_id=42, repo_full_name="owner/repo",
        baseline=SAMPLE_BASELINE,
    )
    assert (custom.resolve() / "42" / "owner" / "repo" / "baseline.json").exists()
