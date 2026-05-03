"""Tests for `ciguard.app.clone_executor`.

Strategy: build a real .tar.gz from a tmp_path repo fixture in each test,
then mock `urllib.request.urlopen` to return its bytes. That exercises:

  - The streaming download loop (chunk size, byte cap)
  - The tarfile filter='data' extraction
  - The single-top-level-dir layout assertion
  - The hand-off to `repo_scan.scan_repo(include_findings=True)`
  - The result-dict translation

Tokens are mocked so the tests never call out to GitHub.
"""
from __future__ import annotations

import asyncio
import io
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest

from ciguard.app import clone_executor
from ciguard.app.scheduler import ScanJob


# ---- Fixtures ---------------------------------------------------------------


_GITLAB_BAD = """\
stages: [build]

build:
  stage: build
  image: ubuntu:latest
  script:
    - curl http://example.com/install.sh | sh
"""


def _make_repo_dir(root: Path) -> Path:
    """Create a minimal scannable repo under `root` and return the path."""
    src = root / "src-repo"
    src.mkdir()
    (src / ".gitlab-ci.yml").write_text(_GITLAB_BAD)
    (src / "README.md").write_text("# test repo\n")
    return src


def _make_tarball(repo_dir: Path, top_level_name: str = "Jo-Jo98-ciguard-abc1234") -> bytes:
    """Pack `repo_dir` into a .tar.gz that mirrors GitHub's tarball layout
    (single top-level dir like `<owner>-<repo>-<sha7>/`)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(str(repo_dir), arcname=top_level_name)
    return buf.getvalue()


class _FakeResponse:
    """Just enough urllib.HTTPResponse surface for `_fetch_tarball`."""

    def __init__(self, body: bytes, status: int = 200):
        self._buf = io.BytesIO(body)
        self.status = status

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _make_scan_job(repo_full_name: str = "Jo-Jo98/ciguard-target") -> ScanJob:
    return ScanJob(
        installation_id=129208018,
        repo_full_name=repo_full_name,
        head_sha="abc1234abc1234abc1234abc1234abc1234abc1",
        pr_number=42,
    )


# ---- _fetch_tarball ---------------------------------------------------------


def test_fetch_tarball_extracts_to_single_top_level_dir(tmp_path: Path):
    repo = _make_repo_dir(tmp_path)
    tarball_bytes = _make_tarball(repo, top_level_name="Jo-Jo98-target-abc1234")
    dest = tmp_path / "dl"
    dest.mkdir()

    with patch.object(clone_executor.tokens, "get_installation_token", return_value="ghs_fake"):
        with patch.object(clone_executor.urllib.request, "urlopen", return_value=_FakeResponse(tarball_bytes)):
            extract_path = clone_executor._fetch_tarball(
                installation_id=42, owner="Jo-Jo98", repo="target",
                ref="abc1234abc1234abc1234abc1234abc1234abc1", dest=dest,
            )

    assert extract_path.is_dir()
    assert extract_path.name == "Jo-Jo98-target-abc1234"
    assert (extract_path / ".gitlab-ci.yml").exists()
    assert (extract_path / ".gitlab-ci.yml").read_text() == _GITLAB_BAD


def test_fetch_tarball_token_used_in_authorization_header_not_url(tmp_path: Path):
    repo = _make_repo_dir(tmp_path)
    tarball_bytes = _make_tarball(repo)
    dest = tmp_path / "dl"; dest.mkdir()
    captured = {}

    def fake_urlopen(req, timeout):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.header_items())
        return _FakeResponse(tarball_bytes)

    with patch.object(clone_executor.tokens, "get_installation_token", return_value="ghs_secret_token_value"):
        with patch.object(clone_executor.urllib.request, "urlopen", side_effect=fake_urlopen):
            clone_executor._fetch_tarball(
                installation_id=42, owner="Jo-Jo98", repo="target",
                ref="abc1234", dest=dest,
            )

    assert "ghs_secret_token_value" not in captured["url"]
    assert captured["url"].endswith("/repos/Jo-Jo98/target/tarball/abc1234")
    auth = captured["headers"].get("Authorization", "")
    assert auth == "token ghs_secret_token_value"


def test_fetch_tarball_aborts_when_size_cap_exceeded(tmp_path: Path):
    # Construct a tarball whose gzip-compressed size exceeds a tiny patched cap.
    # We patch MAX_TARBALL_BYTES rather than building a 200MB+ tarball.
    repo = _make_repo_dir(tmp_path)
    tarball_bytes = _make_tarball(repo)
    dest = tmp_path / "dl"; dest.mkdir()

    with patch.object(clone_executor, "MAX_TARBALL_BYTES", 100):  # 100 bytes cap
        with patch.object(clone_executor.tokens, "get_installation_token", return_value="ghs_fake"):
            with patch.object(clone_executor.urllib.request, "urlopen", return_value=_FakeResponse(tarball_bytes)):
                with pytest.raises(clone_executor.TarballTooLarge):
                    clone_executor._fetch_tarball(
                        installation_id=42, owner="o", repo="r", ref="abc",
                        dest=dest,
                    )


def test_fetch_tarball_401_invalidates_token_cache(tmp_path: Path):
    """Closes the THREAT_MODEL "Cached installation token used after revocation"
    contract — when the API returns 401, the executor MUST purge the cached
    token before re-raising so the next mint re-exchanges JWT."""
    import urllib.error
    dest = tmp_path / "dl"; dest.mkdir()
    err = urllib.error.HTTPError(
        url="http://x", code=401, msg="Unauthorized", hdrs=None, fp=io.BytesIO(b""),
    )

    invalidated = []
    with patch.object(clone_executor.tokens, "get_installation_token", return_value="ghs_revoked"):
        with patch.object(clone_executor.tokens, "invalidate_token", side_effect=lambda iid: invalidated.append(iid)):
            with patch.object(clone_executor.urllib.request, "urlopen", side_effect=err):
                with pytest.raises(clone_executor.TarballFetchError):
                    clone_executor._fetch_tarball(
                        installation_id=129208018, owner="o", repo="r", ref="abc",
                        dest=dest,
                    )

    assert invalidated == [129208018]


def test_fetch_tarball_unexpected_layout_raises(tmp_path: Path):
    """If GitHub's tarball ever stops conforming to the single-top-level-dir
    convention, fail loud rather than silently scanning the wrong path."""
    # Build a tarball with TWO top-level dirs.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        a = tmp_path / "a"; a.mkdir(); (a / "f").write_text("a")
        b = tmp_path / "b"; b.mkdir(); (b / "f").write_text("b")
        tar.add(str(a), arcname="dir-a")
        tar.add(str(b), arcname="dir-b")
    weird_bytes = buf.getvalue()

    dest = tmp_path / "dl"; dest.mkdir()
    with patch.object(clone_executor.tokens, "get_installation_token", return_value="ghs_fake"):
        with patch.object(clone_executor.urllib.request, "urlopen", return_value=_FakeResponse(weird_bytes)):
            with pytest.raises(clone_executor.TarballFetchError, match="unexpected tarball layout"):
                clone_executor._fetch_tarball(
                    installation_id=42, owner="o", repo="r", ref="abc",
                    dest=dest,
                )


# ---- _to_app_result ---------------------------------------------------------


def test_to_app_result_normal_case():
    scan = {
        "files_scanned": 2,
        "total_findings": 3,
        "risk_score": 65.0,
        "grade": "C",
        "findings": [
            {"rule_id": "X-001", "severity": "High", "location": "build", "evidence": "..."},
            {"rule_id": "Y-002", "severity": "Low", "location": "test", "evidence": "..."},
            {"rule_id": "Z-003", "severity": "Info", "location": "global", "evidence": "..."},
        ],
    }
    out = clone_executor._to_app_result(scan)
    assert out["risk_score"] == 65.0
    assert out["grade"] == "C"
    assert len(out["findings"]) == 3
    assert "Scanned 2 pipeline file(s)" in out["summary"]


def test_to_app_result_empty_repo_yields_no_pipelines_marker():
    scan = {"files_scanned": 0, "total_findings": 0, "findings": [], "risk_score": None, "grade": None}
    out = clone_executor._to_app_result(scan)
    assert out["risk_score"] == "—"
    assert out["grade"] == "—"
    assert out["findings"] == []
    assert "did not find any pipeline files" in out["summary"]


def test_to_app_result_error_case():
    scan = {"error": "Path not found: /nonexistent"}
    out = clone_executor._to_app_result(scan)
    assert out["grade"] == "F"
    assert out["findings"] == []
    assert "Path not found" in out["summary"]


# ---- clone_and_scan_executor (full path with mocks) -------------------------


def test_clone_and_scan_executor_end_to_end(tmp_path: Path):
    repo = _make_repo_dir(tmp_path)
    tarball_bytes = _make_tarball(repo)
    job = _make_scan_job()

    with patch.object(clone_executor.tokens, "get_installation_token", return_value="ghs_fake"):
        with patch.object(clone_executor.urllib.request, "urlopen", return_value=_FakeResponse(tarball_bytes)):
            result = asyncio.run(clone_executor.clone_and_scan_executor(job))

    assert "findings" in result
    assert "risk_score" in result
    assert "grade" in result
    assert "summary" in result
    # Our fixture has known High-severity findings (mutable image tag +
    # curl-pipe-sh), so we expect at least one.
    assert len(result["findings"]) >= 1
    severities = {f.get("severity") for f in result["findings"]}
    # The fixture should produce something at High or above
    assert any(s in {"High", "Critical"} for s in severities)


def test_clone_and_scan_executor_cleans_temp_dir_on_success(tmp_path: Path):
    """tempfile.TemporaryDirectory context manager handles this for us, but
    we verify the contract by asserting no leaked dirs in tempfile.gettempdir."""
    import tempfile as _tempfile
    repo = _make_repo_dir(tmp_path)
    tarball_bytes = _make_tarball(repo)
    job = _make_scan_job()

    pre = {p.name for p in Path(_tempfile.gettempdir()).glob("ciguard-app-*")}

    with patch.object(clone_executor.tokens, "get_installation_token", return_value="ghs_fake"):
        with patch.object(clone_executor.urllib.request, "urlopen", return_value=_FakeResponse(tarball_bytes)):
            asyncio.run(clone_executor.clone_and_scan_executor(job))

    post = {p.name for p in Path(_tempfile.gettempdir()).glob("ciguard-app-*")}
    assert post - pre == set(), f"leaked temp dirs: {post - pre}"


def test_clone_and_scan_executor_cleans_temp_dir_on_fetch_failure(tmp_path: Path):
    import tempfile as _tempfile
    job = _make_scan_job()
    pre = {p.name for p in Path(_tempfile.gettempdir()).glob("ciguard-app-*")}

    with patch.object(clone_executor.tokens, "get_installation_token", return_value="ghs_fake"):
        with patch.object(clone_executor.urllib.request, "urlopen", side_effect=ConnectionError("network down")):
            with pytest.raises(Exception):
                asyncio.run(clone_executor.clone_and_scan_executor(job))

    post = {p.name for p in Path(_tempfile.gettempdir()).glob("ciguard-app-*")}
    assert post - pre == set()


def test_clone_and_scan_executor_rejects_malformed_repo_full_name():
    job = ScanJob(
        installation_id=42, repo_full_name="malformed-no-slash",
        head_sha="abc1234abc1234abc1234abc1234abc1234abc1",
        pr_number=None,
    )
    with pytest.raises(ValueError, match="malformed repo_full_name"):
        asyncio.run(clone_executor.clone_and_scan_executor(job))
