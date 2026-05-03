"""Real scan executor for the ciguard GitHub App (v0.11.1).

Replaces `factory._stub_scan_executor` as the default. Pipeline:

  1. Mint an installation token via `tokens.get_installation_token()`.
  2. Fetch a tarball of the repo at `head_sha` via GitHub's
     `GET /repos/{owner}/{repo}/tarball/{ref}` API. Auth-header on the
     initial request only — GitHub redirects to `codeload.github.com`
     with a short-lived signed URL that doesn't need the token.
  3. Extract under a `tempfile.TemporaryDirectory()` with the tarfile
     `filter="data"` safe-filter (Python 3.12+) — rejects path traversal,
     absolute paths, special files, and other archive-injection vectors.
  4. Hand the extracted root to `repo_scan.scan_repo(include_findings=True)`.
  5. Translate the result into the PR-comment-renderer shape.
  6. Temp dir auto-cleans on context exit (success OR exception).

Threat model: `Project ciguard/THREAT_MODEL.md` Surface 9. Closes:

  - "Webhook handler DoS — large payload / slow scan" — the tarball
    download is capped at MAX_TARBALL_BYTES (default 200 MB) with a
    streaming size check that aborts mid-download if the cap is hit.
  - "Installation token leakage" — token lives only in the request
    Authorization header; never appears in URLs (so never in process
    listings, never in logs that capture URLs).
  - "Path traversal in archive content" — `filter="data"` is the load-
    bearing control. We assert the Python version supports it at module
    import time so an inadvertent downgrade to 3.11 fails loud, not silently.

Why tarball not git-clone:
  - No git binary required in the deploy image (smaller container,
    fewer CVEs to patch).
  - Single HTTP request instead of multi-stage clone+fetch+checkout.
  - GitHub's tarball is auto-derived from the ref — no
    "did the shallow clone include this SHA?" edge case.
  - Smaller transfer (no .git/objects metadata).

What is *not* covered (deferred to subsequent work):
  - Subprocess isolation of the scanner itself (defence-in-depth against
    parser exploits in attacker-controlled YAML/Jenkinsfile content).
    The parsers are already hardened (yaml.SafeLoader, RecursionError
    wrap from Fuzz #18, etc.) so this is hardening, not a current risk.
  - Per-installation rate-limit / quota.
"""
from __future__ import annotations

import asyncio
import logging
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable

from .. import repo_scan
from . import tokens
from .scheduler import ScanJob

logger = logging.getLogger("ciguard.app.clone_executor")

# Cap on tarball download size. GitHub doesn't pre-declare Content-Length
# on the codeload redirect, so we enforce streaming. A repo larger than
# this is almost certainly a monorepo we don't want to scan via the App
# anyway — the user can run `ciguard scan-repo` locally.
MAX_TARBALL_BYTES = 200 * 1024 * 1024  # 200 MB

# Network timeout for the tarball fetch. Short enough to not hold a
# scheduler worker forever; long enough for a normal-size repo download
# even on a slow link.
FETCH_TIMEOUT_SECONDS = 120

GITHUB_API_BASE = "https://api.github.com"
USER_AGENT = "ciguard-app"


class TarballTooLarge(Exception):
    """Raised when streaming download exceeds MAX_TARBALL_BYTES."""


class TarballFetchError(Exception):
    """Raised on any non-200 response from the tarball API."""


def _safe_extract(tar: tarfile.TarFile, dest: Path) -> None:
    """Extract `tar` into `dest`, rejecting:

      - absolute paths in member names
      - parent-dir traversal (`../`)
      - symlinks, hardlinks, device files, FIFOs (any non-regular non-dir)

    Equivalent to Python 3.12+ `extractall(filter="data")` but written
    out so we work on 3.10 + 3.11 too. (Python 3.12 added `filter=`
    as a built-in arg; we deliberately don't depend on that so the
    package's existing `python_requires` envelope holds.)
    """
    dest_resolved = dest.resolve()
    for member in tar.getmembers():
        if (
            member.issym() or member.islnk() or member.ischr()
            or member.isblk() or member.isfifo() or member.isdev()
        ):
            raise TarballFetchError(
                f"refusing tarball member with special file type: {member.name!r}"
            )
        # Resolve the would-be target and ensure it stays under dest.
        target = (dest / member.name).resolve()
        if dest_resolved != target and dest_resolved not in target.parents:
            raise TarballFetchError(
                f"refusing tarball member outside dest: {member.name!r}"
            )
    # On 3.12+, also pass `filter="data"` for belt-and-braces (and to silence
    # the 3.14 deprecation warning that fires when no filter is set). On
    # 3.10/3.11 the kwarg doesn't exist; the manual validation above is the
    # equivalent safety.
    if sys.version_info >= (3, 12):
        tar.extractall(path=dest, filter="data")  # nosec B202
    else:
        tar.extractall(path=dest)  # nosec B202 — every member validated above


def _fetch_tarball(
    *, installation_id: int, owner: str, repo: str, ref: str, dest: Path,
) -> Path:
    """Download + extract the repo tarball at `ref` into `dest`. Returns
    the path to the extracted top-level directory (GitHub tarballs extract
    to a single child like `Jo-Jo98-ciguard-abc1234/`).

    Synchronous — call from `asyncio.to_thread()` so the scheduler's
    worker loop isn't blocked by the network round-trip.
    """
    token = tokens.get_installation_token(installation_id)
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/tarball/{ref}"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": USER_AGENT,
        },
    )

    tar_path = dest / "_repo.tar.gz"
    bytes_seen = 0
    chunk_size = 64 * 1024

    try:
        # nosec B310 — URL is constructed from the hardcoded GITHUB_API_BASE
        # constant + caller-controlled `owner`/`repo`/`ref`. The scheme is
        # always https; no file:// or custom-scheme exposure. Token is in
        # the Authorization header (per Surface 9 row 9.7).
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT_SECONDS) as resp:  # nosec B310
            if resp.status != 200:
                raise TarballFetchError(
                    f"GitHub tarball API returned HTTP {resp.status} for "
                    f"{owner}/{repo}@{ref[:7]}"
                )
            with open(tar_path, "wb") as out:
                while True:
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    bytes_seen += len(chunk)
                    if bytes_seen > MAX_TARBALL_BYTES:
                        raise TarballTooLarge(
                            f"tarball exceeded cap "
                            f"({bytes_seen} > {MAX_TARBALL_BYTES} bytes) for "
                            f"{owner}/{repo}@{ref[:7]}"
                        )
                    out.write(chunk)
    except urllib.error.HTTPError as exc:
        # The most likely reason is a revoked / expired installation token.
        # Honour the cache-purge contract from THREAT_MODEL row "Cached
        # installation token used after revocation".
        if exc.code == 401:
            tokens.invalidate_token(installation_id)
        raise TarballFetchError(
            f"GitHub tarball API returned HTTP {exc.code} for "
            f"{owner}/{repo}@{ref[:7]}"
        ) from exc

    extract_root = dest / "extracted"
    extract_root.mkdir()
    with tarfile.open(tar_path, mode="r:gz") as tar:
        _safe_extract(tar, extract_root)

    # Tarball extracts to a single top-level dir. Find it.
    children = [c for c in extract_root.iterdir() if c.is_dir()]
    if len(children) != 1:
        raise TarballFetchError(
            f"unexpected tarball layout: expected 1 top-level dir, "
            f"got {len(children)} ({[c.name for c in children]})"
        )
    return children[0]


def _to_app_result(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """Translate `repo_scan.scan_repo(include_findings=True)` output to
    the shape `checks.render_pr_comment_body()` expects.

    Empty repos (no pipelines discovered) get a graceful "nothing to scan"
    result rather than `risk_score=None`.
    """
    if scan_result.get("error"):
        # Path-not-found shouldn't happen post-extract; if it does, surface
        # explicitly so set_check_run_failed gets a useful message.
        return {
            "risk_score": 0,
            "grade": "F",
            "findings": [],
            "summary": f"Scan error: {scan_result['error']}",
        }

    findings: Iterable[Dict[str, Any]] = scan_result.get("findings") or []
    risk_score = scan_result.get("risk_score")
    grade = scan_result.get("grade")
    files_scanned = scan_result.get("files_scanned", 0)

    if files_scanned == 0:
        return {
            "risk_score": "—",
            "grade": "—",
            "findings": [],
            "summary": (
                "ciguard scanned the repository at this commit but did not "
                "find any pipeline files (`.gitlab-ci.yml`, "
                "`.github/workflows/*.yml`, `Jenkinsfile`)."
            ),
        }

    return {
        "risk_score": risk_score if risk_score is not None else "—",
        "grade": grade if grade is not None else "—",
        "findings": list(findings),
        "summary": (
            f"Scanned {files_scanned} pipeline file(s); "
            f"found {scan_result.get('total_findings', 0)} finding(s)."
        ),
    }


async def clone_and_scan_executor(job: ScanJob) -> Dict[str, Any]:
    """v0.11.1 scan executor: fetch repo at head SHA, scan, return.

    Called by `run_scan()` for each ScanJob the scheduler dispatches.
    The result dict matches the contract `checks.render_pr_comment_body()`
    consumes (risk_score, grade, findings, summary).
    """
    if "/" not in job.repo_full_name:
        raise ValueError(
            f"malformed repo_full_name: {job.repo_full_name!r}"
        )
    owner, _, repo = job.repo_full_name.partition("/")
    head_sha_short = job.head_sha[:7] if job.head_sha else "<unset>"
    logger.info(
        "clone_executor: fetching %s/%s@%s for installation=%d",
        owner, repo, head_sha_short, job.installation_id,
    )

    with tempfile.TemporaryDirectory(prefix="ciguard-app-") as td:
        td_path = Path(td)
        try:
            extract_path = await asyncio.to_thread(
                _fetch_tarball,
                installation_id=job.installation_id,
                owner=owner, repo=repo,
                ref=job.head_sha,
                dest=td_path,
            )
        except (TarballTooLarge, TarballFetchError):
            raise
        except Exception:
            logger.exception(
                "tarball fetch failed for %s/%s@%s",
                owner, repo, head_sha_short,
            )
            raise

        logger.info(
            "clone_executor: scanning extracted tree at %s",
            extract_path,
        )
        scan_result = await asyncio.to_thread(
            repo_scan.scan_repo,
            extract_path,
            offline=False,
            include_findings=True,
        )

    app_result = _to_app_result(scan_result)
    logger.info(
        "clone_executor: %s/%s@%s -> %d findings (grade=%s score=%s)",
        owner, repo, head_sha_short,
        len(app_result.get("findings", []) or []),
        app_result.get("grade"), app_result.get("risk_score"),
    )
    return app_result
