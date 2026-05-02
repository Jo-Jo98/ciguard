"""
OrgProvider Protocol + GitHubOrgProvider (Slice 17).

The org audit talks to one platform at a time — GitHub.com today,
GitLab / Bitbucket / Azure DevOps later. The `OrgProvider` Protocol
is the seam: implementations expose `list_repos(org)` (paginated repo
enumeration with metadata) and `fetch_pipeline_files(repo)` (workflow
+ Jenkinsfile + .gitlab-ci.yml file contents).

GitHubOrgProvider is the only concrete implementation today. It uses:
- `GET /orgs/{org}/repos` (or `/users/{org}/repos` if the slug isn't
  an org) for repo enumeration, paginated.
- `GET /repos/{owner}/{repo}/contents/.github/workflows` to list
  workflow files.
- `GET /repos/{owner}/{repo}/contents/{path}` (or the `download_url`
  it returns) to fetch each file's content.
- `GET /repos/{owner}/{repo}/contents/.gitlab-ci.yml` and
  `/contents/Jenkinsfile` for those single-file pipelines.

Bandwidth model: org audits can hit hundreds of repos, so we only
fetch pipeline files (not the whole tree). The GitHub Contents API
returns base64-encoded content under 1 MB without a separate request,
which keeps the round-trip count to roughly `(repos × 2) + workflow_files`.

Same env-var convention as `topology.verify`: `CIGUARD_GITHUB_TOKEN`
+ optional `CIGUARD_GITHUB_API_URL` for GHE. Stricter than `inventory/`
because the org audit is read-only against many repos at once and
expects a token with `repo` (private) or `public_repo` scope.
"""
from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol

USER_AGENT = "ciguard-audit-org/0.1 (+https://github.com/Jo-Jo98/ciguard)"
DEFAULT_TIMEOUT_SECONDS = 12
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
DEFAULT_GITHUB_API = "https://api.github.com"

# Cap on number of pages fetched per repo enumeration. 100 per page ×
# 50 pages = 5,000 repos — past that we stop and surface the cap so the
# operator knows their org is too big for a single audit run.
MAX_PAGES = 50
PER_PAGE = 100

# Files we actively look for outside the workflow directory. GitHub
# Actions workflows live in `.github/workflows/`; GitLab + Jenkins
# typically have one file each at the repo root.
ROOT_PIPELINE_PATHS = (
    ".gitlab-ci.yml",
    ".gitlab-ci.yaml",
    "Jenkinsfile",
    "jenkinsfile",
    ".jenkinsfile",
)
WORKFLOW_DIR = ".github/workflows"


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass
class RepoInfo:
    """Per-repo metadata returned by `list_repos`. The orchestrator
    persists everything but the raw API payload — `extra` is a future
    seam for provider-specific fields."""
    full_name: str                    # `owner/name`
    default_branch: Optional[str] = None
    private: bool = False
    archived: bool = False
    fork: bool = False
    description: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PipelineFile:
    """One pipeline-file's content + repo-relative path. Decoded text
    (NOT base64). Caller is responsible for writing the file to disk
    before invoking `scan_repo()`."""
    path: str
    content: str


class OrgProviderError(Exception):
    """Raised on platform-API failures. Caught by the orchestrator and
    surfaced via `OrgAuditReport.errors[]` rather than crashing the
    whole audit run."""


class OrgProvider(Protocol):
    """The contract every provider implementation must satisfy."""
    name: str

    def list_repos(self, org: str) -> List[RepoInfo]: ...

    def fetch_pipeline_files(self, repo: str) -> List[PipelineFile]: ...


# ---------------------------------------------------------------------------
# HTTP helper (private — used only by GitHubOrgProvider)
# ---------------------------------------------------------------------------


def _http_get_json(
    url: str,
    *,
    token: str,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    accept: str = "application/vnd.github+json",
) -> Any:
    """GET `url` with bearer auth; return parsed JSON. Raises
    `OrgProviderError` on HTTP failure / non-JSON / oversize. 404 is
    returned as `None` so callers can treat 'no such file' as a
    soft miss without an exception (matters for `Jenkinsfile` /
    `.gitlab-ci.yml` probes — most repos won't have them)."""
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": accept,
        "X-GitHub-Api-Version": "2022-11-28",
        "Authorization": f"Bearer {token}",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            if resp.status != 200:
                raise OrgProviderError(f"HTTP {resp.status}")
            body = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise OrgProviderError(
                    f"response exceeded {MAX_RESPONSE_BYTES} bytes — refusing"
                )
            try:
                return json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise OrgProviderError(f"response is not valid JSON: {exc}")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        msg = f"HTTP {exc.code}"
        if exc.code in (401, 403):
            msg += " — check CIGUARD_GITHUB_TOKEN scope (repo or public_repo)"
        raise OrgProviderError(msg)
    except urllib.error.URLError as exc:
        raise OrgProviderError(f"network error: {exc.reason}")
    except (TimeoutError, OSError) as exc:
        raise OrgProviderError(f"connection failed: {exc}")


# ---------------------------------------------------------------------------
# GitHub provider
# ---------------------------------------------------------------------------


class GitHubOrgProvider:
    """Concrete OrgProvider for GitHub.com (or GitHub Enterprise via
    `api_base` / `CIGUARD_GITHUB_API_URL`).

    Test seam: `http_get` defaults to the stdlib helper but tests
    inject a fake `(url, *, token, timeout, accept) -> dict | None`
    so unit tests exercise the orchestration without the network.
    """
    name: str = "github"

    def __init__(
        self,
        token: str,
        *,
        api_base: str = DEFAULT_GITHUB_API,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        http_get: Optional[Any] = None,
    ) -> None:
        if not token:
            raise ValueError("GitHubOrgProvider requires a non-empty token")
        self.token = token
        self.api_base = api_base.rstrip("/")
        self.timeout = timeout
        self._http_get = http_get or _http_get_json

    # ------------- list_repos -------------

    def list_repos(self, org: str) -> List[RepoInfo]:
        """Enumerate every repo in `org`. Tries `/orgs/<org>/repos` first
        (most common), falls back to `/users/<org>/repos` when the slug
        is a user account rather than an organisation. Pagination via
        the `Link` header isn't exposed by the JSON-only stdlib path —
        we walk pages by `?page=N&per_page=100` until a short page or
        `MAX_PAGES`."""
        repos: List[RepoInfo] = []
        for kind in ("orgs", "users"):
            page_url_tmpl = (
                f"{self.api_base}/{kind}/{urllib.parse.quote(org)}/repos"
                f"?per_page={PER_PAGE}&type=all"
            )
            page = 1
            page_payload: Optional[List[Dict[str, Any]]] = None
            try:
                page_payload = self._fetch_page(f"{page_url_tmpl}&page=1")
            except OrgProviderError:
                # 401/403/etc. — propagate up; falling through to the
                # `users` lane would mask credential errors.
                raise
            # 404 (None) on `orgs` → try `users`. 404 on `users` → empty.
            if page_payload is None:
                continue
            while page_payload is not None and len(page_payload) > 0:
                for raw in page_payload:
                    repo = self._parse_repo_payload(raw)
                    if repo is not None:
                        repos.append(repo)
                if len(page_payload) < PER_PAGE:
                    break
                page += 1
                if page > MAX_PAGES:
                    break
                page_payload = self._fetch_page(f"{page_url_tmpl}&page={page}")
            return repos
        return repos

    def _fetch_page(self, url: str) -> Optional[List[Dict[str, Any]]]:
        payload = self._http_get(url, token=self.token, timeout=self.timeout)
        if payload is None:
            return None
        if not isinstance(payload, list):
            raise OrgProviderError(
                f"expected list response from {url}, got {type(payload).__name__}"
            )
        return payload

    @staticmethod
    def _parse_repo_payload(raw: Dict[str, Any]) -> Optional[RepoInfo]:
        if not isinstance(raw, dict):
            return None
        full_name = raw.get("full_name")
        if not isinstance(full_name, str) or "/" not in full_name:
            return None
        return RepoInfo(
            full_name=full_name,
            default_branch=raw.get("default_branch") if isinstance(raw.get("default_branch"), str) else None,
            private=bool(raw.get("private", False)),
            archived=bool(raw.get("archived", False)),
            fork=bool(raw.get("fork", False)),
            description=raw.get("description") if isinstance(raw.get("description"), str) else None,
        )

    # ------------- fetch_pipeline_files -------------

    def fetch_pipeline_files(self, repo: str) -> List[PipelineFile]:
        """Fetch every recognised pipeline file in `repo`. Walks the
        `.github/workflows/` directory + probes for the four
        single-file pipeline names. Returns an empty list when the
        repo has none — that's a normal outcome (lots of repos have no
        CI), not an error."""
        out: List[PipelineFile] = []

        # Workflow directory (returns a list of file entries).
        wf_payload = self._http_get(
            f"{self.api_base}/repos/{repo}/contents/{WORKFLOW_DIR}",
            token=self.token,
            timeout=self.timeout,
        )
        if isinstance(wf_payload, list):
            for entry in wf_payload:
                if not isinstance(entry, dict):
                    continue
                if entry.get("type") != "file":
                    continue
                name = entry.get("name") or ""
                if not (name.endswith(".yml") or name.endswith(".yaml")):
                    continue
                content = self._decode_file_content(entry)
                if content is None:
                    # Fallback: re-fetch by path when the listing didn't
                    # inline base64 (happens for files >1 MB).
                    content = self._fetch_one_file(repo, f"{WORKFLOW_DIR}/{name}")
                if content is not None:
                    out.append(PipelineFile(path=f"{WORKFLOW_DIR}/{name}", content=content))

        # Single-file pipelines at the root.
        for path in ROOT_PIPELINE_PATHS:
            content = self._fetch_one_file(repo, path)
            if content is not None:
                out.append(PipelineFile(path=path, content=content))
                # Don't fetch case-variant duplicates — first hit wins.
                if path.lower() in {"jenkinsfile", ".jenkinsfile"}:
                    break

        return out

    def _fetch_one_file(self, repo: str, path: str) -> Optional[str]:
        """Fetch one file by repo-relative path. Returns decoded text
        or None on 404. Re-raises OrgProviderError on auth / network
        errors so the orchestrator can capture them per-repo."""
        url = f"{self.api_base}/repos/{repo}/contents/{urllib.parse.quote(path)}"
        payload = self._http_get(url, token=self.token, timeout=self.timeout)
        if payload is None:
            return None
        if isinstance(payload, dict):
            return self._decode_file_content(payload)
        return None

    @staticmethod
    def _decode_file_content(payload: Dict[str, Any]) -> Optional[str]:
        """Extract decoded text from a Contents API file response.
        GitHub returns base64 by default; oversized files (>1 MB) come
        back without `content` and require a separate fetch via
        `download_url`. We do the simple thing here and return None on
        the oversize miss — the caller falls back to per-path fetch."""
        if payload.get("type") != "file":
            return None
        encoding = payload.get("encoding")
        raw_content = payload.get("content")
        if encoding == "base64" and isinstance(raw_content, str):
            try:
                return base64.b64decode(raw_content, validate=False).decode(
                    "utf-8", errors="replace"
                )
            except (ValueError, TypeError):
                return None
        return None


# ---------------------------------------------------------------------------
# CLI helper
# ---------------------------------------------------------------------------


def github_org_provider_from_env(
    env: Optional[Dict[str, str]] = None,
) -> Optional[GitHubOrgProvider]:
    """Build a `GitHubOrgProvider` from `CIGUARD_GITHUB_TOKEN`. Returns
    None when no token is set so the CLI can print a clear error
    rather than constructing an unusable provider. Mirrors
    `topology.verify.github_provider_from_env`."""
    e = dict(env) if env is not None else dict(os.environ)
    token = e.get("CIGUARD_GITHUB_TOKEN", "").strip()
    if not token:
        return None
    api = e.get("CIGUARD_GITHUB_API_URL", DEFAULT_GITHUB_API).strip() or DEFAULT_GITHUB_API
    return GitHubOrgProvider(token=token, api_base=api)


__all__ = [
    "DEFAULT_GITHUB_API",
    "GitHubOrgProvider",
    "OrgProvider",
    "OrgProviderError",
    "PipelineFile",
    "RepoInfo",
    "ROOT_PIPELINE_PATHS",
    "WORKFLOW_DIR",
    "github_org_provider_from_env",
]
