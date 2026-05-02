"""
Tests for the org-level audit (Slice 17, session 1).

Three layers of coverage:

  1. `GitHubOrgProvider` — tested with a stub `http_get` injected via
     the constructor. No network. Asserts pagination, the user-vs-org
     fallback, repo metadata mapping, base64 content decoding, the
     workflow + root-pipeline file collection.

  2. `audit_org` orchestrator — tested with a stub Provider that
     returns canned `RepoInfo` + `PipelineFile` lists. Exercises
     include / exclude / limit filtering, archived + fork skipping,
     per-repo error capture, repos with no pipeline files, the
     aggregate accessors.

  3. `org_audit_html.render` — tested for shape + summary counts +
     escaping + empty-state rendering.
"""
from __future__ import annotations

import base64 as _b64
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.audit_org import audit_org
from ciguard.audit_org.provider import (
    GitHubOrgProvider,
    OrgProviderError,
    PipelineFile,
    RepoInfo,
    github_org_provider_from_env,
)
from ciguard.models.org_audit import OrgAuditReport, RepoScanRecord
from ciguard.reporter import org_audit_html


# ---------------------------------------------------------------------------
# StubProvider — used by orchestrator + reporter tests
# ---------------------------------------------------------------------------


class StubProvider:
    name: str = "stub"

    def __init__(self, repos, files_by_repo=None, list_error=None, fetch_errors=None):
        self.repos = repos
        self.files_by_repo = files_by_repo or {}
        self.list_error = list_error
        self.fetch_errors = fetch_errors or {}
        self.fetch_calls: list[str] = []

    def list_repos(self, org):
        if self.list_error:
            raise self.list_error
        return list(self.repos)

    def fetch_pipeline_files(self, repo):
        self.fetch_calls.append(repo)
        if repo in self.fetch_errors:
            raise self.fetch_errors[repo]
        return list(self.files_by_repo.get(repo, []))


_HELLO_GHA = """name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo hello
"""


# ---------------------------------------------------------------------------
# Orchestrator tests
# ---------------------------------------------------------------------------


class TestAuditOrg:
    def _files(self, *paths):
        return [PipelineFile(path=p, content=_HELLO_GHA) for p in paths]

    def test_scans_repos_with_pipeline_files(self):
        provider = StubProvider(
            repos=[
                RepoInfo(full_name="ex/api", default_branch="main"),
                RepoInfo(full_name="ex/web", default_branch="main"),
            ],
            files_by_repo={
                "ex/api": self._files(".github/workflows/ci.yml"),
                "ex/web": self._files(".github/workflows/ci.yml"),
            },
        )
        report = audit_org("ex", provider, offline=True)
        assert isinstance(report, OrgAuditReport)
        assert report.org == "ex"
        assert report.provider == "stub"
        assert report.repos_scanned == 2
        # Both repos scanned; finding counts depend on rule firings,
        # but the structure must be present.
        for r in report.repos:
            assert r.scan is not None
            assert "files_scanned" in r.scan
            assert "by_severity" in r.scan

    def test_skips_archived_by_default(self):
        provider = StubProvider(
            repos=[
                RepoInfo(full_name="ex/api"),
                RepoInfo(full_name="ex/old", archived=True),
            ],
            files_by_repo={"ex/api": self._files(".github/workflows/ci.yml")},
        )
        report = audit_org("ex", provider, offline=True)
        names = [r.repo for r in report.repos]
        assert "ex/api" in names
        assert "ex/old" not in names
        assert report.skipped_archived == 1

    def test_skips_forks_by_default(self):
        provider = StubProvider(
            repos=[
                RepoInfo(full_name="ex/api"),
                RepoInfo(full_name="ex/upstream-fork", fork=True),
            ],
            files_by_repo={"ex/api": self._files(".github/workflows/ci.yml")},
        )
        report = audit_org("ex", provider, offline=True)
        names = [r.repo for r in report.repos]
        assert "ex/upstream-fork" not in names
        assert report.skipped_forks == 1

    def test_include_archived_keeps_them(self):
        provider = StubProvider(
            repos=[
                RepoInfo(full_name="ex/api"),
                RepoInfo(full_name="ex/old", archived=True),
            ],
            files_by_repo={
                "ex/api": self._files(".github/workflows/ci.yml"),
                "ex/old": self._files(".github/workflows/ci.yml"),
            },
        )
        report = audit_org("ex", provider, offline=True, include_archived=True)
        names = [r.repo for r in report.repos]
        assert "ex/old" in names
        assert report.skipped_archived == 0

    def test_include_filter_regex(self):
        provider = StubProvider(
            repos=[
                RepoInfo(full_name="ex/api"),
                RepoInfo(full_name="ex/web"),
                RepoInfo(full_name="ex/worker"),
            ],
            files_by_repo={
                name: self._files(".github/workflows/ci.yml")
                for name in ("ex/api", "ex/web", "ex/worker")
            },
        )
        report = audit_org("ex", provider, offline=True, include=r"^ex/(api|web)$")
        names = sorted(r.repo for r in report.repos)
        assert names == ["ex/api", "ex/web"]

    def test_exclude_filter_regex(self):
        provider = StubProvider(
            repos=[
                RepoInfo(full_name="ex/api"),
                RepoInfo(full_name="ex/web"),
                RepoInfo(full_name="ex/worker"),
            ],
            files_by_repo={
                name: self._files(".github/workflows/ci.yml")
                for name in ("ex/api", "ex/web", "ex/worker")
            },
        )
        report = audit_org("ex", provider, offline=True, exclude=r"worker$")
        names = sorted(r.repo for r in report.repos)
        assert names == ["ex/api", "ex/web"]

    def test_limit_caps_repo_count(self):
        provider = StubProvider(
            repos=[
                RepoInfo(full_name=f"ex/r{i}")
                for i in range(10)
            ],
            files_by_repo={
                f"ex/r{i}": self._files(".github/workflows/ci.yml")
                for i in range(10)
            },
        )
        report = audit_org("ex", provider, offline=True, limit=3)
        assert len(report.repos) == 3

    def test_repo_with_no_pipeline_files_recorded_unscanned(self):
        provider = StubProvider(
            repos=[RepoInfo(full_name="ex/empty")],
            files_by_repo={"ex/empty": []},
        )
        report = audit_org("ex", provider, offline=True)
        assert len(report.repos) == 1
        rec = report.repos[0]
        assert rec.scan is None
        assert rec.error is None
        assert rec.pipeline_file_count == 0

    def test_per_repo_fetch_error_captured(self):
        provider = StubProvider(
            repos=[
                RepoInfo(full_name="ex/api"),
                RepoInfo(full_name="ex/locked"),
            ],
            files_by_repo={"ex/api": self._files(".github/workflows/ci.yml")},
            fetch_errors={"ex/locked": OrgProviderError("HTTP 403 — forbidden")},
        )
        report = audit_org("ex", provider, offline=True)
        locked = next(r for r in report.repos if r.repo == "ex/locked")
        assert locked.error is not None
        assert "403" in locked.error
        assert any(e.get("repo") == "ex/locked" for e in report.errors)

    def test_list_repos_error_short_circuits_with_error_record(self):
        provider = StubProvider(
            repos=[],
            list_error=OrgProviderError("HTTP 401 — bad token"),
        )
        report = audit_org("ex", provider, offline=True)
        assert report.repos == []
        assert any(e.get("phase") == "list_repos" for e in report.errors)

    def test_aggregate_by_severity_sums_across_repos(self):
        # Build two records by hand to test the aggregate property
        # without depending on rule firings.
        report = OrgAuditReport(
            org="x",
            repos=[
                RepoScanRecord(
                    repo="ex/a",
                    scan={
                        "files_scanned": 1,
                        "total_findings": 3,
                        "by_severity": {"Critical": 1, "High": 2,
                                        "Medium": 0, "Low": 0, "Info": 0},
                        "files": [{"path": "ci.yml", "platform": "github-actions",
                                    "grade": "C", "findings_total": 3,
                                    "findings_by_severity": {}}],
                    },
                ),
                RepoScanRecord(
                    repo="ex/b",
                    scan={
                        "files_scanned": 1,
                        "total_findings": 1,
                        "by_severity": {"Critical": 0, "High": 1,
                                        "Medium": 0, "Low": 0, "Info": 0},
                        "files": [{"path": "ci.yml", "platform": "github-actions",
                                    "grade": "B", "findings_total": 1,
                                    "findings_by_severity": {}}],
                    },
                ),
            ],
        )
        sev = report.by_severity
        assert sev["Critical"] == 1
        assert sev["High"] == 3
        assert report.total_findings == 4
        assert report.repos_with_findings == 2

    def test_grade_distribution_buckets_no_scan_under_question(self):
        report = OrgAuditReport(
            org="x",
            repos=[
                RepoScanRecord(repo="ex/a", scan={
                    "files_scanned": 1,
                    "by_severity": {"Critical": 0, "High": 0, "Medium": 0,
                                    "Low": 0, "Info": 0},
                    "files": [{"path": "x", "platform": "gha", "grade": "A",
                                "findings_total": 0, "findings_by_severity": {}}],
                }),
                RepoScanRecord(repo="ex/empty"),  # no scan
            ],
        )
        dist = report.grade_distribution
        assert dist["A"] == 1
        assert dist["?"] == 1


# ---------------------------------------------------------------------------
# GitHubOrgProvider tests
# ---------------------------------------------------------------------------


class _StubHttp:
    """Records URL calls + serves canned responses keyed by URL substring.
    Longest-key-wins so `/contents/.github/workflows` doesn't get served
    the `/contents` parent payload."""
    def __init__(self, responses=None, errors=None):
        self.responses = responses or {}
        self.errors = errors or {}
        self.calls: list[str] = []

    def __call__(self, url, *, token, timeout, accept="application/vnd.github+json"):
        self.calls.append(url)
        for key in sorted(self.errors.keys(), key=len, reverse=True):
            if key in url:
                raise self.errors[key]
        for key in sorted(self.responses.keys(), key=len, reverse=True):
            if key in url:
                return self.responses[key]
        raise OrgProviderError(f"unexpected URL in test stub: {url}")


def _b64_content(text: str) -> dict:
    """Build a Contents-API file response with `content` set."""
    return {
        "type": "file",
        "encoding": "base64",
        "content": _b64.b64encode(text.encode("utf-8")).decode("ascii"),
    }


class TestGitHubOrgProvider:
    def _provider(self, http):
        return GitHubOrgProvider(token="ghp_test", http_get=http)

    def test_constructor_rejects_empty_token(self):
        with pytest.raises(ValueError):
            GitHubOrgProvider(token="")

    def test_list_repos_single_page(self):
        http = _StubHttp(responses={
            "/orgs/example/repos": [
                {"full_name": "example/api", "default_branch": "main",
                 "private": False, "archived": False, "fork": False},
                {"full_name": "example/web", "default_branch": "trunk",
                 "private": True},
            ],
        })
        repos = self._provider(http).list_repos("example")
        names = sorted(r.full_name for r in repos)
        assert names == ["example/api", "example/web"]
        web = next(r for r in repos if r.full_name == "example/web")
        assert web.default_branch == "trunk"
        assert web.private is True

    def test_list_repos_falls_back_to_users_endpoint_on_404(self):
        # Orgs endpoint returns None (404 → None per provider contract).
        http = _StubHttp(responses={
            "/orgs/jdoe/repos": None,
            "/users/jdoe/repos": [
                {"full_name": "jdoe/dotfiles", "default_branch": "main"},
            ],
        })
        repos = self._provider(http).list_repos("jdoe")
        assert [r.full_name for r in repos] == ["jdoe/dotfiles"]

    def test_list_repos_paginates(self):
        # Two pages: first has PER_PAGE entries (full), second has 1.
        from ciguard.audit_org.provider import PER_PAGE

        page1 = [
            {"full_name": f"example/r{i}"} for i in range(PER_PAGE)
        ]
        page2 = [{"full_name": "example/last"}]
        http = _StubHttp(responses={
            "/orgs/example/repos?per_page=100&type=all&page=1": page1,
            "/orgs/example/repos?per_page=100&type=all&page=2": page2,
        })
        repos = self._provider(http).list_repos("example")
        assert len(repos) == PER_PAGE + 1
        assert repos[-1].full_name == "example/last"

    def test_list_repos_propagates_auth_error(self):
        http = _StubHttp(errors={
            "/orgs/example/repos": OrgProviderError("HTTP 401 — bad token"),
        })
        with pytest.raises(OrgProviderError):
            self._provider(http).list_repos("example")

    def test_fetch_pipeline_files_walks_workflows_dir(self):
        http = _StubHttp(responses={
            "/repos/example/api/contents/.github/workflows": [
                {"type": "file", "name": "ci.yml"},
                {"type": "file", "name": "release.yaml"},
                {"type": "file", "name": "README.md"},  # ignored
                {"type": "dir", "name": "subdir"},      # ignored
            ],
            "/repos/example/api/contents/.github/workflows/ci.yml":
                _b64_content("name: ci"),
            "/repos/example/api/contents/.github/workflows/release.yaml":
                _b64_content("name: release"),
            # Root pipeline probes — all 404.
            "/repos/example/api/contents/.gitlab-ci.yml": None,
            "/repos/example/api/contents/.gitlab-ci.yaml": None,
            "/repos/example/api/contents/Jenkinsfile": None,
            "/repos/example/api/contents/jenkinsfile": None,
            "/repos/example/api/contents/.jenkinsfile": None,
        })
        files = self._provider(http).fetch_pipeline_files("example/api")
        paths = sorted(f.path for f in files)
        assert paths == [
            ".github/workflows/ci.yml",
            ".github/workflows/release.yaml",
        ]
        ci = next(f for f in files if f.path.endswith("ci.yml"))
        assert ci.content == "name: ci"

    def test_fetch_pipeline_files_finds_root_jenkinsfile(self):
        http = _StubHttp(responses={
            # Workflows dir not present.
            "/repos/example/api/contents/.github/workflows": None,
            "/repos/example/api/contents/.gitlab-ci.yml": None,
            "/repos/example/api/contents/.gitlab-ci.yaml": None,
            "/repos/example/api/contents/Jenkinsfile":
                _b64_content("pipeline { agent any }"),
            "/repos/example/api/contents/jenkinsfile": None,
            "/repos/example/api/contents/.jenkinsfile": None,
        })
        files = self._provider(http).fetch_pipeline_files("example/api")
        assert [f.path for f in files] == ["Jenkinsfile"]
        assert "pipeline" in files[0].content

    def test_fetch_pipeline_files_returns_empty_on_no_pipelines(self):
        http = _StubHttp(responses={
            "/repos/example/empty/contents/.github/workflows": None,
            "/repos/example/empty/contents/.gitlab-ci.yml": None,
            "/repos/example/empty/contents/.gitlab-ci.yaml": None,
            "/repos/example/empty/contents/Jenkinsfile": None,
            "/repos/example/empty/contents/jenkinsfile": None,
            "/repos/example/empty/contents/.jenkinsfile": None,
        })
        files = self._provider(http).fetch_pipeline_files("example/empty")
        assert files == []

    def test_unparseable_full_name_skipped_in_list(self):
        http = _StubHttp(responses={
            "/orgs/example/repos": [
                {"full_name": "valid/one"},
                {"full_name": "no-slash"},   # malformed → skipped
                {},                           # missing → skipped
            ],
        })
        repos = self._provider(http).list_repos("example")
        assert [r.full_name for r in repos] == ["valid/one"]


# ---------------------------------------------------------------------------
# github_org_provider_from_env
# ---------------------------------------------------------------------------


class TestProviderFromEnv:
    def test_no_token_returns_none(self):
        assert github_org_provider_from_env({}) is None

    def test_blank_token_returns_none(self):
        assert github_org_provider_from_env({"CIGUARD_GITHUB_TOKEN": "  "}) is None

    def test_builds_provider(self):
        p = github_org_provider_from_env({"CIGUARD_GITHUB_TOKEN": "ghp_x"})
        assert p is not None
        assert p.api_base == "https://api.github.com"

    def test_honours_api_url_override(self):
        p = github_org_provider_from_env({
            "CIGUARD_GITHUB_TOKEN": "ghp_x",
            "CIGUARD_GITHUB_API_URL": "https://ghe.example.com/api/v3/",
        })
        assert p is not None
        assert p.api_base == "https://ghe.example.com/api/v3"


# ---------------------------------------------------------------------------
# Reporter (org_audit_html) tests
# ---------------------------------------------------------------------------


class TestOrgAuditHTML:
    def _report_with_findings(self) -> OrgAuditReport:
        return OrgAuditReport(
            org="example",
            repos=[
                RepoScanRecord(
                    repo="example/api",
                    private=True,
                    scan={
                        "files_scanned": 2,
                        "total_findings": 3,
                        "by_severity": {"Critical": 1, "High": 2,
                                        "Medium": 0, "Low": 0, "Info": 0},
                        "files": [
                            {"path": "ci.yml", "platform": "github-actions",
                             "grade": "C", "findings_total": 2,
                             "findings_by_severity": {}},
                            {"path": "release.yml", "platform": "github-actions",
                             "grade": "D", "findings_total": 1,
                             "findings_by_severity": {}},
                        ],
                    },
                ),
                RepoScanRecord(
                    repo="example/empty",
                    pipeline_file_count=0,
                ),
                RepoScanRecord(
                    repo="example/locked",
                    error="HTTP 403 — forbidden",
                ),
            ],
            errors=[{"repo": "example/locked", "phase": "fetch_pipeline_files",
                     "error": "HTTP 403 — forbidden"}],
            skipped_archived=2,
        )

    def test_renders_html5_with_org_in_title(self):
        out = org_audit_html.render(self._report_with_findings())
        assert out.startswith("<!DOCTYPE html>")
        assert "<title>ciguard audit-org" in out
        assert "example</title>" in out
        assert "</html>" in out

    def test_summary_counts(self):
        out = org_audit_html.render(self._report_with_findings())
        # 1 of 3 records has scan results
        assert "1</span> repos scanned" in out
        assert "3</span> repos in scope" in out
        assert "3</span> findings" in out

    def test_severity_chips_render(self):
        out = org_audit_html.render(self._report_with_findings())
        assert "1 C" in out  # 1 Critical
        assert "2 H" in out  # 2 High

    def test_grade_distribution_strip(self):
        out = org_audit_html.render(self._report_with_findings())
        # api has worst grade D (worst across its files), empty + locked → ?
        assert "Grade distribution" in out
        assert ">D<" in out or "D</span>" in out
        # 2 repos have no graded scan → counted under '?'
        assert "no scan" in out

    def test_platform_strip(self):
        out = org_audit_html.render(self._report_with_findings())
        assert "github-actions" in out

    def test_archived_skip_meta_line(self):
        out = org_audit_html.render(self._report_with_findings())
        assert "Skipped:" in out
        assert "2 archived" in out

    def test_error_panel_rendered(self):
        out = org_audit_html.render(self._report_with_findings())
        assert "Errors (1)" in out
        assert "HTTP 403" in out

    def test_private_flag_chip(self):
        out = org_audit_html.render(self._report_with_findings())
        assert "private" in out

    def test_html_escapes_repo_descriptions(self):
        report = OrgAuditReport(
            org="x",
            repos=[
                RepoScanRecord(
                    repo="ex/api",
                    description="<script>alert(1)</script>",
                    pipeline_file_count=0,
                ),
            ],
        )
        out = org_audit_html.render(report)
        assert "<script>alert(1)</script>" not in out
        assert "&lt;script&gt;" in out

    def test_empty_repo_list_renders_message(self):
        report = OrgAuditReport(org="empty-org")
        out = org_audit_html.render(report)
        assert "no repos in scope" in out

    def test_write_report_creates_parent_dir(self, tmp_path):
        report = OrgAuditReport(org="x")
        target = tmp_path / "deep" / "nested" / "dash.html"
        org_audit_html.write_report(report, target)
        assert target.exists()
        assert target.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


# ---------------------------------------------------------------------------
# Image inventory aggregation (Slice 17 session 2)
# ---------------------------------------------------------------------------


class TestImageInventory:
    def _record(self, repo, *images):
        return RepoScanRecord(
            repo=repo,
            scan={
                "files_scanned": 1, "total_findings": 0,
                "by_severity": {sev: 0 for sev in
                                ("Critical", "High", "Medium", "Low", "Info")},
                "files": [],
            },
            images=list(images),
        )

    def _img(self, name, tag, pin_status, **extra):
        return {
            "raw": f"{name}:{tag}" if tag else name,
            "name": name,
            "tag": tag,
            "cycle_id": None,
            "digest": None,
            "registry": None,
            "pin_status": pin_status,
            "file": ".github/workflows/ci.yml",
            "platform": "github-actions",
            "location": "job[build].container",
            **extra,
        }

    def test_pin_discipline_percentages_round_to_one_decimal(self):
        report = OrgAuditReport(
            org="x",
            repos=[
                self._record("ex/a",
                             self._img("python", "3.11", "tag"),
                             self._img("python", "latest", "mutable")),
                self._record("ex/b",
                             self._img("redis", "7@sha256:abc", "digest"),
                             self._img("redis", "latest", "mutable"),
                             self._img("redis", "7", "tag")),
            ],
        )
        pd = report.pin_discipline
        assert pd["counts"] == {"digest": 1, "tag": 2, "mutable": 2}
        assert pd["total"] == 5
        assert pd["percentages"]["digest"] == 20.0
        assert pd["percentages"]["tag"] == 40.0
        assert pd["percentages"]["mutable"] == 40.0

    def test_pin_discipline_zero_when_no_images(self):
        report = OrgAuditReport(org="x", repos=[self._record("ex/a")])
        pd = report.pin_discipline
        assert pd["total"] == 0
        assert pd["percentages"] == {"digest": 0.0, "tag": 0.0, "mutable": 0.0}

    def test_image_inventory_dedupes_by_name(self):
        report = OrgAuditReport(
            org="x",
            repos=[
                self._record("ex/a", self._img("python", "3.11", "tag")),
                self._record("ex/b", self._img("python", "3.10", "tag")),
                self._record("ex/c", self._img("redis", "7", "tag")),
            ],
        )
        inv = report.image_inventory
        names = [e["name"] for e in inv]
        assert names == ["python", "redis"]
        py = next(e for e in inv if e["name"] == "python")
        assert py["repo_count"] == 2
        assert py["tags"] == ["3.10", "3.11"]
        assert py["distinct_tag_count"] == 2

    def test_image_inventory_sorted_by_repo_count_desc_then_name(self):
        report = OrgAuditReport(
            org="x",
            repos=[
                self._record("ex/a",
                             self._img("python", "3.11", "tag"),
                             self._img("redis", "7", "tag")),
                self._record("ex/b",
                             self._img("python", "3.10", "tag"),
                             self._img("nginx", "1.25", "tag")),
                self._record("ex/c", self._img("python", "3.9", "tag")),
            ],
        )
        inv = report.image_inventory
        assert [e["name"] for e in inv] == ["python", "nginx", "redis"]

    def test_image_inconsistencies_only_returns_multi_tag_images(self):
        report = OrgAuditReport(
            org="x",
            repos=[
                self._record("ex/a", self._img("python", "3.11", "tag")),
                self._record("ex/b", self._img("python", "3.10", "tag")),
                self._record("ex/c", self._img("redis", "7", "tag")),
                self._record("ex/d", self._img("redis", "7", "tag")),
            ],
        )
        inc = report.image_inconsistencies
        assert len(inc) == 1
        assert inc[0]["name"] == "python"
        assert inc[0]["distinct_tag_count"] == 2

    def test_image_inventory_skips_anonymous_images(self):
        # An image record without a `name` (parser couldn't resolve)
        # shouldn't add an empty-string bucket to the inventory.
        report = OrgAuditReport(
            org="x",
            repos=[
                self._record("ex/a",
                             self._img("python", "3.11", "tag"),
                             {"name": "", "pin_status": "mutable"}),
            ],
        )
        inv = report.image_inventory
        assert [e["name"] for e in inv] == ["python"]

    def test_total_image_references_sums_all_repos(self):
        report = OrgAuditReport(
            org="x",
            repos=[
                self._record("ex/a",
                             self._img("python", "3.11", "tag"),
                             self._img("redis", "7", "tag")),
                self._record("ex/b", self._img("python", "3.10", "tag")),
            ],
        )
        assert report.total_image_references == 3


# ---------------------------------------------------------------------------
# extract_repo_images integration (Slice 17 session 2)
# ---------------------------------------------------------------------------


class TestExtractRepoImages:
    def test_extracts_gitlab_image(self, tmp_path):
        from ciguard.audit_org.images import extract_repo_images

        (tmp_path / ".gitlab-ci.yml").write_text(
            "stages: [build]\n"
            "build-job:\n"
            "  stage: build\n"
            "  image: python:3.11.4\n"
            "  script: [echo hi]\n",
            encoding="utf-8",
        )
        records = extract_repo_images(tmp_path)
        assert len(records) == 1
        assert records[0]["name"] == "python"
        assert records[0]["tag"] == "3.11.4"
        assert records[0]["pin_status"] == "tag"
        assert records[0]["platform"] == "gitlab-ci"

    def test_classifies_mutable_tag_as_mutable(self, tmp_path):
        from ciguard.audit_org.images import extract_repo_images

        (tmp_path / ".gitlab-ci.yml").write_text(
            "stages: [build]\n"
            "build-job:\n"
            "  stage: build\n"
            "  image: redis:latest\n"
            "  script: [echo hi]\n",
            encoding="utf-8",
        )
        records = extract_repo_images(tmp_path)
        assert records[0]["pin_status"] == "mutable"

    def test_swallows_parse_errors(self, tmp_path):
        from ciguard.audit_org.images import extract_repo_images

        # Garbage YAML — parser raises; helper must not.
        (tmp_path / ".gitlab-ci.yml").write_text(
            "this is :: not :: valid:: yaml: : :\n"
            "  - and: [unbalanced\n",
            encoding="utf-8",
        )
        records = extract_repo_images(tmp_path)
        # Empty list, no exception.
        assert records == []


# ---------------------------------------------------------------------------
# Per-repo drill-down maps (Slice 17 session 3)
# ---------------------------------------------------------------------------


class TestRepoMaps:
    _CI_YAML = """name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo hello
"""

    def _provider(self, repos_with_files):
        files_by_repo = {
            r.full_name: [PipelineFile(path=".github/workflows/ci.yml",
                                        content=self._CI_YAML)]
            for r in repos_with_files
        }
        return StubProvider(repos_with_files, files_by_repo=files_by_repo)

    def test_repo_map_dir_writes_per_repo_html_and_dashboard_links(self, tmp_path):
        repos = [
            RepoInfo(full_name="example/api"),
            RepoInfo(full_name="example/web"),
        ]
        report = audit_org(
            "example", self._provider(repos),
            offline=True, repo_map_dir=tmp_path,
        )
        # Filesystem layout
        assert (tmp_path / "repos" / "example__api" /
                "github__workflows__ci.yml.html").exists()
        assert (tmp_path / "repos" / "example__web" /
                "github__workflows__ci.yml.html").exists()
        # Each record carries one map entry
        for rec in report.repos:
            assert len(rec.maps) == 1
            entry = rec.maps[0]
            assert entry["path"] == ".github/workflows/ci.yml"
            assert entry["href"].startswith("repos/")
            assert entry["href"].endswith(".html")

    def test_no_repo_map_dir_means_no_files_or_links(self, tmp_path):
        repos = [RepoInfo(full_name="example/api")]
        report = audit_org(
            "example", self._provider(repos),
            offline=True,
        )
        assert report.repos[0].maps == []
        # Nothing written to tmp_path
        assert list(tmp_path.iterdir()) == []

    def test_safe_dirname_collapses_owner_slash_repo(self, tmp_path):
        repos = [RepoInfo(full_name="acme-corp/payments-api")]
        audit_org("acme-corp", self._provider(repos),
                  offline=True, repo_map_dir=tmp_path)
        # Slash in `owner/name` becomes `__` in the dir name
        assert (tmp_path / "repos" / "acme-corp__payments-api").is_dir()
        assert not (tmp_path / "repos" / "acme-corp").exists()

    def test_per_file_render_failures_dont_blank_repo(self, tmp_path):
        # Provide one good file + one with garbage YAML. The garbage
        # one fails to parse so no map is written for it; the good
        # one still renders.
        provider = StubProvider(
            repos=[RepoInfo(full_name="ex/api")],
            files_by_repo={
                "ex/api": [
                    PipelineFile(path=".github/workflows/ci.yml", content=self._CI_YAML),
                    PipelineFile(path=".gitlab-ci.yml",
                                  content="bad ::\n  - [unbalanced"),
                ],
            },
        )
        report = audit_org("ex", provider, offline=True, repo_map_dir=tmp_path)
        good_paths = [m["path"] for m in report.repos[0].maps]
        assert ".github/workflows/ci.yml" in good_paths

    def test_safe_file_stem_collapses_path(self):
        from ciguard.audit_org.orchestrator import _safe_file_stem
        assert _safe_file_stem(".github/workflows/ci.yml") == "github__workflows__ci.yml"
        assert _safe_file_stem("Jenkinsfile") == "Jenkinsfile"
        assert _safe_file_stem(".gitlab-ci.yml") == "gitlab-ci.yml"


# ---------------------------------------------------------------------------
# HTML rendering of the new panels
# ---------------------------------------------------------------------------


class TestImagePanelsHTML:
    def _img(self, name, tag, pin_status):
        return {"name": name, "tag": tag, "pin_status": pin_status,
                "raw": f"{name}:{tag}", "cycle_id": None,
                "digest": None, "registry": None,
                "file": "x", "platform": "gitlab-ci", "location": "y"}

    def test_pin_discipline_panel_renders_when_images_present(self):
        report = OrgAuditReport(
            org="x",
            repos=[
                RepoScanRecord(
                    repo="ex/a",
                    images=[self._img("python", "3.11", "tag"),
                            self._img("python", "latest", "mutable")],
                ),
            ],
        )
        out = org_audit_html.render(report)
        assert "Pin discipline" in out
        assert "50.0%" in out

    def test_pin_discipline_panel_omitted_when_no_images(self):
        report = OrgAuditReport(org="x", repos=[
            RepoScanRecord(repo="ex/a"),
        ])
        out = org_audit_html.render(report)
        assert "Pin discipline" not in out

    def test_image_inventory_renders_inconsistency_warning(self):
        report = OrgAuditReport(
            org="x",
            repos=[
                RepoScanRecord(repo="ex/a",
                               images=[self._img("python", "3.11", "tag")]),
                RepoScanRecord(repo="ex/b",
                               images=[self._img("python", "3.10", "tag")]),
            ],
        )
        out = org_audit_html.render(report)
        assert "Image inventory" in out
        assert "1 inconsistent" in out
        assert "2 variants" in out
        assert "<code>python</code>" in out

    def test_per_repo_maps_rendered_as_links(self):
        report = OrgAuditReport(
            org="x",
            repos=[
                RepoScanRecord(
                    repo="ex/api",
                    scan={
                        "files_scanned": 1, "total_findings": 0,
                        "by_severity": {sev: 0 for sev in
                                        ("Critical", "High", "Medium", "Low", "Info")},
                        "files": [{"path": "ci.yml", "platform": "github-actions",
                                   "grade": "A", "findings_total": 0,
                                   "findings_by_severity": {}}],
                    },
                    maps=[{"path": ".github/workflows/ci.yml",
                            "file": "github__workflows__ci.yml.html",
                            "href": "repos/ex__api/github__workflows__ci.yml.html"}],
                ),
            ],
        )
        out = org_audit_html.render(report)
        assert 'class="flag flag-map"' in out
        assert 'href="repos/ex__api/github__workflows__ci.yml.html"' in out
        assert ".github/workflows/ci.yml" in out

    def test_no_map_chips_when_maps_empty(self):
        report = OrgAuditReport(
            org="x",
            repos=[RepoScanRecord(repo="ex/api")],
        )
        out = org_audit_html.render(report)
        assert 'class="flag flag-map"' not in out

    def test_map_link_href_html_escaped(self):
        report = OrgAuditReport(
            org="x",
            repos=[
                RepoScanRecord(
                    repo="ex/api",
                    maps=[{"path": "<evil>",
                            "file": "x.html",
                            "href": 'evil"&href'}],
                ),
            ],
        )
        out = org_audit_html.render(report)
        assert "<evil>" not in out
        assert "&lt;evil&gt;" in out
        # The raw double-quote that would break the href attribute
        # must be escaped.
        assert 'evil"&href' not in out
        assert "&quot;" in out or "&amp;" in out

    def test_image_inventory_no_inconsistency_label_when_clean(self):
        report = OrgAuditReport(
            org="x",
            repos=[
                RepoScanRecord(repo="ex/a",
                               images=[self._img("python", "3.11", "tag")]),
                RepoScanRecord(repo="ex/b",
                               images=[self._img("python", "3.11", "tag")]),
            ],
        )
        out = org_audit_html.render(report)
        assert "Image inventory" in out
        assert "inconsistent" not in out
