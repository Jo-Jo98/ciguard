"""
Tests for live-API topology verification (Slice 16, session 4).

Three layers of coverage:

  1. `GitHubProvider` — tested with a stub `http_get` injected via the
     constructor. No network. Asserts the protection-rule mapping
     from GitHub's shape to ciguard's gate vocabulary, the 401/404
     branch-protection handling, and the partial-result behaviour
     when one endpoint fails.

  2. `verify_topology` orchestration — tested with a stub Provider
     that returns canned `RepoSnapshot`s. Exercises every drift kind,
     the case-insensitive env match, the unverifiable list (no repo
     set / repo error), and the per-repo dedup (multiple deploy_edges
     in the same repo trigger one fetch).

  3. `github_provider_from_env` — env-var resolution + GHE override.

The test fixture topology is built in-memory so the tests don't
depend on the YAML loader.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.models.topology import (
    DeployEdge,
    Environment,
    Service,
    Topology,
)
from ciguard.topology.verify import (
    DriftRecord,
    GitHubProvider,
    LiveBranchProtection,
    LiveEnvironment,
    ProviderError,
    RepoSnapshot,
    github_provider_from_env,
    verify_topology,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def small_topology() -> Topology:
    """Two services, one shared environment id (`prod`), three deploy
    edges. `worker` deliberately has no repo so we exercise the
    'unverifiable' path."""
    return Topology(
        services=[
            Service(id="api", repo="example/api"),
            Service(id="web", repo="example/web"),
            Service(id="worker"),  # no repo → unverifiable
        ],
        environments=[
            Environment(id="dev", tier="development"),
            Environment(id="prod", tier="production"),
        ],
        deploy_edges=[
            DeployEdge(service="api", environment="dev",
                       pipeline=".github/workflows/dev.yml",
                       gates=["branch_protection"]),
            DeployEdge(service="api", environment="prod",
                       pipeline=".github/workflows/prod.yml",
                       gates=["manual_approval", "required_reviewer"]),
            DeployEdge(service="web", environment="prod",
                       pipeline=".github/workflows/web-prod.yml",
                       gates=["manual_approval"]),
            DeployEdge(service="worker", environment="prod",
                       pipeline=".gitlab-ci.yml",
                       gates=[]),
        ],
    )


class StubProvider:
    """In-memory Provider that returns canned snapshots keyed by repo."""
    name: str = "stub"

    def __init__(self, snapshots):
        self.snapshots = snapshots
        self.calls: list[str] = []

    def fetch(self, repo: str) -> RepoSnapshot:
        self.calls.append(repo)
        if repo not in self.snapshots:
            return RepoSnapshot(repo=repo, error="not configured in test stub")
        return self.snapshots[repo]


# ---------------------------------------------------------------------------
# verify_topology — drift detection
# ---------------------------------------------------------------------------


class TestVerifyTopologyDrift:
    def test_clean_match_no_drift(self, small_topology):
        provider = StubProvider({
            "example/api": RepoSnapshot(
                repo="example/api",
                default_branch="main",
                environments=[
                    LiveEnvironment(name="dev", protection_rules=[]),
                    LiveEnvironment(
                        name="prod",
                        protection_rules=["manual_approval", "required_reviewer"],
                    ),
                ],
                branch_protection=LiveBranchProtection(
                    branch="main", rules=["branch_protection"],
                ),
            ),
            "example/web": RepoSnapshot(
                repo="example/web",
                default_branch="main",
                environments=[
                    LiveEnvironment(name="prod", protection_rules=["manual_approval"]),
                ],
            ),
        })
        result = verify_topology(small_topology, provider)
        # No drift expected for the clean repos
        env_drift = [d for d in result["drift"] if d["kind"] == "environment-not-found"]
        gate_missing = [d for d in result["drift"] if d["kind"] == "gate-not-actual"]
        assert env_drift == []
        assert gate_missing == []

    def test_environment_not_found_drift(self, small_topology):
        provider = StubProvider({
            "example/api": RepoSnapshot(
                repo="example/api",
                default_branch="main",
                environments=[LiveEnvironment(name="dev", protection_rules=[])],
                branch_protection=LiveBranchProtection(
                    branch="main", rules=["branch_protection"],
                ),
            ),
            "example/web": RepoSnapshot(
                repo="example/web",
                default_branch="main",
                environments=[],
            ),
        })
        result = verify_topology(small_topology, provider)
        kinds = [d["kind"] for d in result["drift"]]
        assert "environment-not-found" in kinds
        # api → prod and web → prod both missing
        env_misses = [
            d for d in result["drift"]
            if d["kind"] == "environment-not-found"
        ]
        services_with_miss = sorted(d["service"] for d in env_misses)
        assert services_with_miss == ["api", "web"]

    def test_gate_not_actual_when_live_env_missing_a_gate(self, small_topology):
        provider = StubProvider({
            "example/api": RepoSnapshot(
                repo="example/api",
                default_branch="main",
                environments=[
                    LiveEnvironment(name="dev", protection_rules=[]),
                    # prod has only manual_approval, NOT required_reviewer
                    LiveEnvironment(name="prod", protection_rules=["manual_approval"]),
                ],
                branch_protection=LiveBranchProtection(
                    branch="main", rules=["branch_protection"],
                ),
            ),
            "example/web": RepoSnapshot(
                repo="example/web",
                default_branch="main",
                environments=[
                    LiveEnvironment(name="prod", protection_rules=["manual_approval"]),
                ],
            ),
        })
        result = verify_topology(small_topology, provider)
        misses = [
            d for d in result["drift"]
            if d["kind"] == "gate-not-actual"
            and d["service"] == "api"
            and d["environment"] == "prod"
        ]
        assert len(misses) == 1
        assert "required_reviewer" in misses[0]["detail"]

    def test_branch_level_gate_checks_branch_protection_not_env(self, small_topology):
        # api → dev asserts `branch_protection`. We populate the env with
        # NO env-level rules, but the branch protection has it. Should be
        # considered satisfied (no drift).
        provider = StubProvider({
            "example/api": RepoSnapshot(
                repo="example/api",
                default_branch="main",
                environments=[
                    LiveEnvironment(name="dev", protection_rules=[]),
                    LiveEnvironment(
                        name="prod",
                        protection_rules=["manual_approval", "required_reviewer"],
                    ),
                ],
                branch_protection=LiveBranchProtection(
                    branch="main", rules=["branch_protection"],
                ),
            ),
            "example/web": RepoSnapshot(
                repo="example/web",
                environments=[
                    LiveEnvironment(name="prod", protection_rules=["manual_approval"]),
                ],
            ),
        })
        result = verify_topology(small_topology, provider)
        bp_drift = [
            d for d in result["drift"]
            if d["service"] == "api"
            and d["environment"] == "dev"
            and "branch_protection" in d.get("detail", "")
        ]
        assert bp_drift == []

    def test_branch_level_gate_drift_when_branch_protection_missing(self, small_topology):
        # Same fixture but branch_protection is None — api → dev's
        # asserted `branch_protection` gate becomes drift.
        provider = StubProvider({
            "example/api": RepoSnapshot(
                repo="example/api",
                default_branch="main",
                environments=[
                    LiveEnvironment(name="dev", protection_rules=[]),
                    LiveEnvironment(
                        name="prod",
                        protection_rules=["manual_approval", "required_reviewer"],
                    ),
                ],
                branch_protection=None,
            ),
            "example/web": RepoSnapshot(
                repo="example/web",
                environments=[
                    LiveEnvironment(name="prod", protection_rules=["manual_approval"]),
                ],
            ),
        })
        result = verify_topology(small_topology, provider)
        bp_drift = [
            d for d in result["drift"]
            if d["service"] == "api"
            and d["environment"] == "dev"
            and d["kind"] == "gate-not-actual"
        ]
        assert len(bp_drift) == 1

    def test_actual_not_asserted_drift(self, small_topology):
        # api → prod asserts manual_approval + required_reviewer.
        # If the live env ALSO has wait_timer, that's actual-not-asserted.
        provider = StubProvider({
            "example/api": RepoSnapshot(
                repo="example/api",
                default_branch="main",
                environments=[
                    LiveEnvironment(name="dev", protection_rules=[]),
                    LiveEnvironment(
                        name="prod",
                        protection_rules=["manual_approval", "required_reviewer", "wait_timer"],
                    ),
                ],
                branch_protection=LiveBranchProtection(
                    branch="main", rules=["branch_protection"],
                ),
            ),
            "example/web": RepoSnapshot(
                repo="example/web",
                environments=[
                    LiveEnvironment(name="prod", protection_rules=["manual_approval"]),
                ],
            ),
        })
        result = verify_topology(small_topology, provider)
        extras = [
            d for d in result["drift"]
            if d["kind"] == "gate-actual-not-asserted"
            and d["service"] == "api"
            and d["environment"] == "prod"
        ]
        assert any("wait_timer" in d["detail"] for d in extras)

    def test_case_insensitive_env_match(self):
        topology = Topology(
            services=[Service(id="api", repo="example/api")],
            environments=[Environment(id="prod", tier="production")],
            deploy_edges=[
                DeployEdge(service="api", environment="prod",
                           gates=["manual_approval"]),
            ],
        )
        # GitHub stores "Prod" (different casing of the same name) —
        # should still match. Synonym pairs like prod/production are
        # NOT auto-aligned (auditor must rename either side).
        provider = StubProvider({
            "example/api": RepoSnapshot(
                repo="example/api",
                environments=[
                    LiveEnvironment(name="Prod", protection_rules=["manual_approval"]),
                ],
            ),
        })
        result = verify_topology(topology, provider)
        env_misses = [d for d in result["drift"] if d["kind"] == "environment-not-found"]
        assert env_misses == []


# ---------------------------------------------------------------------------
# verify_topology — unverifiable + dedup
# ---------------------------------------------------------------------------


class TestVerifyTopologyUnverifiable:
    def test_service_without_repo_marked_unverifiable(self, small_topology):
        provider = StubProvider({
            "example/api": RepoSnapshot(repo="example/api"),
            "example/web": RepoSnapshot(repo="example/web"),
        })
        result = verify_topology(small_topology, provider)
        worker_unv = [
            u for u in result["unverifiable"]
            if u["service"] == "worker"
        ]
        assert len(worker_unv) == 1
        assert "no `repo`" in worker_unv[0]["reason"]

    def test_repo_fetch_error_marks_all_edges_unverifiable(self):
        topology = Topology(
            services=[Service(id="api", repo="example/api")],
            environments=[
                Environment(id="dev"),
                Environment(id="prod", tier="production"),
            ],
            deploy_edges=[
                DeployEdge(service="api", environment="dev"),
                DeployEdge(service="api", environment="prod"),
            ],
        )
        provider = StubProvider({
            "example/api": RepoSnapshot(repo="example/api", error="HTTP 404"),
        })
        result = verify_topology(topology, provider)
        assert len(result["unverifiable"]) == 2
        assert all("HTTP 404" in u["reason"] for u in result["unverifiable"])
        assert result["drift"] == []

    def test_one_fetch_per_repo(self, small_topology):
        provider = StubProvider({
            "example/api": RepoSnapshot(repo="example/api"),
            "example/web": RepoSnapshot(repo="example/web"),
        })
        verify_topology(small_topology, provider)
        # api has two edges (dev + prod) but only one fetch should happen.
        assert provider.calls.count("example/api") == 1
        assert provider.calls.count("example/web") == 1

    def test_by_repo_includes_all_fetched_repos(self, small_topology):
        provider = StubProvider({
            "example/api": RepoSnapshot(
                repo="example/api",
                default_branch="main",
                environments=[LiveEnvironment(name="prod")],
            ),
            "example/web": RepoSnapshot(repo="example/web"),
        })
        result = verify_topology(small_topology, provider)
        assert "example/api" in result["by_repo"]
        assert "example/web" in result["by_repo"]
        # worker has no repo so it's not fetched.
        assert "" not in result["by_repo"]
        api_snap = result["by_repo"]["example/api"]
        assert api_snap["default_branch"] == "main"
        assert api_snap["environments"][0]["name"] == "prod"


# ---------------------------------------------------------------------------
# DriftRecord serialisation
# ---------------------------------------------------------------------------


class TestDriftRecord:
    def test_to_dict_round_trip(self):
        d = DriftRecord(
            kind="gate-not-actual",
            service="api",
            environment="prod",
            asserted_gates=["manual_approval"],
            actual_gates=["wait_timer"],
            detail="x",
        )
        out = d.to_dict()
        assert out["kind"] == "gate-not-actual"
        assert out["asserted_gates"] == ["manual_approval"]
        # Lists are copies so mutating the result doesn't mutate the record.
        out["asserted_gates"].append("X")
        assert d.asserted_gates == ["manual_approval"]


# ---------------------------------------------------------------------------
# GitHubProvider — protection-rule mapping
# ---------------------------------------------------------------------------


class _StubHttp:
    """Records calls + serves canned responses keyed by URL substring.
    Raises ProviderError for URLs in `errors`."""
    def __init__(self, responses=None, errors=None):
        self.responses = responses or {}
        self.errors = errors or {}
        self.calls: list[str] = []

    def __call__(self, url, *, token, timeout):
        self.calls.append(url)
        # Longest-key-wins so `/repos/x/y/environments` doesn't get
        # served the `/repos/x/y` payload.
        for key in sorted(self.errors.keys(), key=len, reverse=True):
            if key in url:
                raise self.errors[key]
        for key in sorted(self.responses.keys(), key=len, reverse=True):
            if key in url:
                return self.responses[key]
        raise ProviderError(f"unexpected URL in test stub: {url}")


class TestGitHubProvider:
    def _provider(self, http):
        return GitHubProvider(token="ghp_test", http_get=http)

    def test_required_reviewers_maps_to_two_gates(self):
        http = _StubHttp(responses={
            "/repos/example/api": {"default_branch": "main"},
            "/repos/example/api/environments": {
                "environments": [
                    {"name": "prod", "protection_rules": [
                        {"type": "required_reviewers"},
                    ]},
                ],
            },
            "/branches/main/protection": {
                "required_pull_request_reviews": {"required_approving_review_count": 0},
                "required_status_checks": {"contexts": []},
            },
        })
        snap = self._provider(http).fetch("example/api")
        assert snap.environments[0].protection_rules == [
            "manual_approval", "required_reviewer",
        ]

    def test_wait_timer_and_branch_policy_mapped(self):
        http = _StubHttp(responses={
            "/repos/example/api": {"default_branch": "main"},
            "/repos/example/api/environments": {
                "environments": [
                    {"name": "prod", "protection_rules": [
                        {"type": "wait_timer", "wait_timer": 5},
                        {"type": "branch_policy"},
                    ]},
                ],
            },
            "/branches/main/protection": {},
        })
        snap = self._provider(http).fetch("example/api")
        rules = snap.environments[0].protection_rules
        assert "wait_timer" in rules
        assert "deployment_environment_protection" in rules

    def test_branch_protection_emits_branch_protection_gate(self):
        http = _StubHttp(responses={
            "/repos/example/api": {"default_branch": "trunk"},
            "/repos/example/api/environments": {"environments": []},
            "/branches/trunk/protection": {
                "required_pull_request_reviews": {"required_approving_review_count": 2},
                "required_status_checks": {"contexts": ["ci/test"]},
            },
        })
        snap = self._provider(http).fetch("example/api")
        bp = snap.branch_protection
        assert bp is not None
        assert bp.branch == "trunk"
        assert "branch_protection" in bp.rules
        assert "required_reviewer" in bp.rules
        assert "required_status_check" in bp.rules

    def test_branch_protection_404_returns_none(self):
        http = _StubHttp(
            responses={
                "/repos/example/api": {"default_branch": "main"},
                "/repos/example/api/environments": {"environments": []},
            },
            errors={
                "/branches/main/protection": ProviderError("HTTP 404 — no protection"),
            },
        )
        snap = self._provider(http).fetch("example/api")
        assert snap.branch_protection is None
        # Repo error stays unset because the env fetch succeeded.
        assert snap.error is None

    def test_repo_404_returns_error_snapshot(self):
        http = _StubHttp(errors={
            "/repos/example/missing": ProviderError("HTTP 404 — repo not found"),
        })
        snap = self._provider(http).fetch("example/missing")
        assert snap.error is not None
        assert "404" in snap.error
        assert snap.environments == []
        assert snap.branch_protection is None

    def test_envs_endpoint_failure_keeps_branch_protection(self):
        http = _StubHttp(
            responses={
                "/repos/example/api": {"default_branch": "main"},
                "/branches/main/protection": {
                    "required_pull_request_reviews": {"required_approving_review_count": 1},
                },
            },
            errors={
                "/repos/example/api/environments": ProviderError("HTTP 500"),
            },
        )
        snap = self._provider(http).fetch("example/api")
        assert "environments" in (snap.error or "")
        assert snap.branch_protection is not None
        assert "required_reviewer" in snap.branch_protection.rules

    def test_repo_without_slash_errors_loud(self):
        http = _StubHttp()
        snap = self._provider(http).fetch("not-an-owner-repo")
        assert "owner/name" in (snap.error or "")
        # No HTTP calls should have happened.
        assert http.calls == []

    def test_constructor_rejects_empty_token(self):
        with pytest.raises(ValueError):
            GitHubProvider(token="")

    def test_dedupes_protection_rules(self):
        # Two `required_reviewers` entries shouldn't double the gate list.
        http = _StubHttp(responses={
            "/repos/example/api": {"default_branch": "main"},
            "/repos/example/api/environments": {
                "environments": [
                    {"name": "prod", "protection_rules": [
                        {"type": "required_reviewers"},
                        {"type": "required_reviewers"},
                    ]},
                ],
            },
            "/branches/main/protection": {},
        })
        snap = self._provider(http).fetch("example/api")
        rules = snap.environments[0].protection_rules
        assert rules.count("manual_approval") == 1
        assert rules.count("required_reviewer") == 1


# ---------------------------------------------------------------------------
# github_provider_from_env
# ---------------------------------------------------------------------------


class TestGithubProviderFromEnv:
    def test_returns_none_without_token(self):
        assert github_provider_from_env({}) is None

    def test_returns_none_with_blank_token(self):
        assert github_provider_from_env({"CIGUARD_GITHUB_TOKEN": "   "}) is None

    def test_builds_provider_with_token(self):
        provider = github_provider_from_env({"CIGUARD_GITHUB_TOKEN": "ghp_x"})
        assert provider is not None
        assert provider.api_base == "https://api.github.com"

    def test_honours_api_url_override(self):
        provider = github_provider_from_env({
            "CIGUARD_GITHUB_TOKEN": "ghp_x",
            "CIGUARD_GITHUB_API_URL": "https://ghe.example.com/api/v3/",
        })
        assert provider is not None
        # Trailing slash stripped to match the rest of the codebase.
        assert provider.api_base == "https://ghe.example.com/api/v3"
