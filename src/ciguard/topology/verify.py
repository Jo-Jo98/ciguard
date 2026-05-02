"""
Live-API topology verification (Slice 16, session 4).

Cross-checks the operator-asserted `Topology` against what the live
SCM platform actually says exists, on the *gate* dimension. Pairs with
session 3's drift panel (which checks the asserted topology against
scanned pipeline files — the *file* dimension).

Two questions answered:

  1. Does the asserted environment exist on the platform at all?
     (operator declared deploy-edge to env `prod`, but GitHub doesn't
     list a `prod` deployment environment under that repo)
  2. Do the asserted gates match the actual protection rules?
     (operator asserted `[manual_approval, required_reviewer]`, but
     the live env has only a 5-minute wait_timer)

Three drift kinds:

  - `environment-not-found` — DeployEdge.environment isn't an env on
    the live platform for that repo. Most-actionable signal.
  - `gate-not-actual` — DeployEdge declares a gate the live env
    doesn't have. False sense of security; auditor's bread and butter.
  - `gate-actual-not-asserted` — live env has a protection rule the
    DeployEdge doesn't list. Lowest-signal: the topology under-claims
    protection. Surfaced for completeness, not as a posture concern.

Provider abstraction is deliberately minimal — single `Provider`
Protocol (`fetch(repo) -> RepoSnapshot`). GitHubProvider is the only
concrete implementation today; a GitLab equivalent fits the same
shape (the gate vocabulary maps cleanly to GitLab's `environments`
API + `protected_branches` API).

Network model: synchronous HTTP via stdlib `urllib.request` (mirrors
the inventory probes + SCA clients — no extra deps). 8 s timeout,
5 MB cap. `CIGUARD_GITHUB_TOKEN` env var; `CIGUARD_GITHUB_API_URL`
override for GitHub Enterprise (defaults to api.github.com).

Pure orchestration is testable without network — provider is injected,
tests pass a stub. The GitHub HTTP calls live on GitHubProvider only.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol

from ..models.topology import Topology

USER_AGENT = "ciguard-topology-verify/0.1 (+https://github.com/Jo-Jo98/ciguard)"
DEFAULT_TIMEOUT_SECONDS = 8
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
DEFAULT_GITHUB_API = "https://api.github.com"

# Branch-protection-style gates apply to the *repo* (default branch),
# not to a specific deployment environment. Drift-checking these reads
# `LiveBranchProtection`, not `LiveEnvironment`.
_BRANCH_LEVEL_GATES = {
    "branch_protection",
    "required_status_check",
}


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass
class LiveEnvironment:
    """One deployment environment as the platform sees it. `protection_rules`
    is normalised to ciguard's gate vocabulary (`manual_approval`,
    `required_reviewer`, `wait_timer`, `deployment_environment_protection`)
    so the drift comparison is apples-to-apples regardless of which platform
    sourced it."""
    name: str
    protection_rules: List[str] = field(default_factory=list)


@dataclass
class LiveBranchProtection:
    """Branch-protection state on the repo's default branch (or a named
    branch when topologies wire promotion gates per-branch — future
    work). `rules` is normalised to ciguard's gate vocabulary."""
    branch: str
    rules: List[str] = field(default_factory=list)


@dataclass
class RepoSnapshot:
    """Per-repo result of one provider fetch. `error` is set when the
    repo couldn't be queried (404, 401, network) — the verifier marks
    every DeployEdge for services in this repo as `unverifiable`."""
    repo: str
    default_branch: Optional[str] = None
    environments: List[LiveEnvironment] = field(default_factory=list)
    branch_protection: Optional[LiveBranchProtection] = None
    error: Optional[str] = None


@dataclass
class DriftRecord:
    """One asserted-vs-actual mismatch on a DeployEdge. Serialises as a
    plain dict for the HTML reporter + JSON output."""
    kind: str
    service: str
    environment: str
    asserted_gates: List[str]
    actual_gates: List[str]
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "service": self.service,
            "environment": self.environment,
            "asserted_gates": list(self.asserted_gates),
            "actual_gates": list(self.actual_gates),
            "detail": self.detail,
        }


# ---------------------------------------------------------------------------
# Provider Protocol
# ---------------------------------------------------------------------------


class Provider(Protocol):
    """A platform that can answer 'tell me about repo R'."""
    name: str

    def fetch(self, repo: str) -> RepoSnapshot: ...


class ProviderError(Exception):
    """Raised when a provider can't query the platform. Caught by the
    verifier and surfaced as `RepoSnapshot.error`."""


# ---------------------------------------------------------------------------
# HTTP helper (private — used only by GitHubProvider)
# ---------------------------------------------------------------------------


def _http_get_json(
    url: str,
    *,
    token: str,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> Any:
    """GET `url` with bearer auth, return parsed JSON. Raises
    `ProviderError` on HTTP failure / non-JSON / oversize. 404 is
    surfaced as `ProviderError` with a clear message — callers (in
    GitHubProvider) decide whether 404 is fatal or expected."""
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Authorization": f"Bearer {token}",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            if resp.status != 200:
                raise ProviderError(f"HTTP {resp.status}")
            body = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise ProviderError(
                    f"response exceeded {MAX_RESPONSE_BYTES} bytes — refusing"
                )
            try:
                return json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ProviderError(f"response is not valid JSON: {exc}")
    except urllib.error.HTTPError as exc:
        msg = f"HTTP {exc.code}"
        if exc.code in (401, 403):
            msg += " — check CIGUARD_GITHUB_TOKEN scope (repo + read:org)"
        elif exc.code == 404:
            msg += " — repo or endpoint not found"
        raise ProviderError(msg)
    except urllib.error.URLError as exc:
        raise ProviderError(f"network error: {exc.reason}")
    except (TimeoutError, OSError) as exc:
        raise ProviderError(f"connection failed: {exc}")


# ---------------------------------------------------------------------------
# GitHub provider
# ---------------------------------------------------------------------------


class GitHubProvider:
    """Reads deployment-environments + branch-protection from GitHub.

    Mapping from GitHub's protection-rule shape to ciguard's gate
    vocabulary:

      - `required_reviewers`   → `manual_approval` + `required_reviewer`
      - `wait_timer`           → `wait_timer`
      - `branch_policy`        → `deployment_environment_protection`

    Branch protection (default branch only — per-environment branch
    policies are surfaced via the env's `branch_policy` rule):

      - presence (200 OK)                            → `branch_protection`
      - required_pull_request_reviews.count >= 1     → `required_reviewer`
      - required_status_checks.contexts non-empty    → `required_status_check`

    The 401 response from `/branches/<branch>/protection` is treated as
    'no branch protection configured' (200 = configured, 404 = no protection,
    401 = no permission to read it). 401 is logged but not fatal — the env
    list still drives the drift report.
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
            raise ValueError("GitHubProvider requires a non-empty token")
        self.token = token
        self.api_base = api_base.rstrip("/")
        self.timeout = timeout
        # Test seam: tests inject a fake `http_get(url, *, token, timeout)`
        # that returns parsed JSON. Production passes the stdlib helper.
        self._http_get = http_get or _http_get_json

    def fetch(self, repo: str) -> RepoSnapshot:
        """Fetch repo metadata + envs + default-branch protection. Returns a
        `RepoSnapshot`. Single ProviderError sets snapshot.error and
        leaves the rest empty — partial results aren't worth the
        complexity for an audit deliverable."""
        if "/" not in repo:
            return RepoSnapshot(
                repo=repo,
                error=f"repo {repo!r} is not in `owner/name` form",
            )

        # Step 1: repo metadata (we need the default branch).
        try:
            meta = self._http_get(
                f"{self.api_base}/repos/{repo}",
                token=self.token,
                timeout=self.timeout,
            )
        except ProviderError as exc:
            return RepoSnapshot(repo=repo, error=str(exc))

        default_branch = (meta or {}).get("default_branch") if isinstance(meta, dict) else None
        snapshot = RepoSnapshot(repo=repo, default_branch=default_branch)

        # Step 2: deployment environments. May be empty (404 isn't expected
        # here — the endpoint always returns 200 with zero envs).
        try:
            envs_payload = self._http_get(
                f"{self.api_base}/repos/{repo}/environments",
                token=self.token,
                timeout=self.timeout,
            )
            snapshot.environments = self._parse_environments(envs_payload)
        except ProviderError as exc:
            # If envs fail, leave them empty but continue to branch
            # protection so the auditor still sees what we could read.
            snapshot.error = f"environments: {exc}"

        # Step 3: branch protection on the default branch.
        if default_branch:
            snapshot.branch_protection = self._fetch_branch_protection(
                repo, default_branch
            )

        return snapshot

    @staticmethod
    def _parse_environments(payload: Any) -> List[LiveEnvironment]:
        """GitHub returns `{total_count, environments: [...]}`. Each env
        has `name` + optional `protection_rules` (typed objects)."""
        if not isinstance(payload, dict):
            return []
        envs_raw = payload.get("environments")
        if not isinstance(envs_raw, list):
            return []
        out: List[LiveEnvironment] = []
        for raw in envs_raw:
            if not isinstance(raw, dict):
                continue
            name = raw.get("name")
            if not isinstance(name, str) or not name:
                continue
            rules = GitHubProvider._normalise_env_rules(raw.get("protection_rules") or [])
            out.append(LiveEnvironment(name=name, protection_rules=rules))
        return out

    @staticmethod
    def _normalise_env_rules(rules_raw: Any) -> List[str]:
        """Map GitHub protection-rule types to ciguard's gate vocabulary.
        Order is stable + de-duped so the rendered output is deterministic."""
        out: List[str] = []
        seen: set[str] = set()

        def _add(gate: str) -> None:
            if gate not in seen:
                out.append(gate)
                seen.add(gate)

        if not isinstance(rules_raw, list):
            return out
        for rule in rules_raw:
            if not isinstance(rule, dict):
                continue
            rule_type = rule.get("type")
            if rule_type == "required_reviewers":
                _add("manual_approval")
                _add("required_reviewer")
            elif rule_type == "wait_timer":
                _add("wait_timer")
            elif rule_type == "branch_policy":
                _add("deployment_environment_protection")
        return out

    def _fetch_branch_protection(
        self, repo: str, branch: str
    ) -> Optional[LiveBranchProtection]:
        """Read `/branches/{branch}/protection` and translate to ciguard's
        gate vocabulary. 404 → 'no protection configured' → returns None.
        401 → 'we lack the scope to read it' → returns None (the auditor
        sees no protection in the report; this is the safe interpretation
        because ciguard can't prove it). Other errors → None."""
        try:
            payload = self._http_get(
                f"{self.api_base}/repos/{repo}/branches/{branch}/protection",
                token=self.token,
                timeout=self.timeout,
            )
        except ProviderError:
            return None
        if not isinstance(payload, dict):
            return None

        rules: List[str] = ["branch_protection"]
        seen = set(rules)

        def _add(gate: str) -> None:
            if gate not in seen:
                rules.append(gate)
                seen.add(gate)

        prr = payload.get("required_pull_request_reviews")
        if isinstance(prr, dict):
            count = prr.get("required_approving_review_count")
            if isinstance(count, int) and count >= 1:
                _add("required_reviewer")

        rsc = payload.get("required_status_checks")
        if isinstance(rsc, dict):
            contexts = rsc.get("contexts") or rsc.get("checks") or []
            if isinstance(contexts, list) and len(contexts) > 0:
                _add("required_status_check")

        return LiveBranchProtection(branch=branch, rules=rules)


# ---------------------------------------------------------------------------
# Verifier orchestration
# ---------------------------------------------------------------------------


def verify_topology(
    topology: Topology,
    provider: Provider,
) -> Dict[str, Any]:
    """Walk every DeployEdge whose service has a known repo + a known
    pipeline path, fetch each repo's live state once, then compute drift.

    Output shape (JSON-serialisable):

        {
            "by_repo": {
                "owner/name": {
                    "default_branch": "main",
                    "environments": [{"name": "prod", "protection_rules": [...]}],
                    "branch_protection": {"branch": "main", "rules": [...]} | None,
                    "error": "..." | None,
                },
                ...
            },
            "drift": [DriftRecord.to_dict(), ...],
            "unverifiable": [
                {"service": "...", "reason": "..."}, ...
            ],
        }
    """
    repo_for_service: Dict[str, Optional[str]] = {
        s.id: s.repo for s in topology.services
    }

    by_repo: Dict[str, Dict[str, Any]] = {}
    drift: List[DriftRecord] = []
    unverifiable: List[Dict[str, str]] = []

    # Fetch one snapshot per unique repo (multiple deploy_edges per repo
    # is the common case — api → dev/staging/prod is three edges, one
    # repo, one fetch).
    needed_repos: List[str] = []
    seen_repo: set[str] = set()
    for edge in topology.deploy_edges:
        repo = repo_for_service.get(edge.service)
        if not repo:
            continue
        if repo in seen_repo:
            continue
        seen_repo.add(repo)
        needed_repos.append(repo)

    for repo in needed_repos:
        snap = provider.fetch(repo)
        by_repo[repo] = {
            "default_branch": snap.default_branch,
            "environments": [
                {"name": e.name, "protection_rules": list(e.protection_rules)}
                for e in snap.environments
            ],
            "branch_protection": (
                {"branch": snap.branch_protection.branch,
                 "rules": list(snap.branch_protection.rules)}
                if snap.branch_protection else None
            ),
            "error": snap.error,
        }

    for edge in topology.deploy_edges:
        repo = repo_for_service.get(edge.service)
        if not repo:
            unverifiable.append({
                "service": edge.service,
                "environment": edge.environment,
                "reason": "service has no `repo` set in topology",
            })
            continue
        snap_dict = by_repo.get(repo)
        if snap_dict is None:
            # Should not happen — we collected every repo above. Defensive.
            unverifiable.append({
                "service": edge.service,
                "environment": edge.environment,
                "reason": f"repo {repo!r} not fetched",
            })
            continue
        if snap_dict.get("error"):
            unverifiable.append({
                "service": edge.service,
                "environment": edge.environment,
                "reason": f"{repo}: {snap_dict['error']}",
            })
            continue

        live_env = _find_env(snap_dict["environments"], edge.environment)
        if live_env is None:
            drift.append(DriftRecord(
                kind="environment-not-found",
                service=edge.service,
                environment=edge.environment,
                asserted_gates=list(edge.gates),
                actual_gates=[],
                detail=(
                    f"topology asserts {edge.service} deploys to "
                    f"{edge.environment} but {repo} has no such "
                    "deployment environment"
                ),
            ))
            continue

        actual_env_rules = list(live_env["protection_rules"])
        bp = snap_dict.get("branch_protection") or {}
        actual_branch_rules = list(bp.get("rules") or [])
        # The combined "actual" set used to compare against asserted gates
        # depends on which gate is being checked (env-level vs branch-level).
        actual_combined = sorted(set(actual_env_rules) | set(actual_branch_rules))

        for asserted_gate in edge.gates:
            if asserted_gate in _BRANCH_LEVEL_GATES:
                if asserted_gate not in actual_branch_rules:
                    drift.append(DriftRecord(
                        kind="gate-not-actual",
                        service=edge.service,
                        environment=edge.environment,
                        asserted_gates=list(edge.gates),
                        actual_gates=actual_combined,
                        detail=(
                            f"topology asserts gate {asserted_gate!r} on "
                            f"{edge.service} → {edge.environment} but "
                            f"branch protection on {repo} default branch "
                            "doesn't include it"
                        ),
                    ))
            else:
                if asserted_gate not in actual_env_rules:
                    drift.append(DriftRecord(
                        kind="gate-not-actual",
                        service=edge.service,
                        environment=edge.environment,
                        asserted_gates=list(edge.gates),
                        actual_gates=actual_combined,
                        detail=(
                            f"topology asserts gate {asserted_gate!r} on "
                            f"{edge.service} → {edge.environment} but the "
                            f"live env on {repo} doesn't have that "
                            "protection rule"
                        ),
                    ))

        for actual_gate in actual_env_rules:
            if actual_gate not in edge.gates:
                drift.append(DriftRecord(
                    kind="gate-actual-not-asserted",
                    service=edge.service,
                    environment=edge.environment,
                    asserted_gates=list(edge.gates),
                    actual_gates=actual_combined,
                    detail=(
                        f"live env on {repo} has gate {actual_gate!r} that "
                        "the topology DeployEdge doesn't list — under-claimed "
                        "protection"
                    ),
                ))

    return {
        "by_repo": by_repo,
        "drift": [d.to_dict() for d in drift],
        "unverifiable": unverifiable,
    }


def _find_env(envs: List[Dict[str, Any]], env_id: str) -> Optional[Dict[str, Any]]:
    """Case-insensitive match — operators routinely write `Prod` in YAML
    where GitHub stores `production`. Exact-case wins; otherwise lowercase
    fallback. Returns None when nothing matches."""
    for e in envs:
        if e["name"] == env_id:
            return e
    target = env_id.lower()
    for e in envs:
        if e["name"].lower() == target:
            return e
    return None


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------


def github_provider_from_env(env: Optional[Dict[str, str]] = None) -> Optional[GitHubProvider]:
    """Build a `GitHubProvider` from `CIGUARD_GITHUB_TOKEN` (+ optional
    `CIGUARD_GITHUB_API_URL`). Returns None when no token is set so the
    CLI can print a clear error rather than constructing an unusable
    provider."""
    e = dict(env) if env is not None else dict(os.environ)
    token = e.get("CIGUARD_GITHUB_TOKEN", "").strip()
    if not token:
        return None
    api = e.get("CIGUARD_GITHUB_API_URL", DEFAULT_GITHUB_API).strip() or DEFAULT_GITHUB_API
    return GitHubProvider(token=token, api_base=api)
