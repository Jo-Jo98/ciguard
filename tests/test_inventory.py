"""
Tests for the infrastructure inventory module (Slice 14b).

HTTP is mocked at the urllib layer — same pattern as `test_sca_rules.py`
uses for endoflife.date / OSV.dev. Each probe has a unit test for the
happy path + at least one for an error mode (auth failure, missing
field, malformed JSON).

Runner tests verify env-var gating + EOL enrichment via a stubbed
EndOfLifeClient (no network).
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.inventory import ALL_PROBES, InventoryRunner, ProbeError
from ciguard.inventory.argocd import ArgoCDProbe
from ciguard.inventory.artifactory import ArtifactoryProbe
from ciguard.inventory.gitlab import GitLabSelfHostProbe
from ciguard.inventory.github_enterprise import GitHubEnterpriseProbe
from ciguard.inventory.harbor import HarborProbe
from ciguard.inventory.jenkins import JenkinsProbe
from ciguard.inventory.nexus import NexusProbe
from ciguard.inventory.sonarqube import SonarQubeProbe
from ciguard.inventory import probes as probes_mod
from ciguard.inventory import sonarqube as sonarqube_mod
from ciguard.models.inventory import InventoryEntry, InventoryReport


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class TestInventoryEntryStatus:
    def test_unconfigured(self):
        e = InventoryEntry(tool="jenkins", configured=False)
        assert e.status == "unconfigured"

    def test_error(self):
        e = InventoryEntry(tool="jenkins", configured=True, error="boom")
        assert e.status == "error"

    def test_end_of_life(self):
        e = InventoryEntry(
            tool="jenkins", configured=True, version="2.300",
            eol_date="2024-01-01", days_until_eol=-100,
        )
        assert e.status == "end-of-life"

    def test_end_of_support(self):
        e = InventoryEntry(
            tool="jenkins", configured=True, version="2.426",
            eos_date="2024-01-01", days_until_eos=-50, days_until_eol=200,
        )
        assert e.status == "end-of-support"

    def test_approaching_eol(self):
        e = InventoryEntry(
            tool="jenkins", configured=True, version="2.426",
            eol_date="2026-08-01", days_until_eol=90,
        )
        assert e.status == "approaching-eol"

    def test_ok(self):
        e = InventoryEntry(
            tool="jenkins", configured=True, version="2.500",
            eol_date="2027-12-01", days_until_eol=600,
        )
        assert e.status == "ok"


class TestInventoryReport:
    def test_configured_count(self):
        r = InventoryReport(entries=[
            InventoryEntry(tool="a", configured=True, version="1"),
            InventoryEntry(tool="b", configured=False),
            InventoryEntry(tool="c", configured=True, version="2"),
        ])
        assert r.configured_count == 2

    def test_has_findings_true_on_error(self):
        r = InventoryReport(entries=[
            InventoryEntry(tool="a", configured=True, error="x"),
        ])
        assert r.has_findings is True

    def test_has_findings_false_when_all_ok(self):
        r = InventoryReport(entries=[
            InventoryEntry(tool="a", configured=True, version="1"),
            InventoryEntry(tool="b", configured=False),
        ])
        assert r.has_findings is False


# ---------------------------------------------------------------------------
# HTTP helper — mocked urlopen
# ---------------------------------------------------------------------------

class _FakeResp:
    def __init__(self, status: int, body: bytes):
        self.status = status
        self._body = body

    def read(self, n: Optional[int] = None) -> bytes:
        if n is None:
            return self._body
        return self._body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def _mock_urlopen(monkeypatch, status: int, body: bytes):
    def fake_urlopen(req, timeout=None):
        return _FakeResp(status, body)
    monkeypatch.setattr(probes_mod.urllib.request, "urlopen", fake_urlopen)


def _mock_urlopen_raises(monkeypatch, exc):
    def fake_urlopen(req, timeout=None):
        raise exc
    monkeypatch.setattr(probes_mod.urllib.request, "urlopen", fake_urlopen)


class TestHttpGetJson:
    def test_returns_parsed_payload(self, monkeypatch):
        _mock_urlopen(monkeypatch, 200, b'{"a": 1}')
        out = probes_mod.http_get_json("https://x.example/api")
        assert out == {"a": 1}

    def test_basic_auth_header_set(self, monkeypatch):
        captured = {}

        def fake_urlopen(req, timeout=None):
            captured["headers"] = dict(req.headers)
            return _FakeResp(200, b'{}')

        monkeypatch.setattr(probes_mod.urllib.request, "urlopen", fake_urlopen)
        probes_mod.http_get_json("https://x.example/api", auth=("user", "tok"))
        # urllib lowercases header names in `req.headers`.
        assert captured["headers"]["Authorization"].startswith("Basic ")

    def test_oversize_response_rejected(self, monkeypatch):
        big = b"x" * (probes_mod.MAX_RESPONSE_BYTES + 10)
        _mock_urlopen(monkeypatch, 200, big)
        with pytest.raises(ProbeError, match="exceeded"):
            probes_mod.http_get_json("https://x.example/api")

    def test_non_200_raises(self, monkeypatch):
        _mock_urlopen(monkeypatch, 500, b'{}')
        with pytest.raises(ProbeError, match="HTTP 500"):
            probes_mod.http_get_json("https://x.example/api")

    def test_non_json_body_raises(self, monkeypatch):
        _mock_urlopen(monkeypatch, 200, b'<html>not json</html>')
        with pytest.raises(ProbeError, match="not valid JSON"):
            probes_mod.http_get_json("https://x.example/api")

    def test_401_message_mentions_credentials(self, monkeypatch):
        import urllib.error
        _mock_urlopen_raises(monkeypatch, urllib.error.HTTPError(
            url="x", code=401, msg="Unauthorized", hdrs=None, fp=None,
        ))
        with pytest.raises(ProbeError, match="credentials"):
            probes_mod.http_get_json("https://x.example/api")


# ---------------------------------------------------------------------------
# Per-probe tests
# ---------------------------------------------------------------------------

ENV_JENKINS = {
    "CIGUARD_JENKINS_URL":   "https://jenkins.example",
    "CIGUARD_JENKINS_USER":  "admin",
    "CIGUARD_JENKINS_TOKEN": "tok",
}

ENV_GITLAB = {
    "CIGUARD_GITLAB_URL":   "https://gitlab.example",
    "CIGUARD_GITLAB_TOKEN": "glpat-xxx",
}

ENV_GHE = {
    "CIGUARD_GHE_URL":   "https://ghe.example",
    "CIGUARD_GHE_TOKEN": "ghp_xxx",
}


class TestJenkinsProbe:
    def test_happy_path(self, monkeypatch):
        _mock_urlopen(monkeypatch, 200, b'{"version": "2.426.3"}')
        entry = JenkinsProbe().probe(ENV_JENKINS)
        assert entry.tool == "jenkins"
        assert entry.version == "2.426.3"
        assert entry.configured is True
        assert entry.error is None

    def test_missing_version_field_errors_clearly(self, monkeypatch):
        _mock_urlopen(monkeypatch, 200, b'{"useCrumbs": true}')
        with pytest.raises(ProbeError, match="no `version` field"):
            JenkinsProbe().probe(ENV_JENKINS)

    def test_strips_trailing_slash_from_base_url(self, monkeypatch):
        captured = {}

        def fake_urlopen(req, timeout=None):
            captured["url"] = req.full_url
            return _FakeResp(200, b'{"version": "2.500"}')

        monkeypatch.setattr(probes_mod.urllib.request, "urlopen", fake_urlopen)
        env = dict(ENV_JENKINS, CIGUARD_JENKINS_URL="https://jenkins.example/")
        JenkinsProbe().probe(env)
        assert captured["url"] == "https://jenkins.example/api/json"


class TestGitLabProbe:
    def test_happy_path_ce(self, monkeypatch):
        _mock_urlopen(monkeypatch, 200,
                      b'{"version": "16.5.0", "enterprise": false}')
        entry = GitLabSelfHostProbe().probe(ENV_GITLAB)
        assert entry.version == "16.5.0"
        assert entry.edition == "CE"

    def test_happy_path_ee(self, monkeypatch):
        _mock_urlopen(monkeypatch, 200,
                      b'{"version": "16.5.0-ee", "enterprise": true}')
        entry = GitLabSelfHostProbe().probe(ENV_GITLAB)
        assert entry.edition == "EE"

    def test_uses_private_token_header(self, monkeypatch):
        captured = {}

        def fake_urlopen(req, timeout=None):
            captured["headers"] = dict(req.headers)
            return _FakeResp(200, b'{"version": "16.5.0", "enterprise": true}')

        monkeypatch.setattr(probes_mod.urllib.request, "urlopen", fake_urlopen)
        GitLabSelfHostProbe().probe(ENV_GITLAB)
        # urllib normalises header names to title-case in `req.headers`.
        assert captured["headers"].get("Private-token") == "glpat-xxx"


class TestGheProbe:
    def test_happy_path(self, monkeypatch):
        _mock_urlopen(monkeypatch, 200, b'{"installed_version": "3.12.0"}')
        entry = GitHubEnterpriseProbe().probe(ENV_GHE)
        assert entry.version == "3.12.0"
        assert entry.tool == "github-enterprise"

    def test_github_dot_com_clear_error(self, monkeypatch):
        # github.com returns a different shape with no installed_version.
        _mock_urlopen(monkeypatch, 200, b'{"verifiable_password_authentication": false}')
        with pytest.raises(ProbeError, match="installed_version"):
            GitHubEnterpriseProbe().probe(ENV_GHE)


# ---------------------------------------------------------------------------
# EOL enrichment
# ---------------------------------------------------------------------------

class _StubEol:
    """Drop-in replacement for `EndOfLifeClient` used by the runner — lets
    tests pre-seed cycle data without touching disk or network."""

    def __init__(self, by_product: dict):
        self._by_product = by_product

    def cycles_for_product(self, product: str):
        return self._by_product.get(product)


class TestEnrichWithEol:
    def test_attaches_eol_for_matching_cycle(self):
        entry = InventoryEntry(
            tool="jenkins", configured=True, version="2.426",
            raw={"_endoflife_product": "jenkins"},
        )
        client = _StubEol({"jenkins": [
            {"cycle": "2.426", "eol": "2026-12-31", "support": "2026-06-30"},
        ]})
        probes_mod.enrich_with_eol(
            entry, client,
            today=datetime(2026, 5, 2, tzinfo=timezone.utc),
        )
        assert entry.eol_date == "2026-12-31"
        assert entry.days_until_eol is not None and entry.days_until_eol > 0
        assert entry.eos_date == "2026-06-30"

    def test_falls_back_to_major_minor_when_patch_missing(self):
        entry = InventoryEntry(
            tool="jenkins", configured=True, version="2.426.3",
            raw={"_endoflife_product": "jenkins"},
        )
        client = _StubEol({"jenkins": [
            {"cycle": "2.426", "eol": "2026-12-31"},
        ]})
        probes_mod.enrich_with_eol(entry, client,
                                   today=datetime(2026, 5, 2, tzinfo=timezone.utc))
        assert entry.eol_date == "2026-12-31"

    def test_silent_skip_when_no_product_slug(self):
        entry = InventoryEntry(tool="custom", configured=True, version="1.0",
                               raw={"_endoflife_product": None})
        probes_mod.enrich_with_eol(
            entry, _StubEol({}),
            today=datetime(2026, 5, 2, tzinfo=timezone.utc),
        )
        assert entry.eol_date is None

    def test_silent_skip_on_error_entry(self):
        entry = InventoryEntry(tool="jenkins", configured=True, error="x",
                               raw={"_endoflife_product": "jenkins"})
        client = _StubEol({"jenkins": [{"cycle": "2.426", "eol": "2024-01-01"}]})
        probes_mod.enrich_with_eol(entry, client)
        assert entry.eol_date is None


# ---------------------------------------------------------------------------
# Runner orchestration
# ---------------------------------------------------------------------------

class TestInventoryRunner:
    def test_unconfigured_probes_silently_skipped(self, tmp_path):
        runner = InventoryRunner(env={}, eol_cache_dir=tmp_path, eol_offline=True)
        report = runner.run()
        # Three probes registered; all should appear with configured=False.
        assert len(report.entries) == len(ALL_PROBES)
        assert all(e.configured is False for e in report.entries)

    def test_partial_configuration_only_runs_configured(self, tmp_path, monkeypatch):
        _mock_urlopen(monkeypatch, 200, b'{"version": "2.500"}')
        runner = InventoryRunner(
            env=ENV_JENKINS,
            eol_cache_dir=tmp_path,
            eol_offline=True,
        )
        report = runner.run()
        configured = [e for e in report.entries if e.configured]
        assert len(configured) == 1
        assert configured[0].tool == "jenkins"
        assert configured[0].version == "2.500"

    def test_probe_error_lands_in_entry_not_a_crash(self, tmp_path, monkeypatch):
        _mock_urlopen(monkeypatch, 401, b'{}')
        runner = InventoryRunner(
            env=ENV_JENKINS,
            eol_cache_dir=tmp_path,
            eol_offline=True,
        )
        report = runner.run()
        jenkins = next(e for e in report.entries if e.tool == "jenkins")
        assert jenkins.configured is True
        assert jenkins.error is not None
        assert jenkins.version is None

    def test_eol_enrichment_runs_when_cache_seeded(self, tmp_path, monkeypatch):
        _mock_urlopen(monkeypatch, 200, b'{"version": "2.426"}')
        # Pre-seed the on-disk endoflife cache so offline-mode finds it.
        cache = tmp_path
        cache.mkdir(parents=True, exist_ok=True)
        (cache / "endoflife-jenkins.json").write_text(
            json.dumps([{"cycle": "2.426", "eol": "2026-12-31"}])
        )
        runner = InventoryRunner(
            env=ENV_JENKINS,
            eol_cache_dir=cache,
            eol_offline=True,
        )
        report = runner.run()
        jenkins = next(e for e in report.entries if e.tool == "jenkins")
        assert jenkins.eol_date == "2026-12-31"


# ---------------------------------------------------------------------------
# Probe registry — guards against silent registration drift
# ---------------------------------------------------------------------------

class TestProbeRegistry:
    def test_three_priority_probes_registered(self):
        names = {p.tool for p in ALL_PROBES}
        assert {"jenkins", "gitlab-self-host", "github-enterprise"} <= names

    def test_each_probe_declares_required_env(self):
        for p in ALL_PROBES:
            assert p.required_env, f"{p.tool} missing required_env declaration"
            assert all(k.startswith("CIGUARD_") for k in p.required_env), \
                f"{p.tool} env vars must follow CIGUARD_<TOOL>_* convention"

    def test_each_probe_has_endoflife_product_or_explicit_none(self):
        for p in ALL_PROBES:
            # Attribute must exist even when None — runner reads it.
            assert hasattr(p, "endoflife_product")

    def test_all_eight_probes_registered(self):
        names = {p.tool for p in ALL_PROBES}
        expected = {
            "jenkins", "gitlab-self-host", "github-enterprise",
            "nexus", "artifactory", "sonarqube", "argocd", "harbor",
        }
        assert names == expected, f"missing or extra probes: {names ^ expected}"


# ---------------------------------------------------------------------------
# Per-probe tests — Slice 14b session 2 (5 incremental probes)
# ---------------------------------------------------------------------------

ENV_NEXUS = {
    "CIGUARD_NEXUS_URL":      "https://nexus.example",
    "CIGUARD_NEXUS_USER":     "audit",
    "CIGUARD_NEXUS_PASSWORD": "pw",
}

ENV_ARTIFACTORY_TOKEN = {
    "CIGUARD_ARTIFACTORY_URL":   "https://artifactory.example",
    "CIGUARD_ARTIFACTORY_TOKEN": "tok",
}

ENV_ARTIFACTORY_BASIC = {
    "CIGUARD_ARTIFACTORY_URL":      "https://artifactory.example",
    "CIGUARD_ARTIFACTORY_USER":     "admin",
    "CIGUARD_ARTIFACTORY_PASSWORD": "pw",
}

ENV_SONAR = {
    "CIGUARD_SONAR_URL":   "https://sonar.example",
    "CIGUARD_SONAR_TOKEN": "sqp_xxx",
}

ENV_ARGOCD = {
    "CIGUARD_ARGOCD_URL":   "https://argocd.example",
    "CIGUARD_ARGOCD_TOKEN": "ey...",
}

ENV_HARBOR = {
    "CIGUARD_HARBOR_URL":      "https://harbor.example",
    "CIGUARD_HARBOR_USER":     "robot$audit",
    "CIGUARD_HARBOR_PASSWORD": "pw",
}


class TestNexusProbe:
    def test_happy_path_via_system_info(self, monkeypatch):
        _mock_urlopen(monkeypatch, 200,
                      b'{"version": "3.66.0", "edition": "PRO"}')
        entry = NexusProbe().probe(ENV_NEXUS)
        assert entry.version == "3.66.0"
        assert entry.edition == "PRO"
        assert entry.tool == "nexus"

    def test_falls_back_to_status_check_on_403(self, monkeypatch):
        # First call returns 403 (no system-info-read), second returns the
        # status/check payload with version nested inside `node.api`.
        calls = {"n": 0}

        def fake_urlopen(req, timeout=None):
            calls["n"] += 1
            if calls["n"] == 1:
                import urllib.error
                raise urllib.error.HTTPError(
                    url="x", code=403, msg="Forbidden", hdrs=None, fp=None,
                )
            return _FakeResp(200, b'{"node": {"api": {"nexus_version": "3.42.0"}}}')

        monkeypatch.setattr(probes_mod.urllib.request, "urlopen", fake_urlopen)
        entry = NexusProbe().probe(ENV_NEXUS)
        assert entry.version == "3.42.0"

    def test_unrecognised_response_errors_clearly(self, monkeypatch):
        _mock_urlopen(monkeypatch, 200, b'{"unknown_field": true}')
        with pytest.raises(ProbeError, match="recognisable version"):
            NexusProbe().probe(ENV_NEXUS)


class TestArtifactoryProbe:
    def test_happy_path_token(self, monkeypatch):
        captured = {}

        def fake_urlopen(req, timeout=None):
            captured["url"] = req.full_url
            captured["headers"] = dict(req.headers)
            return _FakeResp(200,
                             b'{"version": "7.77.3", "license": "Enterprise"}')

        monkeypatch.setattr(probes_mod.urllib.request, "urlopen", fake_urlopen)
        entry = ArtifactoryProbe().probe(ENV_ARTIFACTORY_TOKEN)
        assert entry.version == "7.77.3"
        assert entry.edition == "Enterprise"
        # Default URL should pick up the `/artifactory/` prefix.
        assert "/artifactory/api/system/version" in captured["url"]
        assert captured["headers"]["Authorization"] == "Bearer tok"

    def test_basic_auth_path(self, monkeypatch):
        _mock_urlopen(monkeypatch, 200, b'{"version": "6.23.21", "license": "Pro"}')
        entry = ArtifactoryProbe().probe(ENV_ARTIFACTORY_BASIC)
        assert entry.version == "6.23.21"

    def test_missing_auth_errors(self):
        env = {"CIGUARD_ARTIFACTORY_URL": "https://x.example"}
        with pytest.raises(ProbeError, match="ARTIFACTORY_TOKEN"):
            ArtifactoryProbe().probe(env)

    def test_pre_prefixed_url_not_doubled(self, monkeypatch):
        captured = {}

        def fake_urlopen(req, timeout=None):
            captured["url"] = req.full_url
            return _FakeResp(200, b'{"version": "7.0.0", "license": "OSS"}')

        monkeypatch.setattr(probes_mod.urllib.request, "urlopen", fake_urlopen)
        env = dict(ENV_ARTIFACTORY_TOKEN,
                   CIGUARD_ARTIFACTORY_URL="https://x.example/artifactory")
        ArtifactoryProbe().probe(env)
        assert captured["url"] == "https://x.example/artifactory/api/system/version"
        assert captured["url"].count("/artifactory/") == 1


class TestSonarQubeProbe:
    def test_happy_path(self, monkeypatch):
        # SonarQube returns plain text — our probe reads it directly without
        # going through http_get_json. Patch the urlopen on the sonarqube
        # module's namespace, which imports `urllib.request` at module top.
        def fake_urlopen(req, timeout=None):
            return _FakeResp(200, b"10.4.1.88267")

        monkeypatch.setattr(sonarqube_mod.urllib.request, "urlopen", fake_urlopen)
        entry = SonarQubeProbe().probe(ENV_SONAR)
        assert entry.version == "10.4.1.88267"
        assert entry.tool == "sonarqube"

    def test_401_message_mentions_token(self, monkeypatch):
        import urllib.error

        def fake_urlopen(req, timeout=None):
            raise urllib.error.HTTPError(
                url="x", code=401, msg="Unauthorized", hdrs=None, fp=None,
            )

        monkeypatch.setattr(sonarqube_mod.urllib.request, "urlopen", fake_urlopen)
        with pytest.raises(ProbeError, match="user token"):
            SonarQubeProbe().probe(ENV_SONAR)

    def test_empty_body_errors(self, monkeypatch):
        def fake_urlopen(req, timeout=None):
            return _FakeResp(200, b"")

        monkeypatch.setattr(sonarqube_mod.urllib.request, "urlopen", fake_urlopen)
        with pytest.raises(ProbeError, match="empty body"):
            SonarQubeProbe().probe(ENV_SONAR)


class TestArgoCDProbe:
    def test_happy_path_capital_v(self, monkeypatch):
        _mock_urlopen(monkeypatch, 200, b'{"Version": "v2.10.4+abc1234"}')
        entry = ArgoCDProbe().probe(ENV_ARGOCD)
        # Leading `v` stripped to match endoflife `cycle` format.
        assert entry.version == "2.10.4+abc1234"

    def test_happy_path_lowercase(self, monkeypatch):
        _mock_urlopen(monkeypatch, 200, b'{"version": "2.11.0"}')
        entry = ArgoCDProbe().probe(ENV_ARGOCD)
        assert entry.version == "2.11.0"

    def test_missing_version_errors(self, monkeypatch):
        _mock_urlopen(monkeypatch, 200, b'{"BuildDate": "2026-01-01"}')
        with pytest.raises(ProbeError, match="no `Version`"):
            ArgoCDProbe().probe(ENV_ARGOCD)


class TestHarborProbe:
    def test_happy_path(self, monkeypatch):
        _mock_urlopen(monkeypatch, 200,
                      b'{"harbor_version": "v2.10.1-abc1234"}')
        entry = HarborProbe().probe(ENV_HARBOR)
        # Strips both `v` prefix and `-abc1234` build hash.
        assert entry.version == "2.10.1"

    def test_missing_version_errors(self, monkeypatch):
        _mock_urlopen(monkeypatch, 200, b'{"auth_mode": "db_auth"}')
        with pytest.raises(ProbeError, match="harbor_version"):
            HarborProbe().probe(ENV_HARBOR)

    def test_passes_basic_auth(self, monkeypatch):
        captured = {}

        def fake_urlopen(req, timeout=None):
            captured["headers"] = dict(req.headers)
            return _FakeResp(200, b'{"harbor_version": "v2.10.0"}')

        monkeypatch.setattr(probes_mod.urllib.request, "urlopen", fake_urlopen)
        HarborProbe().probe(ENV_HARBOR)
        assert captured["headers"]["Authorization"].startswith("Basic ")
