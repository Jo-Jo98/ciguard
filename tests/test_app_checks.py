"""Tests for the v0.10.0 GitHub App Check Run + PR comment layer.

Covers Surface 9 STRIDE rows that THIS module closes:
  - PR comment markdown injection (High, DREAD 18) — every
    user-controlled string in a PR comment goes through a sanitiser.
  - Check Run state confusion (Medium, DREAD 16) — see
    `test_app_scan_runner.py` for the full lifecycle test; this file
    exercises the Check Run primitives in isolation.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock
from urllib.error import HTTPError

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.app import checks  # noqa: E402


# ===========================================================================
# Markdown sanitisation
# ===========================================================================


class TestSafeMdInline:
    def test_none_yields_placeholder_not_crash(self) -> None:
        assert checks._safe_md_inline(None) == "_(none)_"

    def test_empty_string_passes_through(self) -> None:
        assert checks._safe_md_inline("") == ""

    def test_markdown_link_is_escaped(self) -> None:
        out = checks._safe_md_inline("[click](javascript:alert(1))")
        # The bracket / paren must be escaped so the link doesn't render.
        assert "\\[click\\]" in out
        assert "\\(javascript:alert\\(1\\)\\)" in out
        # And the result must NOT contain an unescaped `](` linker.
        assert "](" not in out

    def test_html_tags_are_encoded(self) -> None:
        out = checks._safe_md_inline("<img src=x onerror=alert(1)>")
        assert "&lt;img" in out
        assert "<img" not in out

    def test_ampersand_encoded_before_angle_brackets(self) -> None:
        # `&lt;` must NOT become `&amp;lt;` — the order matters.
        out = checks._safe_md_inline("a & <b>")
        assert "&amp; " in out
        assert "&lt;b&gt;" in out

    def test_crlf_stripped(self) -> None:
        out = checks._safe_md_inline("line1\r\nERROR: forged\nline3")
        assert "\r" not in out
        assert "\n" not in out

    def test_length_capped(self) -> None:
        out = checks._safe_md_inline("x" * 500, max_len=100)
        assert len(out) <= 102  # 100 + the `…` ellipsis
        assert out.endswith("…")


class TestSafeMdBlock:
    def test_none_yields_empty_fence(self) -> None:
        assert checks._safe_md_block(None).startswith("````")

    def test_evidence_wrapped_in_4_backtick_fence(self) -> None:
        out = checks._safe_md_block("hello: world")
        assert out.startswith("````\n")
        assert out.endswith("\n````")

    def test_three_backtick_break_out_does_not_terminate_fence(self) -> None:
        """Standard 3-backtick fences are vulnerable to nested 3-backticks.
        Our 4-backtick fence stays intact."""
        evil = "```\nFAKE: rendered as separate code block\n```"
        out = checks._safe_md_block(evil)
        # Output structure: open-fence, content (which may contain ```),
        # close-fence. The CLOSE fence must still be `````` not get
        # confused by the inner triple-backticks.
        assert out.startswith("````")
        assert out.endswith("````")
        assert out.count("````") == 2  # exactly the open + close

    def test_four_backtick_runs_in_evidence_are_neutralised(self) -> None:
        """4-or-more backticks could escape our 4-backtick fence;
        replace those runs with `~` of the same length."""
        evil = "```` ESCAPED FENCE BREAK"
        out = checks._safe_md_block(evil)
        # The 4-run got replaced with `~~~~` — fence now has exactly
        # 2 occurrences of ```` (open + close).
        assert out.count("````") == 2
        assert "~~~~" in out

    def test_five_backtick_runs_handled_too(self) -> None:
        evil = "````` more"
        out = checks._safe_md_block(evil)
        assert out.count("````") == 2
        assert "~~~~~" in out

    def test_length_capped_with_truncated_marker(self) -> None:
        out = checks._safe_md_block("x" * 500, max_len=100)
        assert "(truncated)" in out


# ===========================================================================
# PR comment body rendering
# ===========================================================================


class TestRenderPrCommentBody:
    def test_empty_findings_says_so(self) -> None:
        body = checks.render_pr_comment_body({
            "risk_score": 100, "grade": "A", "findings": [],
        })
        assert "No findings" in body
        assert checks.PR_COMMENT_MARKER in body

    def test_marker_always_first_line(self) -> None:
        """Upsert relies on finding the marker — keep it stable."""
        body = checks.render_pr_comment_body({
            "risk_score": 80, "grade": "B", "findings": [],
        })
        assert body.startswith(checks.PR_COMMENT_MARKER)

    def test_finding_evidence_with_link_attempt_is_neutralised(self) -> None:
        body = checks.render_pr_comment_body({
            "risk_score": 60, "grade": "C",
            "findings": [{
                "rule_id": "GHA-IAM-005", "severity": "High",
                "message": "Workflow has no permissions block",
                "location": "[click](javascript:alert(1)):42",
                "evidence": "[evil](javascript:alert(1))",
            }],
        })
        # The link attempt in `location` must be backslash-escaped so it
        # doesn't render as a clickable link.
        assert "[click](javascript" not in body
        # The evidence link is wrapped in a fence — the literal text
        # appears, but as code, not as a clickable link.
        assert "````" in body

    def test_finding_with_html_tags_is_encoded(self) -> None:
        body = checks.render_pr_comment_body({
            "risk_score": 60, "grade": "C",
            "findings": [{
                "rule_id": "GHA-RUN-001", "severity": "Medium",
                "message": "<img src=x onerror=alert(1)> see job",
                "location": "ci.yml:10",
                "evidence": "run: echo hi",
            }],
        })
        assert "<img" not in body  # raw HTML never lands in the body
        assert "&lt;img" in body

    def test_long_findings_list_is_capped_and_overflow_noted(self) -> None:
        body = checks.render_pr_comment_body({
            "risk_score": 0, "grade": "F",
            "findings": [
                {"rule_id": f"X-{i:03d}", "severity": "High",
                 "message": "m", "location": "a:1", "evidence": "x"}
                for i in range(40)
            ],
        })
        assert "and 15 more" in body  # 40 - 25 = 15

    def test_severity_summary_lists_only_present_severities(self) -> None:
        body = checks.render_pr_comment_body({
            "risk_score": 50, "grade": "C",
            "findings": [
                {"severity": "High", "rule_id": "a", "message": "",
                 "location": "", "evidence": ""},
                {"severity": "High", "rule_id": "b", "message": "",
                 "location": "", "evidence": ""},
                {"severity": "Low", "rule_id": "c", "message": "",
                 "location": "", "evidence": ""},
            ],
        })
        assert "2 High" in body
        assert "1 Low" in body
        assert "Critical" not in body
        assert "Medium" not in body


# ===========================================================================
# Conclusion mapping
# ===========================================================================


@pytest.mark.parametrize(
    "findings,expected",
    [
        ([], "success"),
        ([{"severity": "Info"}], "success"),
        ([{"severity": "Low"}], "neutral"),
        ([{"severity": "Medium"}], "neutral"),
        ([{"severity": "High"}], "failure"),
        ([{"severity": "Critical"}], "failure"),
        ([{"severity": "Low"}, {"severity": "High"}], "failure"),
        ([{"severity": "Medium"}, {"severity": "Info"}], "neutral"),
    ],
)
def test_conclusion_for_findings(
    findings: list[dict], expected: str
) -> None:
    assert checks.conclusion_for_findings(findings) == expected


# ===========================================================================
# HTTP layer — mocked urllib.request.urlopen
# ===========================================================================


class _FakeResponse:
    """Drop-in replacement for the urlopen context-manager response."""

    def __init__(self, payload: bytes, status: int = 200) -> None:
        self._payload = payload
        self.status = status

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *args) -> None:
        return None

    def read(self, n: int = -1) -> bytes:
        return self._payload if n == -1 else self._payload[:n]


@pytest.fixture
def stub_token(monkeypatch: pytest.MonkeyPatch) -> str:
    """Stub `tokens.get_installation_token` so HTTP tests don't try to
    mint real JWTs."""
    fake = "ghs_stub_test_token"
    monkeypatch.setattr(
        checks.tokens, "get_installation_token", lambda inst_id: fake
    )
    return fake


def test_create_check_run_posts_in_progress_payload(
    stub_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict = {}

    def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        captured["body"] = req.data
        captured["auth"] = req.get_header("Authorization")
        return _FakeResponse(json.dumps({"id": 9876}).encode())

    monkeypatch.setattr(
        checks.urllib.request, "urlopen", fake_urlopen
    )
    cr_id = checks.create_check_run(
        installation_id=42, owner="o", repo="r", head_sha="cafef00d" * 5,
    )
    assert cr_id == 9876
    assert captured["method"] == "POST"
    assert captured["url"].endswith("/repos/o/r/check-runs")
    assert captured["auth"] == f"Bearer {stub_token}"
    body = json.loads(captured["body"])
    assert body["status"] == "in_progress"
    assert body["head_sha"] == "cafef00d" * 5


def test_complete_check_run_rejects_invalid_conclusion(
    stub_token: str
) -> None:
    with pytest.raises(ValueError, match="invalid Check Run conclusion"):
        checks.complete_check_run(
            installation_id=42, owner="o", repo="r", check_run_id=1,
            conclusion="rolled-eyes", summary="x",
        )


def test_401_invalidates_token_and_reraises(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """The contract every API caller honours — a 401 from GitHub purges
    the cached token so the NEXT webhook re-mints from a fresh JWT."""
    monkeypatch.setattr(
        checks.tokens, "get_installation_token", lambda inst_id: "ghs_x"
    )
    invalidate = MagicMock()
    monkeypatch.setattr(checks.tokens, "invalidate_token", invalidate)

    def boom(req, timeout):  # type: ignore[no-untyped-def]
        raise HTTPError(req.full_url, 401, "Unauthorized", {}, None)  # type: ignore[arg-type]

    monkeypatch.setattr(checks.urllib.request, "urlopen", boom)
    with pytest.raises(HTTPError):
        checks.create_check_run(
            installation_id=42, owner="o", repo="r", head_sha="abc",
        )
    invalidate.assert_called_once_with(42)


def test_post_or_update_finds_existing_comment_and_patches(
    stub_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Idempotency by hidden marker — second post UPDATES, doesn't stack."""
    calls: list[tuple[str, str]] = []

    def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
        method = req.get_method()
        url = req.full_url
        calls.append((method, url))
        if method == "GET":
            # Comments listing — return one comment with our marker
            existing_body = (
                f"{checks.PR_COMMENT_MARKER}\nsome older content"
            )
            return _FakeResponse(json.dumps([
                {"id": 999, "body": "unrelated comment"},
                {"id": 555, "body": existing_body},
            ]).encode())
        if method == "PATCH":
            return _FakeResponse(json.dumps({"id": 555}).encode())
        if method == "POST":
            return _FakeResponse(json.dumps({"id": 1234}).encode())
        raise AssertionError(f"unexpected method {method}")

    monkeypatch.setattr(checks.urllib.request, "urlopen", fake_urlopen)
    cid = checks.post_or_update_pr_comment(
        installation_id=42, owner="o", repo="r",
        pr_number=7, body=f"{checks.PR_COMMENT_MARKER}\nnew",
    )
    assert cid == 555  # the existing one
    methods = [m for m, _ in calls]
    assert "PATCH" in methods
    assert "POST" not in methods


def test_post_or_update_creates_when_none_existing(
    stub_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
        if req.get_method() == "GET":
            return _FakeResponse(json.dumps([]).encode())
        return _FakeResponse(json.dumps({"id": 1234}).encode())

    monkeypatch.setattr(checks.urllib.request, "urlopen", fake_urlopen)
    cid = checks.post_or_update_pr_comment(
        installation_id=42, owner="o", repo="r",
        pr_number=7, body=f"{checks.PR_COMMENT_MARKER}\nfirst",
    )
    assert cid == 1234


def test_set_check_run_failed_swallows_secondary_failure(
    stub_token: str, monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Last-line-of-defence: if the failure-completion call ALSO fails,
    we log + continue — never raise out of the death-handler."""

    def boom(req, timeout):  # type: ignore[no-untyped-def]
        raise HTTPError(req.full_url, 500, "boom", {}, None)  # type: ignore[arg-type]

    monkeypatch.setattr(checks.urllib.request, "urlopen", boom)

    # Must not raise.
    checks.set_check_run_failed(
        installation_id=42, owner="o", repo="r",
        check_run_id=999, message="primary scan failed",
    )
    # And must log.
    text = "\n".join(r.message for r in caplog.records)
    assert "ALSO failed" in text


# ===========================================================================
# Sanity check — coverage of every value-source in the comment body
# ===========================================================================


def test_render_with_attacker_evidence_does_not_break_out_of_fence() -> None:
    """End-to-end injection attempt: every string in the finding tries
    to break out of its sanitisation. The full rendered body must not
    contain a clickable injected link OR a runaway code block."""
    body = checks.render_pr_comment_body({
        "risk_score": 0, "grade": "F",
        "findings": [{
            "rule_id": "EVIL-001\n## Header injection",
            "severity": "High",
            "message": "[Approve as admin](mailto:admin@x.com)",
            "location": "../../etc/passwd:1",
            "evidence": (
                "before\n"
                "```` ESCAPE ATTEMPT\n"
                "[Approve](https://evil.example/click)\n"
                "after"
            ),
        }],
    })
    # No real markdown link in the rendered body.
    assert "[Approve as admin]" not in body
    # The evidence's 4-backtick attempt is neutralised so the fence
    # closes correctly — the document ends with a closing fence.
    open_fences = body.count("````")
    assert open_fences % 2 == 0, (
        "Unbalanced 4-backtick fences indicate evidence escaped its block"
    )
    # Header injection attempt becomes literal text, not a real heading.
    assert "## Header injection" not in body  # because `#` is escaped
