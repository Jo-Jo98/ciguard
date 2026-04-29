"""Tests for the v0.10.0 GitHub App scan-orchestration layer.

Closes Surface 9 STRIDE row "Check Run state confusion" (Medium, DREAD 16):
no code path that creates an `in_progress` Check Run may leave it in
`in_progress` after a crash, and a crash MUST NOT silently flip the
Check Run to `success`.

Strategy: stub the GitHub HTTP layer (we don't re-test the HTTP plumbing
that's already covered by test_app_checks.py), inject scan executors that
exercise every shape — clean, blocking, neutral, executor-raises,
post-comment-raises, complete-check-run-raises — and assert the recorded
calls land the Check Run in the right terminal state.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.app import scan_runner  # noqa: E402
from ciguard.app.scheduler import ScanJob  # noqa: E402


def _job(
    *, repo: str = "owner/repo", pr: int | None = 7,
    head: str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
) -> ScanJob:
    return ScanJob(
        installation_id=42, repo_full_name=repo,
        head_sha=head, pr_number=pr, event="pull_request",
    )


@pytest.fixture
def stub_checks(monkeypatch: pytest.MonkeyPatch) -> dict[str, MagicMock]:
    """Replace the entire checks module surface with MagicMocks so we can
    assert call shape without touching urllib or tokens."""
    create = MagicMock(return_value=12345)
    complete = MagicMock(return_value=None)
    set_failed = MagicMock(return_value=None)
    post_comment = MagicMock(return_value=99999)
    monkeypatch.setattr(scan_runner.checks, "create_check_run", create)
    monkeypatch.setattr(scan_runner.checks, "complete_check_run", complete)
    monkeypatch.setattr(scan_runner.checks, "set_check_run_failed", set_failed)
    monkeypatch.setattr(
        scan_runner.checks, "post_or_update_pr_comment", post_comment
    )
    return {
        "create_check_run": create,
        "complete_check_run": complete,
        "set_check_run_failed": set_failed,
        "post_or_update_pr_comment": post_comment,
    }


def _run(coro):
    return asyncio.run(coro)


# ---- Happy path -------------------------------------------------------------


def test_clean_scan_finalizes_success(stub_checks: dict) -> None:
    async def executor(job: ScanJob) -> dict[str, Any]:
        return {"risk_score": 100, "grade": "A", "findings": []}

    _run(scan_runner.run_scan(_job(), executor))

    stub_checks["create_check_run"].assert_called_once()
    stub_checks["complete_check_run"].assert_called_once()
    kwargs = stub_checks["complete_check_run"].call_args.kwargs
    assert kwargs["conclusion"] == "success"
    assert kwargs["check_run_id"] == 12345
    stub_checks["set_check_run_failed"].assert_not_called()


def test_high_severity_finding_finalizes_failure(
    stub_checks: dict
) -> None:
    async def executor(job: ScanJob) -> dict[str, Any]:
        return {
            "risk_score": 60, "grade": "C",
            "findings": [{"severity": "High", "rule_id": "X-1",
                          "message": "m", "location": "a:1",
                          "evidence": "x"}],
        }

    _run(scan_runner.run_scan(_job(), executor))

    kwargs = stub_checks["complete_check_run"].call_args.kwargs
    assert kwargs["conclusion"] == "failure"
    stub_checks["set_check_run_failed"].assert_not_called()


def test_only_low_findings_finalizes_neutral(stub_checks: dict) -> None:
    async def executor(job: ScanJob) -> dict[str, Any]:
        return {
            "risk_score": 85, "grade": "B",
            "findings": [{"severity": "Low", "rule_id": "X-1",
                          "message": "m", "location": "a:1",
                          "evidence": "x"}],
        }

    _run(scan_runner.run_scan(_job(), executor))
    kwargs = stub_checks["complete_check_run"].call_args.kwargs
    assert kwargs["conclusion"] == "neutral"


# ---- THREAT: Check Run state confusion --------------------------------------


def test_executor_exception_routes_to_failure_not_in_progress(
    stub_checks: dict
) -> None:
    """The headline test for the STRIDE row. An exception in the scan
    executor MUST land the Check Run in `failure`. It MUST NOT remain
    `in_progress` and MUST NOT silently flip to `success`."""
    async def executor(job: ScanJob) -> dict[str, Any]:
        raise RuntimeError("ciguard parser crashed on malformed YAML")

    _run(scan_runner.run_scan(_job(), executor))

    # Check Run was created.
    stub_checks["create_check_run"].assert_called_once()
    # The success path must NOT have run.
    stub_checks["complete_check_run"].assert_not_called()
    # The failure path MUST have run, with our error message.
    stub_checks["set_check_run_failed"].assert_called_once()
    msg = stub_checks["set_check_run_failed"].call_args.kwargs["message"]
    assert "parser crashed" in msg


def test_create_check_run_failure_returns_quietly(
    stub_checks: dict
) -> None:
    """If we can't even create the Check Run, abort the scan; no
    set_check_run_failed call to make (no id to flip)."""
    stub_checks["create_check_run"].side_effect = RuntimeError("github 502")

    async def executor(job: ScanJob) -> dict[str, Any]:
        return {"risk_score": 100, "grade": "A", "findings": []}

    _run(scan_runner.run_scan(_job(), executor))

    stub_checks["complete_check_run"].assert_not_called()
    stub_checks["set_check_run_failed"].assert_not_called()


def test_pr_comment_failure_does_not_block_check_run_completion(
    stub_checks: dict
) -> None:
    """Transient comment-API failure must not leave the Check Run in
    `in_progress` — fall through to complete_check_run() so the gate
    still lands in a final state."""
    stub_checks["post_or_update_pr_comment"].side_effect = RuntimeError(
        "comments API 500"
    )

    async def executor(job: ScanJob) -> dict[str, Any]:
        return {
            "risk_score": 60, "grade": "C",
            "findings": [{"severity": "High", "rule_id": "X-1",
                          "message": "m", "location": "a:1",
                          "evidence": "x"}],
        }

    _run(scan_runner.run_scan(_job(), executor))
    stub_checks["complete_check_run"].assert_called_once()
    stub_checks["set_check_run_failed"].assert_not_called()


def test_complete_check_run_failure_routes_to_set_failed(
    stub_checks: dict
) -> None:
    """If complete_check_run itself raises (e.g. GitHub 502), the
    outer except clause catches it and routes through set_check_run_failed
    — defence in depth."""
    stub_checks["complete_check_run"].side_effect = RuntimeError(
        "github 502 on PATCH"
    )

    async def executor(job: ScanJob) -> dict[str, Any]:
        return {"risk_score": 100, "grade": "A", "findings": []}

    _run(scan_runner.run_scan(_job(), executor))

    stub_checks["set_check_run_failed"].assert_called_once()


# ---- PR comment posting -----------------------------------------------------


def test_pr_comment_posted_only_when_pr_number_present(
    stub_checks: dict
) -> None:
    """Push-without-PR shouldn't try to comment (no comments API target)."""
    async def executor(job: ScanJob) -> dict[str, Any]:
        return {"risk_score": 100, "grade": "A", "findings": []}

    _run(scan_runner.run_scan(_job(pr=None), executor))

    stub_checks["post_or_update_pr_comment"].assert_not_called()
    stub_checks["complete_check_run"].assert_called_once()


def test_pr_comment_posted_with_sanitised_body(
    stub_checks: dict
) -> None:
    """End-to-end: an attacker-controlled finding flows through to the
    PR comment body but is sanitised. Spot-check that the body the
    runner posts contains the marker (so upsert works) and doesn't
    contain raw HTML."""
    async def executor(job: ScanJob) -> dict[str, Any]:
        return {
            "risk_score": 60, "grade": "C",
            "findings": [{
                "severity": "High", "rule_id": "X-1",
                "message": "<img src=x>", "location": "a:1",
                "evidence": "evil",
            }],
        }

    _run(scan_runner.run_scan(_job(), executor))

    body = stub_checks["post_or_update_pr_comment"].call_args.kwargs["body"]
    assert "<!-- ciguard:pr-marker:v1 -->" in body
    assert "<img" not in body  # raw HTML stripped
    assert "&lt;img" in body


# ---- Edge cases -------------------------------------------------------------


def test_malformed_repo_full_name_skips_silently(
    stub_checks: dict
) -> None:
    """A malformed `owner/repo` value (validated server-side from
    webhook) shouldn't crash the worker — log + skip."""
    async def executor(job: ScanJob) -> dict[str, Any]:
        raise AssertionError("executor should not run on malformed repo")

    _run(scan_runner.run_scan(
        ScanJob(installation_id=42, repo_full_name="not-valid",
                head_sha="x" * 40, pr_number=None, event="push"),
        executor,
    ))
    stub_checks["create_check_run"].assert_not_called()
    stub_checks["complete_check_run"].assert_not_called()
    stub_checks["set_check_run_failed"].assert_not_called()
