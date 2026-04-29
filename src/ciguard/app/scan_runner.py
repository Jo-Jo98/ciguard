"""Scan-orchestration layer for the ciguard GitHub App.

Threat model: `Project ciguard/THREAT_MODEL.md` Surface 9. This module
closes the "Check Run state confusion" row by being the SINGLE place
that holds the create → execute → finalize lifecycle. Every exception
the executor can raise is caught and routed through
`checks.set_check_run_failed()` so a Check Run started here never
remains in `in_progress` after a crash.

The scan executor itself is injected (`ScanExecutor` Protocol) — the
orchestration is what we test here; the actual work of cloning the
repo + running `ciguard scan-repo` against the head SHA lands in
step (vi) when the App is wired together. This separation keeps the
exception-routing logic testable without mocking a real scan.
"""
from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable

from . import checks
from .scheduler import ScanJob

logger = logging.getLogger("ciguard.app.scan_runner")

# A scan executor takes a ScanJob and returns the scan result dict
# `render_pr_comment_body()` understands. Step (vi) wires the real one;
# tests inject stubs.
ScanExecutor = Callable[[ScanJob], Awaitable[dict[str, Any]]]


def _split_repo(repo_full_name: str) -> tuple[str, str]:
    """`owner/repo` → `(owner, repo)`. Raises ValueError on malformed input."""
    if "/" not in repo_full_name:
        raise ValueError(
            f"repo_full_name must be `owner/repo`, got {repo_full_name!r}"
        )
    owner, _, repo = repo_full_name.partition("/")
    if not owner or not repo or "/" in repo:
        raise ValueError(
            f"repo_full_name must be `owner/repo`, got {repo_full_name!r}"
        )
    return owner, repo


async def run_scan(job: ScanJob, executor: ScanExecutor) -> None:
    """Orchestrate one scan: create Check Run → execute → finalize.

    The flow:
      1. Create the Check Run in `in_progress` (via App credentials).
      2. Run the executor — it returns a scan-result dict.
      3. On success: post / update the PR comment + complete the
         Check Run with conclusion derived from findings severity.
      4. On any exception in steps 2 or 3: set the Check Run to
         `failure` with a sanitised message; never leave it
         `in_progress`.

    Exceptions are NOT re-raised — the scheduler's worker loop
    already handles last-line-of-defence logging. Re-raising would
    just make every failure also crash the Check Run finaliser.
    """
    try:
        owner, repo = _split_repo(job.repo_full_name)
    except ValueError:
        logger.exception(
            "invalid repo_full_name on job (installation=%d) — skipping",
            job.installation_id,
        )
        return

    check_run_id: int | None = None
    try:
        check_run_id = checks.create_check_run(
            installation_id=job.installation_id,
            owner=owner, repo=repo, head_sha=job.head_sha,
        )
    except Exception:  # noqa: BLE001
        logger.exception(
            "failed to create Check Run (installation=%d repo=%s/%s head=%s)",
            job.installation_id, owner, repo, job.head_sha[:7],
        )
        return  # without a check-run id we can't finalize anything

    try:
        result = await executor(job)
        await _finalize_success(
            job=job, owner=owner, repo=repo,
            check_run_id=check_run_id, result=result,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception(
            "scan executor raised — routing Check Run %d to failure",
            check_run_id,
        )
        checks.set_check_run_failed(
            installation_id=job.installation_id,
            owner=owner, repo=repo, check_run_id=check_run_id,
            message=str(exc),
        )


async def _finalize_success(
    *, job: ScanJob, owner: str, repo: str, check_run_id: int,
    result: dict[str, Any],
) -> None:
    findings = list(result.get("findings", []) or [])
    conclusion = checks.conclusion_for_findings(findings)
    summary = _summary_line(result, findings)

    # Post / update the PR comment FIRST so the user sees results inline
    # before the Check Run badge flips. If the comment post fails, we
    # still want the Check Run to land in a final state — fall through
    # to complete_check_run() so the gate isn't left in_progress on a
    # transient comment-API failure.
    if job.pr_number is not None:
        try:
            body = checks.render_pr_comment_body(result)
            checks.post_or_update_pr_comment(
                installation_id=job.installation_id,
                owner=owner, repo=repo,
                pr_number=job.pr_number, body=body,
            )
        except Exception:  # noqa: BLE001
            logger.exception(
                "PR comment post/update failed (pr=#%d); continuing to "
                "finalize Check Run", job.pr_number,
            )

    checks.complete_check_run(
        installation_id=job.installation_id,
        owner=owner, repo=repo, check_run_id=check_run_id,
        conclusion=conclusion, summary=summary,
    )


def _summary_line(
    result: dict[str, Any], findings: list[dict[str, Any]]
) -> str:
    """Short markdown summary for the Check Run output. Goes through the
    same inline sanitiser as PR comment fields."""
    score = result.get("risk_score", "—")
    grade = checks._safe_md_inline(str(result.get("grade", "?")), max_len=4)
    if not findings:
        return f"**No findings.** Risk score {score} ({grade})."
    counts: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", "Info"))
        counts[sev] = counts.get(sev, 0) + 1
    sev_order = ["Critical", "High", "Medium", "Low", "Info"]
    parts = [f"{counts[s]} {s}" for s in sev_order if counts.get(s, 0) > 0]
    return (
        f"**{len(findings)} findings:** {', '.join(parts)}. "
        f"Risk score {score} ({grade})."
    )
