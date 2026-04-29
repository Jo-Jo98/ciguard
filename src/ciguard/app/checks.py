"""GitHub Check Run + PR comment posting for the ciguard App.

Threat model: `Project ciguard/THREAT_MODEL.md` Surface 9. Closes:

  - "PR comment markdown injection" (High, DREAD 18) — every
    user-controlled string (rule evidence, location, finding message)
    that flows into a PR comment goes through `_safe_md_block()` /
    `_safe_md_inline()`. Evidence is wrapped in 4-backtick fences with
    backtick-run neutralisation; inline values are length-capped and
    have markdown special-chars + raw HTML escaped.

  - "Check Run state confusion" (Medium, DREAD 16) — every code path
    that reaches a Check Run with `status=in_progress` MUST conclude
    via `complete_check_run()` (success / neutral / failure) OR
    `set_check_run_failed()` (failure-with-message). The `_finalize_*`
    naming makes "did we finalize?" auditable in code review and via
    the test in test_app_scan_runner.py.

PR-comment idempotency: a hidden HTML marker `<!-- ciguard:pr-marker -->`
is embedded in every comment body. `post_or_update_pr_comment()` searches
for the marker and PATCHes the existing comment when present, POSTs a
fresh one otherwise. That collapses GitHub-retried + concurrent-event
deliveries to a single visible comment per PR (THREAT_MODEL row
"Concurrent webhook race").

GitHub API endpoints used:
  - POST /repos/{owner}/{repo}/check-runs               (create)
  - PATCH /repos/{owner}/{repo}/check-runs/{id}         (complete)
  - GET /repos/{owner}/{repo}/issues/{n}/comments       (find existing)
  - POST /repos/{owner}/{repo}/issues/{n}/comments      (create)
  - PATCH /repos/{owner}/{repo}/issues/comments/{id}    (update)
"""
from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from typing import Any, Iterable, Optional

from . import tokens

logger = logging.getLogger("ciguard.app.checks")

GITHUB_API_BASE = "https://api.github.com"
USER_AGENT = "ciguard-app"
API_VERSION = "2022-11-28"

# Hidden marker embedded in every PR comment body so we can find +
# update our own comment instead of stacking duplicates.
PR_COMMENT_MARKER = "<!-- ciguard:pr-marker:v1 -->"

# Length caps — keep evidence manageable in PR comments + defeat the
# "huge wall of attacker text" annoyance vector.
EVIDENCE_MAX_CHARS = 200
INLINE_MAX_CHARS = 120

# Maximum response body we'll read from GitHub. PR-comment lists can be
# moderately large; cap defensively against a hostile/malformed response.
MAX_RESPONSE_BYTES = 1 * 1024 * 1024  # 1 MB


# ===========================================================================
# Markdown sanitisation
# ===========================================================================


# Markdown special chars worth escaping when content lands inline. Backslash
# must come first so we don't double-escape what we just inserted.
_MD_SPECIALS = r"\`*_{}[]()#+-.!|>~"


def _safe_md_inline(value: Optional[str], *, max_len: int = INLINE_MAX_CHARS) -> str:
    """Escape attacker-controlled strings that land INLINE in markdown.

    Used for: file paths in `path:line` references, rule messages we
    don't fully trust (built-in messages are safe; LLM-enriched ones
    may not be), human-readable severities echoed back from input.

    Strips CR/LF + tab; escapes markdown specials; caps length;
    HTML-encodes `<` and `>` to defeat raw-HTML injection in markdown.
    """
    if value is None:
        return "_(none)_"
    safe = (
        value.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    )
    # HTML-encode angle brackets first (markdown lets raw HTML through).
    safe = safe.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # Backslash-escape every markdown special so links / emphasis can't
    # be smuggled in.
    out_chars: list[str] = []
    for ch in safe:
        if ch in _MD_SPECIALS:
            out_chars.append("\\" + ch)
        else:
            out_chars.append(ch)
    safe = "".join(out_chars)
    if len(safe) > max_len:
        safe = safe[:max_len] + "…"
    return safe


def _safe_md_block(value: Optional[str], *, max_len: int = EVIDENCE_MAX_CHARS) -> str:
    """Wrap attacker-controlled multi-line content in a 4-backtick fence.

    Used for: rule evidence (the YAML excerpt from the pipeline file).
    Evidence is the highest-risk surface — it can contain anything the
    attacker chose to put in their pipeline.

    A 4-backtick fence resists the standard 3-backtick break-out; if
    attacker content also has 4-or-more backtick runs, those runs get
    replaced with `~` so the fence can't be terminated early.
    """
    if value is None or value == "":
        return "```` ````"  # empty fence
    # Replace any run of 4-or-more backticks with the same number of `~`.
    safe = re.sub(r"`{4,}", lambda m: "~" * len(m.group(0)), value)
    # Length cap (counts characters; an evil multi-byte payload still
    # bounded in chars because we slice the str, not bytes).
    if len(safe) > max_len:
        safe = safe[:max_len] + "\n…(truncated)"
    # Strip CR — keep LF for legibility; CR alone confuses some clients.
    safe = safe.replace("\r", "")
    return f"````\n{safe}\n````"


# ===========================================================================
# PR comment body rendering
# ===========================================================================


def render_pr_comment_body(scan_result: dict[str, Any]) -> str:
    """Build a markdown PR comment body from a ciguard scan result.

    `scan_result` is expected to expose:
      - `risk_score`: int
      - `grade`: str ("A" / "B" / "C" / "D" / "F")
      - `findings`: list of dicts with `severity`, `rule_id`, `message`,
        `location`, `evidence`
      - `summary`: optional string

    Every value sourced from `findings` is treated as untrusted — the
    pipeline that contains a finding is, by definition, attacker-
    influenced for repos installed on the App.
    """
    score = scan_result.get("risk_score", "—")
    grade = _safe_md_inline(str(scan_result.get("grade", "?")), max_len=4)
    findings = list(scan_result.get("findings", []) or [])

    by_severity: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", "Info"))
        by_severity[sev] = by_severity.get(sev, 0) + 1

    parts: list[str] = [PR_COMMENT_MARKER, ""]
    parts.append(f"### ciguard scan — score {score} ({grade})")
    parts.append("")
    if not findings:
        parts.append("_No findings._")
    else:
        sev_order = ["Critical", "High", "Medium", "Low", "Info"]
        sev_summary = ", ".join(
            f"{by_severity[s]} {s}"
            for s in sev_order
            if by_severity.get(s, 0) > 0
        )
        parts.append(f"**{len(findings)} findings:** {sev_summary}")
        parts.append("")
        for f in findings[:25]:  # cap at 25 in the comment; full list in artifact
            parts.append(_render_finding_block(f))
        if len(findings) > 25:
            parts.append(f"_…and {len(findings) - 25} more (see SARIF artifact)_")
    parts.append("")
    parts.append("_Posted by ciguard. See "
                 "[github.com/Jo-Jo98/ciguard](https://github.com/Jo-Jo98/ciguard)._")
    return "\n".join(parts)


def _render_finding_block(finding: dict[str, Any]) -> str:
    rule_id = _safe_md_inline(str(finding.get("rule_id", "?")), max_len=64)
    severity = _safe_md_inline(str(finding.get("severity", "Info")), max_len=16)
    location = _safe_md_inline(str(finding.get("location", "")), max_len=160)
    message = _safe_md_inline(str(finding.get("message", "")), max_len=240)
    evidence = _safe_md_block(finding.get("evidence"))
    return (
        f"**[{severity}] {rule_id}** — {message}  \n"
        f"`{location}`\n"
        f"{evidence}"
    )


def conclusion_for_findings(findings: Iterable[dict[str, Any]]) -> str:
    """Map findings → Check Run conclusion.

      - failure: any Critical / High
      - neutral: only Medium / Low (informational; doesn't gate)
      - success: 0 or only Info
    """
    has_blocking = False
    has_warning = False
    for f in findings:
        sev = str(f.get("severity", "Info"))
        if sev in ("Critical", "High"):
            has_blocking = True
        elif sev in ("Medium", "Low"):
            has_warning = True
    if has_blocking:
        return "failure"
    if has_warning:
        return "neutral"
    return "success"


# ===========================================================================
# GitHub REST helpers (auth + 401 → invalidate)
# ===========================================================================


def _gh_request(
    *,
    method: str,
    url: str,
    installation_id: int,
    json_body: Optional[dict[str, Any]] = None,
) -> Any:
    """Authenticated request against api.github.com.

    On 401 we invalidate the cached installation token (the THREAT_MODEL
    "post-revocation" contract) and re-raise so the caller surfaces the
    failure cleanly. We do NOT auto-retry — a 401 means the install was
    revoked or the token was rejected; retry-immediately would just
    burn through the cache invalidation.
    """
    token = tokens.get_installation_token(installation_id)
    body_bytes: Optional[bytes] = None
    if json_body is not None:
        body_bytes = json.dumps(json_body).encode("utf-8")
    req = urllib.request.Request(
        url,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": API_VERSION,
            **({"Content-Type": "application/json"} if body_bytes else {}),
        },
        data=body_bytes,
    )
    try:
        # B310 nosec: URL is hardcoded HTTPS to api.github.com — see
        # GITHUB_API_BASE constant. No scheme injection possible.
        with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise RuntimeError(
                    "GitHub API response exceeded size cap"
                )
            if not raw:
                return None
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            logger.warning(
                "401 from GitHub on %s %s — invalidating cached token",
                method, _redact_url(url),
            )
            tokens.invalidate_token(installation_id)
        raise


def _redact_url(url: str) -> str:
    """Trim the URL for log lines — strip query params (sometimes carry
    pagination cursors) but keep the path so forensics can identify the
    endpoint."""
    return url.split("?", 1)[0]


# ===========================================================================
# Check Run primitives
# ===========================================================================


def create_check_run(
    *, installation_id: int, owner: str, repo: str, head_sha: str,
    name: str = "ciguard",
) -> int:
    """Open an in_progress Check Run; return its numeric id."""
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/check-runs"
    payload = {
        "name": name,
        "head_sha": head_sha,
        "status": "in_progress",
    }
    resp = _gh_request(
        method="POST", url=url, installation_id=installation_id,
        json_body=payload,
    )
    check_run_id = int(resp["id"])
    logger.info(
        "created check run id=%d (repo=%s/%s head=%s)",
        check_run_id, owner, repo, head_sha[:7],
    )
    return check_run_id


def complete_check_run(
    *, installation_id: int, owner: str, repo: str, check_run_id: int,
    conclusion: str, summary: str, title: str = "ciguard scan results",
) -> None:
    """Mark the Check Run as completed with the given conclusion.

    `summary` may contain markdown; it goes into `output.summary`. We
    don't put attacker-controlled content in `title`.
    """
    if conclusion not in (
        "success", "failure", "neutral",
        "cancelled", "skipped", "timed_out", "action_required",
    ):
        raise ValueError(f"invalid Check Run conclusion: {conclusion!r}")
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/check-runs/{check_run_id}"
    payload = {
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": title,
            "summary": summary,
        },
    }
    _gh_request(
        method="PATCH", url=url, installation_id=installation_id,
        json_body=payload,
    )
    logger.info(
        "completed check run id=%d conclusion=%s", check_run_id, conclusion,
    )


def set_check_run_failed(
    *, installation_id: int, owner: str, repo: str, check_run_id: int,
    message: str,
) -> None:
    """Defensive helper called from every scan-runner exception path.

    Closes the THREAT_MODEL row "Check Run state confusion" — internal
    crash MUST land the Check Run in `failure`, never leave it
    in_progress and never silently flip to success.
    """
    safe_msg = _safe_md_inline(message, max_len=400)
    summary = (
        "ciguard hit an internal error while scanning this commit. "
        f"\n\n> {safe_msg}\n\n"
        "Re-run the check after the issue is resolved."
    )
    try:
        complete_check_run(
            installation_id=installation_id, owner=owner, repo=repo,
            check_run_id=check_run_id, conclusion="failure",
            summary=summary, title="ciguard scan failed",
        )
    except Exception:  # noqa: BLE001 — last-line-of-defence logger
        # If even the failure-completion call fails, log + continue.
        # The Check Run will be left in_progress; the worker shouldn't
        # blow up its own death-handler.
        logger.exception(
            "set_check_run_failed: failure-completion call ALSO failed "
            "(check_run_id=%d). Check Run may remain in_progress.",
            check_run_id,
        )


# ===========================================================================
# PR comment primitives — upsert via hidden marker
# ===========================================================================


def post_or_update_pr_comment(
    *, installation_id: int, owner: str, repo: str, pr_number: int, body: str,
) -> int:
    """Find the existing ciguard comment by marker; PATCH if present,
    POST a new one otherwise. Returns the comment id either way.
    """
    if PR_COMMENT_MARKER not in body:
        # Defensive: the marker is what makes upsert work. If a caller
        # forgets it, we'd stack duplicate comments.
        body = f"{PR_COMMENT_MARKER}\n{body}"
    existing = _find_existing_ciguard_comment(
        installation_id=installation_id,
        owner=owner, repo=repo, pr_number=pr_number,
    )
    if existing is not None:
        url = (
            f"{GITHUB_API_BASE}/repos/{owner}/{repo}/issues/comments/"
            f"{existing}"
        )
        _gh_request(
            method="PATCH", url=url, installation_id=installation_id,
            json_body={"body": body},
        )
        logger.info(
            "updated PR comment id=%d (repo=%s/%s pr=#%d)",
            existing, owner, repo, pr_number,
        )
        return existing

    url = (
        f"{GITHUB_API_BASE}/repos/{owner}/{repo}/issues/{pr_number}/comments"
    )
    resp = _gh_request(
        method="POST", url=url, installation_id=installation_id,
        json_body={"body": body},
    )
    comment_id = int(resp["id"])
    logger.info(
        "posted PR comment id=%d (repo=%s/%s pr=#%d)",
        comment_id, owner, repo, pr_number,
    )
    return comment_id


def _find_existing_ciguard_comment(
    *, installation_id: int, owner: str, repo: str, pr_number: int,
) -> Optional[int]:
    """Walk the comments on the PR, return the id of the first one that
    contains our marker. Single-page only; if the PR has so many
    comments that ours has fallen off page 1, we'll post a new one.
    That's an acceptable degradation — the alternative is unbounded
    pagination on every webhook.
    """
    url = (
        f"{GITHUB_API_BASE}/repos/{owner}/{repo}/issues/{pr_number}/"
        "comments?per_page=100"
    )
    comments = _gh_request(
        method="GET", url=url, installation_id=installation_id,
    )
    if not isinstance(comments, list):
        return None
    for c in comments:
        if not isinstance(c, dict):
            continue
        body = c.get("body", "")
        if isinstance(body, str) and PR_COMMENT_MARKER in body:
            try:
                return int(c["id"])
            except (KeyError, TypeError, ValueError):
                continue
    return None
