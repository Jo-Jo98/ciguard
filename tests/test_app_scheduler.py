"""Tests for the v0.10.0 GitHub App scan scheduler.

Covers Surface 9 STRIDE rows that THIS module closes:
  - Concurrent webhook race (Medium, DREAD 15) — idempotency on
    (installation_id, head_sha) collapses duplicate same-SHA deliveries;
    per-(installation_id, repo) lock serialises baseline writes.
  - Webhook handler DoS — large payload / slow scan (High, DREAD 18) —
    bounded queue + bounded worker pool keep slow scans off the
    request thread.

The project has no `pytest-asyncio` dep — each test is a thin sync
wrapper around an `async def _inner()` invoked via `asyncio.run()`.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Awaitable, Callable

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.app.scheduler import ScanJob, ScanScheduler  # noqa: E402


def _job(
    *, installation_id: int = 42, repo: str = "owner/repo",
    head: str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    event: str = "push", pr: int | None = None,
) -> ScanJob:
    return ScanJob(
        installation_id=installation_id,
        repo_full_name=repo,
        head_sha=head,
        pr_number=pr,
        event=event,
    )


def _run(coro_factory: Callable[[], Awaitable[None]]) -> None:
    asyncio.run(coro_factory())


# ---- Idempotency ------------------------------------------------------------


def test_duplicate_installation_id_and_head_dedups() -> None:
    """Two webhook deliveries for the same (installation_id, head_sha)
    must collapse — only one scan runs."""
    scanned: list[ScanJob] = []

    async def stub_scan(job: ScanJob) -> None:
        scanned.append(job)

    async def _inner() -> None:
        sched = ScanScheduler(stub_scan, num_workers=1)
        await sched.start()
        try:
            out1 = await sched.enqueue(_job(event="push"))
            out2 = await sched.enqueue(_job(event="pull_request"))
            await asyncio.sleep(0.05)
        finally:
            await sched.shutdown()
        assert out1.accepted is True
        assert out1.reason == "enqueued"
        assert out2.accepted is False
        assert out2.reason == "deduplicated"
        assert len(scanned) == 1

    _run(_inner)


def test_push_and_pull_request_for_same_head_sha_both_run() -> None:
    """Caught on the v0.10.0 smoke test (2026-04-30). When `git push`
    with an open PR fires both `push` (pr_number=None) and
    `pull_request.synchronize` (pr_number=N) within ~1s for the same
    head SHA, BOTH must dispatch — push gets a Check Run, the PR
    event additionally posts the inline comment. Without pr_number
    in the idempotency key, push wins the race and the PR comment
    never gets posted."""
    scanned: list[ScanJob] = []

    async def stub_scan(job: ScanJob) -> None:
        scanned.append(job)

    async def _inner() -> None:
        sched = ScanScheduler(stub_scan, num_workers=1)
        await sched.start()
        try:
            push_out = await sched.enqueue(_job(event="push", pr=None))
            pr_out = await sched.enqueue(_job(event="pull_request", pr=42))
            await asyncio.sleep(0.05)
        finally:
            await sched.shutdown()
        assert push_out.accepted is True
        assert pr_out.accepted is True
        assert len(scanned) == 2
        assert {j.pr_number for j in scanned} == {None, 42}


def test_different_installations_with_same_sha_do_not_dedup() -> None:
    """The dedup key is the FULL tuple — same SHA in different
    installations must each run."""
    scanned: list[ScanJob] = []

    async def stub_scan(job: ScanJob) -> None:
        scanned.append(job)

    async def _inner() -> None:
        sched = ScanScheduler(stub_scan, num_workers=1)
        await sched.start()
        try:
            await sched.enqueue(_job(installation_id=111))
            await sched.enqueue(_job(installation_id=222))
            await asyncio.sleep(0.05)
        finally:
            await sched.shutdown()
        assert len(scanned) == 2
        assert {j.installation_id for j in scanned} == {111, 222}

    _run(_inner)


def test_idempotency_window_expires_so_re_scan_works() -> None:
    """Past the idempotency TTL, the same (install, sha) is allowed to
    re-scan — handles the deliberate `re-run failed checks` case."""
    scanned: list[ScanJob] = []

    async def stub_scan(job: ScanJob) -> None:
        scanned.append(job)

    fake_now = [1000.0]

    async def _inner() -> None:
        sched = ScanScheduler(
            stub_scan, num_workers=1, idempotency_ttl=300.0,
            clock=lambda: fake_now[0],
        )
        await sched.start()
        try:
            await sched.enqueue(_job())
            await asyncio.sleep(0.05)
            fake_now[0] += 100.0
            out_within = await sched.enqueue(_job())
            fake_now[0] += 250.0
            out_past = await sched.enqueue(_job())
            await asyncio.sleep(0.05)
        finally:
            await sched.shutdown()
        assert out_within.reason == "deduplicated"
        assert out_past.reason == "enqueued"
        assert len(scanned) == 2

    _run(_inner)


# ---- Queue overflow ---------------------------------------------------------


def test_queue_full_returns_outcome_without_dropping_state() -> None:
    """Bounded queue protects against unbounded memory growth; caller
    decides how to surface (webhook handler will return 503)."""
    async def _inner() -> None:
        block_until = asyncio.Event()
        started = asyncio.Event()

        async def slow_scan(job: ScanJob) -> None:
            started.set()
            await block_until.wait()

        sched = ScanScheduler(slow_scan, num_workers=1, queue_size=2)
        await sched.start()
        try:
            a = await sched.enqueue(_job(head="a" * 40))
            await started.wait()
            b = await sched.enqueue(_job(head="b" * 40))
            c = await sched.enqueue(_job(head="c" * 40))
            d = await sched.enqueue(_job(head="d" * 40))
            assert a.reason == b.reason == c.reason == "enqueued"
            assert d.accepted is False
            assert d.reason == "queue_full"
        finally:
            block_until.set()
            await sched.shutdown()

    _run(_inner)


# ---- Worker fan-out ---------------------------------------------------------


def test_workers_run_distinct_jobs_in_parallel() -> None:
    """Bounded worker pool processes the queue concurrently. Two jobs
    against different SHAs should run in parallel, not serially."""
    async def _inner() -> None:
        in_flight = 0
        max_in_flight = 0
        lock = asyncio.Lock()

        async def slow_scan(job: ScanJob) -> None:
            nonlocal in_flight, max_in_flight
            async with lock:
                in_flight += 1
                max_in_flight = max(max_in_flight, in_flight)
            await asyncio.sleep(0.02)
            async with lock:
                in_flight -= 1

        sched = ScanScheduler(slow_scan, num_workers=2)
        await sched.start()
        try:
            for i in range(4):
                await sched.enqueue(_job(head=str(i) * 40))
            await asyncio.sleep(0.2)
        finally:
            await sched.shutdown()
        assert max_in_flight == 2

    _run(_inner)


# ---- Per-key baseline lock --------------------------------------------------


def test_baseline_lock_serialises_same_repo() -> None:
    """Two acquisitions of the same (install, repo) baseline_lock must
    serialise — no overlap. Different repos run concurrently."""
    async def _inner() -> None:
        async def noop(_job: ScanJob) -> None:
            return None

        sched = ScanScheduler(noop)
        overlap_seen = False
        holding = 0

        async def acquire_same() -> None:
            nonlocal overlap_seen, holding
            async with sched.baseline_lock(42, "owner/repo"):
                holding += 1
                if holding > 1:
                    overlap_seen = True
                await asyncio.sleep(0.01)
                holding -= 1

        await asyncio.gather(acquire_same(), acquire_same(), acquire_same())
        assert overlap_seen is False

    _run(_inner)


def test_baseline_lock_different_repos_run_in_parallel() -> None:
    """Two scans against different (install, repo) tuples must not
    block each other — that would serialise unrelated work."""
    async def _inner() -> None:
        async def noop(_job: ScanJob) -> None:
            return None

        sched = ScanScheduler(noop)
        holding = 0
        max_holding = 0
        lock = asyncio.Lock()

        async def acquire(install: int, repo: str) -> None:
            nonlocal holding, max_holding
            async with sched.baseline_lock(install, repo):
                async with lock:
                    holding += 1
                    max_holding = max(max_holding, holding)
                await asyncio.sleep(0.02)
                async with lock:
                    holding -= 1

        await asyncio.gather(
            acquire(42, "owner/a"),
            acquire(42, "owner/b"),
            acquire(99, "owner/a"),
        )
        assert max_holding == 3

    _run(_inner)


def test_baseline_lock_dictionary_grows_only_per_unique_repo() -> None:
    """The lock dict shouldn't spam new entries on every call — re-using
    the same key returns the same lock."""
    async def _inner() -> None:
        async def noop(_job: ScanJob) -> None:
            return None

        sched = ScanScheduler(noop)
        async with sched.baseline_lock(42, "owner/repo"):
            pass
        async with sched.baseline_lock(42, "owner/repo"):
            pass
        async with sched.baseline_lock(42, "owner/other"):
            pass
        assert sched.baseline_lock_count() == 2

    _run(_inner)


# ---- Worker fault tolerance -------------------------------------------------


def test_one_failing_scan_does_not_kill_the_worker() -> None:
    """Exception in scan_fn must be logged + swallowed; the worker
    continues to drain the queue. Final routing of the failure to a
    Check Run lands in step (iv); for now we just need fault tolerance."""
    seen: list[int] = []

    async def flaky_scan(job: ScanJob) -> None:
        if job.installation_id == 1:
            raise RuntimeError("boom")
        seen.append(job.installation_id)

    async def _inner() -> None:
        sched = ScanScheduler(flaky_scan, num_workers=1)
        await sched.start()
        try:
            await sched.enqueue(_job(installation_id=1, head="a" * 40))
            await sched.enqueue(_job(installation_id=2, head="b" * 40))
            await sched.enqueue(_job(installation_id=3, head="c" * 40))
            await asyncio.sleep(0.05)
        finally:
            await sched.shutdown()
        assert seen == [2, 3]

    _run(_inner)


# ---- Shutdown drains -------------------------------------------------------


def test_shutdown_drains_queued_jobs() -> None:
    """A pending queue must complete on graceful shutdown (within drain
    timeout) before workers cancel."""
    completed: list[int] = []

    async def quick_scan(job: ScanJob) -> None:
        await asyncio.sleep(0.01)
        completed.append(job.installation_id)

    async def _inner() -> None:
        sched = ScanScheduler(quick_scan, num_workers=1)
        await sched.start()
        for i in range(5):
            await sched.enqueue(_job(installation_id=i, head=str(i) * 40))
        await sched.shutdown(drain_seconds=2.0)
        assert sorted(completed) == [0, 1, 2, 3, 4]

    _run(_inner)


def test_enqueue_after_shutdown_is_rejected() -> None:
    async def _inner() -> None:
        async def noop(_job: ScanJob) -> None:
            return None

        sched = ScanScheduler(noop)
        await sched.start()
        await sched.shutdown()
        out = await sched.enqueue(_job())
        assert out.accepted is False
        assert out.reason == "queue_full"

    _run(_inner)
