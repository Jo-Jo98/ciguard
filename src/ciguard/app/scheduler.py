"""Async scan scheduler for the ciguard GitHub App.

Threat model: `Project ciguard/THREAT_MODEL.md` Surface 9. Closes:

  - "Concurrent webhook race" (Medium, DREAD 15) — two `push` deliveries
    for the same `(installation_id, head_sha)` collapse to one scan.
    Two scans against the same `(installation_id, repo_full_name)`
    serialise their baseline writes via a per-key asyncio.Lock so the
    on-disk baseline.json can't be corrupted by interleaved writes.
  - "Webhook handler DoS — large payload / slow scan" (High, DREAD 18) —
    completes the mitigation started in webhook.py: the handler returns
    202 in milliseconds; this scheduler queues the work + executes it
    on N background workers, so a slow scan can't block legit deliveries.

Design commitments from THREAT_MODEL.md "v0.10.0 design rationale":

  1. Idempotency key = `(installation_id, head_sha)` — strict tuple, no
     `repo_full_name`-only collapse (same SHA across different repos
     would still scan twice; same SHA inside one installation collapses).
  2. Webhook handler returns 202 within ms; queue is the boundary.
  3. Per-key lock on baseline writes; the lock dictionary itself is
     guarded by a coarse asyncio.Lock so the lookup-or-create is atomic.
  4. Worker fan-out is bounded (default 2); queue is bounded too (default
     128) so a flood backpressures via 503 at the enqueue site instead
     of unbounded memory growth.

Scope of THIS module:
  - The scheduler primitives (queue + idempotency cache + per-key lock).
  - A pluggable `scan_fn` injection point — the actual scan_repo + Check
    Run + PR comment work lands in step (iv) and is passed in here.
  - No FastAPI integration yet — step (vi) wires this to app.state.
"""
from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncIterator, Awaitable, Callable, Optional

logger = logging.getLogger("ciguard.app.scheduler")

DEFAULT_QUEUE_SIZE = 128
DEFAULT_WORKERS = 2

# Idempotency cache TTL — if the same (installation_id, head_sha) shows up
# again after this window, treat it as a fresh scan request. 1 hour matches
# the X-GitHub-Delivery dedup window in webhook.py: GitHub retries land
# inside that envelope, anything later is a deliberate re-scan.
IDEMPOTENCY_TTL_SECONDS = 60 * 60


# ---- Data shapes -----------------------------------------------------------


@dataclass(frozen=True)
class ScanJob:
    """A single repository-at-SHA scan request, derived from a webhook
    delivery. The exact fields will grow as steps (iv) + (v) flesh out
    the actual scan / Check-Run / baseline pipeline; this minimal shape
    is enough for the scheduler to do its job."""
    installation_id: int
    repo_full_name: str
    head_sha: str
    pr_number: Optional[int] = None
    event: str = "push"

    @property
    def idempotency_key(self) -> tuple[int, str]:
        return (self.installation_id, self.head_sha)

    @property
    def baseline_key(self) -> tuple[int, str]:
        """Per-installation, per-repo. Two scans of the same repo at
        different SHAs still serialise their baseline writes."""
        return (self.installation_id, self.repo_full_name)


@dataclass(frozen=True)
class EnqueueOutcome:
    accepted: bool
    reason: str  # "enqueued" | "deduplicated" | "queue_full"


# ---- Scheduler -------------------------------------------------------------


@dataclass
class _IdemEntry:
    job: ScanJob
    enqueued_at: float


ScanFn = Callable[[ScanJob], Awaitable[None]]


class ScanScheduler:
    """Receives ScanJobs from the webhook handler, dedupes, fans out
    to a small worker pool. The injected `scan_fn` is what actually
    runs against the repo — see step (iv)."""

    def __init__(
        self,
        scan_fn: ScanFn,
        *,
        queue_size: int = DEFAULT_QUEUE_SIZE,
        num_workers: int = DEFAULT_WORKERS,
        idempotency_ttl: float = IDEMPOTENCY_TTL_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._scan_fn = scan_fn
        self._queue: asyncio.Queue[ScanJob] = asyncio.Queue(maxsize=queue_size)
        self._idempotency: dict[tuple[int, str], _IdemEntry] = {}
        self._idempotency_ttl = idempotency_ttl
        self._clock = clock
        self._num_workers = num_workers

        # Per-`baseline_key` locks. The dict itself is guarded by a coarse
        # lock so lookup-or-create stays atomic across concurrent
        # `baseline_lock()` calls.
        self._baseline_locks: dict[tuple[int, str], asyncio.Lock] = {}
        self._locks_guard = asyncio.Lock()

        self._workers: list[asyncio.Task[None]] = []
        self._shutdown = False

    # ---- Lifecycle ----

    async def start(self) -> None:
        if self._workers:
            raise RuntimeError("scheduler already started")
        self._shutdown = False
        for i in range(self._num_workers):
            self._workers.append(asyncio.create_task(self._worker_loop(i)))
        logger.info("scan scheduler started (workers=%d)", self._num_workers)

    async def shutdown(self, *, drain_seconds: float = 30.0) -> None:
        """Stop accepting new work, drain the queue, then cancel workers."""
        self._shutdown = True
        try:
            await asyncio.wait_for(self._queue.join(), timeout=drain_seconds)
        except asyncio.TimeoutError:
            logger.warning(
                "scheduler drain timed out after %.1fs (queue=%d)",
                drain_seconds, self._queue.qsize(),
            )
        for w in self._workers:
            w.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()
        logger.info("scan scheduler shut down")

    # ---- Public surface ----

    async def enqueue(self, job: ScanJob) -> EnqueueOutcome:
        """Try to enqueue. Returns the outcome; the caller (webhook handler)
        decides what HTTP status to surface."""
        if self._shutdown:
            return EnqueueOutcome(accepted=False, reason="queue_full")

        self._purge_expired_idempotency()
        if job.idempotency_key in self._idempotency:
            logger.info(
                "deduplicated scan job (installation=%d head=%s)",
                job.installation_id, job.head_sha[:7],
            )
            return EnqueueOutcome(accepted=False, reason="deduplicated")

        try:
            self._queue.put_nowait(job)
        except asyncio.QueueFull:
            logger.warning(
                "rejecting scan job — queue full (size=%d)",
                self._queue.qsize(),
            )
            return EnqueueOutcome(accepted=False, reason="queue_full")

        self._idempotency[job.idempotency_key] = _IdemEntry(
            job=job, enqueued_at=self._clock(),
        )
        logger.info(
            "enqueued scan job (installation=%d repo=%s head=%s event=%s)",
            job.installation_id, job.repo_full_name, job.head_sha[:7], job.event,
        )
        return EnqueueOutcome(accepted=True, reason="enqueued")

    @asynccontextmanager
    async def baseline_lock(
        self, installation_id: int, repo_full_name: str
    ) -> AsyncIterator[None]:
        """Per-`(installation_id, repo)` lock for serialising baseline.json
        writes. Two concurrent scans of the same repo block here; scans of
        different repos within the same install run in parallel."""
        key = (installation_id, repo_full_name)
        async with self._locks_guard:
            lock = self._baseline_locks.get(key)
            if lock is None:
                lock = asyncio.Lock()
                self._baseline_locks[key] = lock
        async with lock:
            yield

    # ---- Workers ----

    async def _worker_loop(self, worker_id: int) -> None:
        """Pull jobs off the queue and hand them to the injected scan_fn.
        Exceptions are logged + swallowed so one bad job can't kill the
        worker; future steps will route them to a Check Run failure
        (THREAT_MODEL row "Check Run state confusion")."""
        while True:
            job = await self._queue.get()
            try:
                await self._scan_fn(job)
            except asyncio.CancelledError:
                self._queue.task_done()
                raise
            except Exception:  # noqa: BLE001 — last line of defence
                logger.exception(
                    "scan_fn raised for job (installation=%d head=%s); "
                    "the worker continues but the Check Run remains "
                    "unset — wire failure routing in step (iv).",
                    job.installation_id, job.head_sha[:7],
                )
            finally:
                self._queue.task_done()

    # ---- Internals ----

    def _purge_expired_idempotency(self) -> None:
        cutoff = self._clock() - self._idempotency_ttl
        stale = [k for k, e in self._idempotency.items() if e.enqueued_at < cutoff]
        for k in stale:
            self._idempotency.pop(k, None)

    # ---- Test introspection ----

    def queue_size(self) -> int:
        return self._queue.qsize()

    def baseline_lock_count(self) -> int:
        return len(self._baseline_locks)
