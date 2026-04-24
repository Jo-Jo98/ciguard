"""
In-memory scan result store with simple LRU eviction.

Suitable for single-process deployments. For multi-process deployments
(multiple uvicorn workers) replace with a Redis-backed store.
"""
from __future__ import annotations

import uuid
from collections import OrderedDict
from typing import Optional

from ..models.pipeline import Report


class ScanStore:
    MAX_SCANS = 200  # evict oldest after this limit

    def __init__(self) -> None:
        self._store: OrderedDict[str, Report] = OrderedDict()

    def put(self, report: Report) -> str:
        """Store a report and return its scan_id."""
        scan_id = str(uuid.uuid4())
        if len(self._store) >= self.MAX_SCANS:
            self._store.popitem(last=False)  # drop oldest
        self._store[scan_id] = report
        return scan_id

    def get(self, scan_id: str) -> Optional[Report]:
        return self._store.get(scan_id)

    def __len__(self) -> int:
        return len(self._store)


# Module-level singleton — shared across all requests in one process
_store = ScanStore()


def get_store() -> ScanStore:
    return _store
