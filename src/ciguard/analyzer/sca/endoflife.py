"""
endoflife.date client + on-disk cache.

endoflife.date is a free, well-maintained vendor-neutral catalogue of EOL
schedules for ~250 products. Each product endpoint returns
`[{cycle, eol, releaseDate, latest, ...}, ...]` JSON, sorted newest first.

  - `cycle` is the major or major.minor identifier (e.g. "3.18" for
    Alpine, "12" for Debian, "3.9" for Python).
  - `eol` is an ISO date string OR `false` if not yet announced. We treat
    `false` as "no EOL signal" (skip).
  - `releaseDate` is ISO date.

Caching: file-based at `<cache_dir>/endoflife-<product>.json` with a default
24h TTL. Pipeline scans must stay fast — we cannot hit the network on every
run. Cache misses fall back to network; network errors fall back to a stale
cache if available, otherwise return `None` (rules then skip the check).

Offline mode (`--offline` CLI flag): never hits the network. Uses cache if
present, returns `None` otherwise. Designed for air-gapped CI environments.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

API_BASE = "https://endoflife.date/api"
USER_AGENT = "ciguard-sca/0.6 (+https://github.com/Jo-Jo98/ciguard)"
DEFAULT_TTL_SECONDS = 24 * 60 * 60                 # 24 hours
DEFAULT_TIMEOUT_SECONDS = 8

# Map of "image name → endoflife.date product slug". Many image names match
# their endoflife slug exactly; the ones below need explicit redirection.
# Add aggressively — false negatives are worse than false positives here
# (a missing mapping = silently skipped EOL check).
IMAGE_TO_PRODUCT: dict[str, str] = {
    # OS bases
    "alpine": "alpine-linux",
    "debian": "debian",
    "ubuntu": "ubuntu",
    "centos": "centos",
    "rockylinux": "rocky-linux",
    "rocky": "rocky-linux",
    "almalinux": "alma-linux",
    "fedora": "fedora",
    # Language runtimes
    "python": "python",
    "node": "nodejs",
    "nodejs": "nodejs",
    "ruby": "ruby",
    "golang": "go",
    "go": "go",
    "rust": "rust",
    "php": "php",
    "openjdk": "java",
    "eclipse-temurin": "eclipse-temurin",
    "amazoncorretto": "amazon-corretto",
    "ibm-semeru-runtimes": "ibm-semeru-runtimes",
    # Databases (rarely in CI base images but covered)
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "mongo": "mongodb",
    "mongodb": "mongodb",
    "redis": "redis",
    # Tooling
    "maven": "maven",
    "gradle": "gradle",
}


class EndOfLifeClient:
    """Thin wrapper around the endoflife.date REST API with an on-disk
    cache. Designed to be reused across many lookups in a single scan."""

    def __init__(
        self,
        cache_dir: Path,
        offline: bool = False,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.cache_dir = cache_dir
        self.offline = offline
        self.ttl_seconds = ttl_seconds
        self.timeout_seconds = timeout_seconds
        # In-memory cache so repeated lookups in one scan don't re-read disk.
        self._mem: dict[str, Optional[list[dict]]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def cycles_for_image(self, image_name: str) -> Optional[list[dict]]:
        """Return the endoflife.date cycle list for a Docker image name,
        or None if we can't map / fetch / find it. Result is the raw API
        payload (`[{cycle, eol, ...}, ...]`)."""
        product = IMAGE_TO_PRODUCT.get(image_name.lower())
        if product is None:
            return None
        return self.cycles_for_product(product)

    def cycles_for_product(self, product: str) -> Optional[list[dict]]:
        """Return the endoflife.date cycle list for a product slug, or None
        on error / not-found. Caches successful results."""
        if product in self._mem:
            return self._mem[product]
        cached = self._read_cache(product)
        if cached is not None and not self._cache_stale(product):
            self._mem[product] = cached
            return cached
        if self.offline:
            # Offline + stale (or missing) cache → return whatever we have
            # without trying the network.
            self._mem[product] = cached
            return cached
        fetched = self._fetch(product)
        if fetched is not None:
            self._write_cache(product, fetched)
            self._mem[product] = fetched
            return fetched
        # Network error → fall back to stale cache if any.
        self._mem[product] = cached
        return cached

    @staticmethod
    def find_cycle(cycles: list[dict], cycle_id: str) -> Optional[dict]:
        """Find the cycle entry whose `cycle` field matches `cycle_id`.
        Tries exact match first, then prefix match (e.g. "3.18.4" → "3.18",
        "21.0.5" → "21"). Returns the cycle dict or None."""
        for c in cycles:
            if str(c.get("cycle", "")) == cycle_id:
                return c
        # Prefix match: try shrinking the cycle_id from the right.
        # "3.18.4" → "3.18" → "3"
        parts = cycle_id.split(".")
        while len(parts) > 1:
            parts.pop()
            candidate = ".".join(parts)
            for c in cycles:
                if str(c.get("cycle", "")) == candidate:
                    return c
        return None

    @staticmethod
    def days_until_eol(cycle: dict, today: Optional[datetime] = None) -> Optional[int]:
        """Days from `today` until this cycle's EOL date. Negative = past
        EOL. None if the cycle has no EOL date yet (`eol: false` from API).

        `today` defaults to UTC now; passable for testing."""
        eol_raw = cycle.get("eol")
        if eol_raw is None or eol_raw is False:
            return None
        try:
            eol_date = datetime.fromisoformat(str(eol_raw)).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return None
        now = today or datetime.now(tz=timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        delta = eol_date - now
        return delta.days

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _cache_path(self, product: str) -> Path:
        # Slashes in product names can't appear in endoflife slugs, so
        # this is safe without further sanitising.
        return self.cache_dir / f"endoflife-{product}.json"

    def _read_cache(self, product: str) -> Optional[list[dict]]:
        path = self._cache_path(product)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    def _write_cache(self, product: str, data: list[dict]) -> None:
        path = self._cache_path(product)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.write_text(json.dumps(data), encoding="utf-8")
        except OSError:
            # Cache failures are non-fatal; we just won't get the perf
            # benefit on the next run.
            pass

    def _cache_stale(self, product: str) -> bool:
        path = self._cache_path(product)
        if not path.exists():
            return True
        age = time.time() - path.stat().st_mtime
        return age > self.ttl_seconds

    def _fetch(self, product: str) -> Optional[list[dict]]:
        url = f"{API_BASE}/{product}.json"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )
        try:
            # B310: URL is hardcoded HTTPS to endoflife.date; no scheme injection possible.
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:  # nosec B310
                if resp.status != 200:
                    return None
                payload = json.loads(resp.read().decode("utf-8"))
                if not isinstance(payload, list):
                    return None
                return payload
        except (urllib.error.HTTPError, urllib.error.URLError,
                json.JSONDecodeError, TimeoutError, OSError):
            # Any network / parse error → caller falls back to stale cache.
            return None
