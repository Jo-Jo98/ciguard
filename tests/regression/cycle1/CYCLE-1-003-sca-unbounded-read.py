#!/usr/bin/env python3
"""Regression test for CYCLE-1-003 (GHSA-xw8c-rrvx-f7xq): SCA HTTP client reads
response body unbounded.

Pre-fix (v0.8.1): osv.py + endoflife.py call resp.read() without a size cap; a
hostile/MITM'd response of arbitrary size causes ciguard to allocate that much.
Post-fix (v0.8.2): MAX_RESPONSE_BYTES=5MB cap; oversized responses return None,
caller falls back to stale cache.

Approach: monkey-patch urllib.request.urlopen with a fake response of
attacker-controlled size, observe whether the OSV client honours the cap.

Exit semantics:
  exit 0 = EXPLOIT_CONFIRMED (regression — client read the entire oversize body)
  exit 1 = EXPLOIT_FAILED    (fix in place — client refused oversize body)

CI invokes via `python tests/regression/cycle1/CYCLE-1-003-sca-unbounded-read.py`.
"""
import resource
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

SIZE_MB = int(sys.argv[1]) if len(sys.argv) > 1 else 50

PAYLOAD = b'{"vulns":[{"id":"FAKE-CVE","summary":"' + b"A" * (SIZE_MB * 1024 * 1024) + b'"}]}'
print(f"[POC] crafted payload size: {len(PAYLOAD) / 1024 / 1024:.1f} MB")


class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body
        self.status = 200

    def read(self, n=None):
        if n is None:
            return self._body
        return self._body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def _fake_urlopen(req, timeout=None):
    print(f"[POC] urlopen called for {getattr(req, 'full_url', req)}")
    return _FakeResponse(PAYLOAD)


def _rss_mb() -> float:
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return rss / 1024 / 1024 if sys.platform == "darwin" else rss / 1024


print(f"[POC] memory at start: {_rss_mb():.1f} MB")

cache_dir = Path(tempfile.mkdtemp(prefix="cycle1-003-cache-"))

with patch("urllib.request.urlopen", _fake_urlopen):
    from ciguard.analyzer.sca.osv import OSVClient
    client = OSVClient(cache_dir=cache_dir, offline=False)
    print(f"[POC] memory before OSV lookup: {_rss_mb():.1f} MB")
    result = client.vulns_for_action("actions/checkout", "4.0.0")
    print(f"[POC] memory after OSV lookup:  {_rss_mb():.1f} MB")
    print(f"[POC] OSV returned {len(result) if result else 0} vulns")

print()
# Pre-fix expectation: result has 1+ entries (the fake CVE was parsed).
# Post-fix expectation: result is None or empty (cap exceeded → fetch returned None).
if result:
    print("EXPLOIT CONFIRMED: SCA client parsed oversize response.")
    print(f"With SIZE_MB = {SIZE_MB} memory grew significantly.")
    print("Mitigation: cap resp.read() with MAX_RESPONSE_BYTES (default 5 MB).")
    sys.exit(0)
print("EXPLOIT FAILED: SCA client refused to parse oversize response.")
print(f"With SIZE_MB={SIZE_MB} and MAX_RESPONSE_BYTES default 5 MB,")
print("the cap correctly returned None (caller falls back to stale cache).")
sys.exit(1)
