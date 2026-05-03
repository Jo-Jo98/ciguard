#!/usr/bin/env python3
"""Regression: F-9.1.1 — leading/trailing OWS in X-Hub-Signature-256.

Cycle 1.5 finding F-9.1.1 (issue #23). Originally surfaced 2026-05-03.

Test contract:
- The exploit input is a signed-but-OWS-prefixed/suffixed signature header.
- The exploit "succeeds" if `_verify_signature()` accepts the value and
  returns None (i.e. the strict-OWS check has regressed).
- The exploit "fails" if `_verify_signature()` raises HTTPException(401).

Note on environmental scope: under canonical Uvicorn-on-h11 the HTTP layer
strips OWS BEFORE the ASGI handler sees the value, so this PoC runs the
unit function directly with literal whitespace prepended/appended. That's
the test-bench equivalent of "what would happen if a non-stripping ASGI
server (Hypercorn / Daphne) or a quirky proxy delivered the value with
its OWS preserved." The defence-in-depth check in webhook.py is exactly
the property this PoC pins.

Convention: exit 0 = exploit FAILED (fix held); exit 1 = exploit SUCCEEDED.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import sys

from fastapi import HTTPException

from ciguard.app import config, webhook

WEBHOOK_SECRET = "regression-secret-F-9.1.1"


def _sign(body: bytes) -> str:
    return "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode(), body, hashlib.sha256
    ).hexdigest()


def main() -> int:
    os.environ[config.WEBHOOK_SECRET_ENV] = WEBHOOK_SECRET
    body = b'{"action":"opened","number":1}'
    valid_sig = _sign(body)

    cases = [
        (" " + valid_sig,   "leading SPACE"),
        ("\t" + valid_sig,  "leading TAB"),
        (valid_sig + " ",   "trailing SPACE"),
        (valid_sig + "\t",  "trailing TAB"),
        ("  " + valid_sig,  "double leading SPACE"),
    ]

    fail = 0
    for sig, label in cases:
        try:
            webhook._verify_signature(body, sig)
            print(f"  [{label}] FAIL — exploit succeeded, OWS accepted: {sig!r}")
            fail += 1
        except HTTPException as exc:
            if exc.status_code == 401:
                print(f"  [{label}] PASS — fix held (401 raised)")
            else:
                print(
                    f"  [{label}] FAIL — wrong status {exc.status_code}: "
                    f"{exc.detail!r}"
                )
                fail += 1

    print()
    if fail:
        print(
            f"EXPLOIT SUCCEEDED ({fail}/{len(cases)} cases) — "
            "regression: F-9.1.1 has reopened."
        )
        return 1
    print(
        f"EXPLOIT FAILED ({len(cases)} cases) — F-9.1.1 strict-OWS check is in place."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
