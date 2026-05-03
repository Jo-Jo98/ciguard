#!/usr/bin/env python3
"""Regression: F-9.6.1 — `_safe_md_inline` must strip ASCII NUL bytes.

Originally surfaced by Cycle 1.5 self-pentest 2026-05-03. Fixed in v0.11.0-1.5fix.

PoC contract:
- The exploit input is a string with embedded ASCII NUL bytes.
- The exploit is "succeeded" if `_safe_md_inline()` returns a string still
  containing `\\x00` (i.e. CWE-158 vulnerability remains open).
- The exploit is "failed" if `_safe_md_inline()` strips the NULs.

Convention: exit 0 = exploit FAILED (fix held); exit 1 = exploit SUCCEEDED (regression).
"""
import sys

from ciguard.app import checks


def main() -> int:
    cases = [
        "before\x00middle\x00after",
        "\x00leading-null",
        "trailing-null\x00",
        "all-c0-controls\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1fend",
        "del-byte\x7fend",
    ]

    fail = 0
    for raw in cases:
        out = checks._safe_md_inline(raw)
        leaked = any(c == "\x00" for c in out) or any(0x01 <= ord(c) <= 0x1f for c in out) or "\x7f" in out
        verdict = "FAIL — exploit succeeded, control char leaked" if leaked else "PASS — fix held"
        print(f"  in={raw!r}\n    out={out!r}\n    {verdict}")
        if leaked:
            fail += 1

    print()
    if fail:
        print(f"EXPLOIT SUCCEEDED ({fail}/{len(cases)} cases) — regression: F-9.6.1 has reopened.")
        return 1
    print(f"EXPLOIT FAILED ({len(cases)} cases) — F-9.6.1 fix is in place.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
