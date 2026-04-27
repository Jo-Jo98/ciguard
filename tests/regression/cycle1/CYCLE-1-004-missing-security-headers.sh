#!/usr/bin/env bash
# Regression test for CYCLE-1-004 (GHSA-7ww3-xvf5-cxwm): Web UI missing HTTP
# defence-in-depth headers.
#
# Pre-fix (v0.8.1): FastAPI app set no defence-in-depth headers; ZAP baseline
# flagged 11 alerts.
# Post-fix (v0.8.2): SecurityHeadersMiddleware sets 7 required headers globally
# (CSP / X-Frame-Options / X-Content-Type-Options / Referrer-Policy /
# Permissions-Policy / COOP / CORP). COEP intentionally omitted (would break
# Swagger UI cross-origin assets at /api/docs; ZAP flagged COEP at LOW only).
#
# Exit semantics:
#   exit 0 = EXPLOIT_CONFIRMED (regression — one or more required headers missing)
#   exit 1 = EXPLOIT_FAILED    (fix in place — all 7 headers present)
#
# CI invokes this directly. $PYTHON env var lets local users override.
set -euo pipefail

PYTHON="${PYTHON:-python3}"
PORT="${PORT:-8081}"

REQUIRED_HEADERS=(
  "Content-Security-Policy"
  "X-Frame-Options"
  "X-Content-Type-Options"
  "Referrer-Policy"
  "Permissions-Policy"
  "Cross-Origin-Opener-Policy"
  "Cross-Origin-Resource-Policy"
)

echo "=== Starting uvicorn on 127.0.0.1:$PORT ==="
"$PYTHON" -m uvicorn ciguard.web.app:app --host 127.0.0.1 --port "$PORT" \
  > /tmp/cycle1-004-uvicorn.log 2>&1 &
UVICORN_PID=$!

trap "kill $UVICORN_PID 2>/dev/null || true; rm -f /tmp/cycle1-004-uvicorn.log /tmp/cycle1-004-headers.txt" EXIT

# Wait for uvicorn (up to ~10 s).
for i in $(seq 1 10); do
  if curl -s -o /dev/null "http://127.0.0.1:$PORT/api/health" 2>/dev/null; then
    break
  fi
  sleep 1
done

echo
echo "=== Response headers from GET / ==="
curl -sI "http://127.0.0.1:$PORT/" | tee /tmp/cycle1-004-headers.txt

echo
echo "=== Header audit ==="
missing=0
for h in "${REQUIRED_HEADERS[@]}"; do
  if grep -i -q "^${h}:" /tmp/cycle1-004-headers.txt; then
    printf "  [PRESENT] %s\n" "$h"
  else
    printf "  [MISSING] %s\n" "$h"
    missing=$((missing + 1))
  fi
done

echo
if [ "$missing" -gt 0 ]; then
  echo "EXPLOIT CONFIRMED: $missing of ${#REQUIRED_HEADERS[@]} required defence-in-depth headers absent."
  echo "Mitigation: ensure SecurityHeadersMiddleware is registered in src/ciguard/web/app.py."
  exit 0
fi
echo "EXPLOIT FAILED: all ${#REQUIRED_HEADERS[@]} required headers present."
exit 1
