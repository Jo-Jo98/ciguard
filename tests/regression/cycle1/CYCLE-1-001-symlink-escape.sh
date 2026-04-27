#!/usr/bin/env bash
# Regression test for CYCLE-1-001 (GHSA-8cxw-cc62-q28v): discover_pipeline_files
# follows symlinks out of scan root.
#
# Pre-fix (v0.8.1): symlinked subdir's pipeline files appear in the result set.
# Post-fix (v0.8.2): symlinks ignored at walk time + resolved-root filter.
#
# Exit semantics:
#   exit 0 = EXPLOIT_CONFIRMED (regression — symlink target leaked into results)
#   exit 1 = EXPLOIT_FAILED    (fix in place — discovery stayed within scan root)
#
# CI invokes this directly; see .github/workflows/_checks.yml::regression-cycle1.
# $PYTHON env var lets local users override (default: python3 from PATH).
set -euo pipefail

PYTHON="${PYTHON:-python3}"
WORKDIR="$(mktemp -d -t cycle1-001.XXXXXX)"
SECRET_DIR="$(mktemp -d -t cycle1-001-secret.XXXXXX)"

trap "rm -rf '$WORKDIR' '$SECRET_DIR'" EXIT

echo "=== Setup ==="
echo "  scan root:  $WORKDIR"
echo "  secret dir: $SECRET_DIR"

# Stage a "secret" canonical-named pipeline file in the secret dir — this is
# what an attacker would want exfiltrated. CYCLE-1-001 fired because discovery
# walked the symlink and returned this path as if it lived inside the scan root.
cat > "$SECRET_DIR/.gitlab-ci.yml" << 'YEOF'
stages: [deploy]
deploy_prod:
  image: alpine:3.16
  variables:
    INTERNAL_DEPLOY_TOKEN: "glpat-not-real-just-a-marker-CYCLE-1-001"
  script:
    - echo "Token starts with: ${INTERNAL_DEPLOY_TOKEN:0:10}"
YEOF

# Plant the attacker's symlink. Pretend this came from a malicious repo clone.
ln -s "$SECRET_DIR" "$WORKDIR/innocent_subdir"

# A canonical pipeline file inside the legitimate scan root — included so
# the discovery walker has a reason to descend at all (without it the walker
# may early-return).
cat > "$WORKDIR/.gitlab-ci.yml" << 'YEOF'
stages: [test]
test: { script: [echo hi] }
YEOF

echo
echo "=== Running discover_pipeline_files($WORKDIR) ==="
"$PYTHON" - "$WORKDIR" "$SECRET_DIR" << 'PYEOF'
import sys
from pathlib import Path
from ciguard.discovery import discover_pipeline_files

root = Path(sys.argv[1])
secret = Path(sys.argv[2]).resolve()
files = discover_pipeline_files(root)

print(f"Discovery returned {len(files)} files:")
escaped = []
for f in files:
    resolved = f.path.resolve()
    in_scope = str(resolved).startswith(str(root.resolve()))
    flag = "    " if in_scope else "[ESC]"
    print(f"  {flag} {f.path}")
    if str(resolved).startswith(str(secret)):
        escaped.append(f)

print()
if escaped:
    print(f"REGRESSION ({len(escaped)} escaped): discovery returned files outside the scan root.")
    print("EXPLOIT CONFIRMED — discovery walked symlink out of scan dir.")
    sys.exit(0)
print("EXPLOIT FAILED — discovery stayed within scan root (fix is in place).")
sys.exit(1)
PYEOF
