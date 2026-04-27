#!/usr/bin/env bash
# Regression test for CYCLE-1-002 (GHSA-jrm4-4pcf-4763): container image runs
# as root.
#
# Pre-fix (v0.8.1): Dockerfile lacked USER directive; container ran as uid=0.
# Post-fix (v0.8.2): groupadd + useradd + USER ciguard (uid=999).
#
# Exit semantics:
#   exit 0 = EXPLOIT_CONFIRMED (regression — container running as root again)
#   exit 1 = EXPLOIT_FAILED    (fix in place — non-root uid)
#
# CI invokes this with $IMAGE pointing at a locally-built image so the gate
# fires before publish. Local users can target a published tag via
# IMAGE=ghcr.io/jo-jo98/ciguard:latest.
set -euo pipefail

IMAGE="${IMAGE:-ciguard:dev}"

echo "=== Inspecting $IMAGE ==="
docker inspect "$IMAGE" >/dev/null || {
  echo "Image $IMAGE not found locally. CI should build it first; local users:"
  echo "  docker build -t ciguard:dev ."
  exit 2
}

echo
echo "=== id inside the container ==="
docker run --rm "$IMAGE" id

echo
echo "=== Dockerfile USER directive ==="
USER_DIRECTIVE=$(docker inspect "$IMAGE" --format '{{ .Config.User }}')
echo "  Config.User: ${USER_DIRECTIVE:-(empty - defaults to root)}"

UID_IN_CONTAINER=$(docker run --rm "$IMAGE" id -u)
echo
if [ "$UID_IN_CONTAINER" = "0" ]; then
  echo "EXPLOIT CONFIRMED: ciguard runs as root (uid=0) inside the container."
  echo "Mitigation: ensure 'USER ciguard' is the last directive in Dockerfile."
  exit 0
fi
echo "EXPLOIT FAILED: ciguard runs as non-root (uid=$UID_IN_CONTAINER) inside the container."
exit 1
