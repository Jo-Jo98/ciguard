#!/usr/bin/env bash
# Local pre-tag release script.
#
# Runs every check that GitHub Actions will run, against a clean local venv,
# BEFORE bumping the version + tagging + pushing. If any check fails, the
# script aborts before touching git — no bad commit ever lands on main.
#
# Why this exists:
#   v0.6.0 and v0.6.1 both shipped despite their CI workflow runs being red
#   on the tagged commit. The Release workflow now gates on the same checks
#   (see .github/workflows/_checks.yml) which closes the GitHub-side gap,
#   but having a local fail-fast script means you discover problems in
#   seconds instead of after a 3-5 minute CI round-trip.
#
# Usage:
#   ./scripts/release.sh 0.6.2 "fix: short summary"
#
# What this does NOT do:
#   - Does NOT push automatically. After all checks pass + version is bumped
#     + tag is created, it prints the exact `git push` commands and exits.
#     Run them yourself when you're ready.
#   - Does NOT edit CHANGELOG.md. Add the entry by hand before running.

set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "usage: $0 X.Y.Z 'commit message subject'" >&2
    exit 2
fi

VERSION="$1"
SUBJECT="$2"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Sanity: must be on main and clean (apart from pyproject.toml + CHANGELOG.md
# which we expect to have been edited).
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$BRANCH" != "main" ]]; then
    echo "ERROR: must release from main (currently on $BRANCH)" >&2
    exit 1
fi
if ! git diff --quiet -- ':!pyproject.toml' ':!CHANGELOG.md'; then
    echo "ERROR: working tree has changes outside pyproject.toml + CHANGELOG.md" >&2
    git status --short >&2
    exit 1
fi

# Check version matches what was passed.
PYPROJECT_VERSION="$(grep -E '^version = ' pyproject.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')"
if [[ "$PYPROJECT_VERSION" != "$VERSION" ]]; then
    echo "ERROR: pyproject.toml version is $PYPROJECT_VERSION, expected $VERSION" >&2
    echo "       update pyproject.toml first, then re-run." >&2
    exit 1
fi
if ! grep -q "^## \[$VERSION\]" CHANGELOG.md; then
    echo "ERROR: no '## [$VERSION]' header found in CHANGELOG.md" >&2
    exit 1
fi

# Pull rebase first — Dependabot PRs land continuously and stale-base pushes
# get rejected. Captured as feedback memory `feedback_ciguard_pull_first`.
echo "→ git pull --rebase origin main"
git pull --rebase origin main

VENV="${VENV:-./venv}"
if [[ ! -x "$VENV/bin/python" ]]; then
    echo "ERROR: venv not found at $VENV — set VENV=path/to/venv or create one." >&2
    exit 1
fi

echo "→ ruff lint"
"$VENV/bin/ruff" check src tests scripts

echo "→ pytest"
"$VENV/bin/python" -m pytest -q

echo "→ bandit (medium/medium gate)"
"$VENV/bin/bandit" -r src/ --severity-level medium --confidence-level medium

echo "→ pip-audit"
"$VENV/bin/pip-audit" --strict -r requirements.txt

echo "→ validate_fixtures.py (PRD acceptance criteria 1 & 2)"
"$VENV/bin/python" scripts/validate_fixtures.py >/dev/null

# All green — stage the version + changelog edits, commit, tag.
echo "→ git add + commit + tag"
git add pyproject.toml CHANGELOG.md
git commit -m "$VERSION: $SUBJECT"
git tag -a "v$VERSION" -m "v$VERSION"

cat <<EOF

✅ All checks green; commit + tag created locally:
   $(git log -1 --oneline)
   $(git tag -l "v$VERSION" | head -1)

To finish the release, push commit + tag:
   git push origin main
   git push origin v$VERSION

The Release workflow will re-run the same checks before publishing — see
.github/workflows/release.yml.
EOF
