"""
Labelled-fixture validator for ciguard.

Validates the two PRD acceptance criteria that need ground truth:

  1. Recall: ≥90% of rules expected to fire on `bad_pipeline.yml` actually fire.
  2. Precision: zero false positives on `good_pipeline.yml`.

Each fixture is annotated below with the set of rule IDs that *should* fire
("expected_rules"). For `good_pipeline.yml` the expected set is empty.

The expectations are derived from the inline comments in the fixtures
themselves and the PRD rule catalogue. They are documentation: if the
fixture changes, update the labels.

Run from project root:
    ./venv/bin/python scripts/validate_fixtures.py

Exit code is 0 only if all criteria pass.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ciguard.analyzer.engine import AnalysisEngine
from ciguard.parser.gitlab_parser import GitLabCIParser

FIXTURES = ROOT / "tests" / "fixtures"
RESULTS_DIR = ROOT / "tests" / "corpus_results"

# Ground-truth labels. Each entry:
#   "fixture_basename": {
#       "expected_rules": {rule_ids that MUST fire at least once},
#       "max_false_positives": int  # 0 for good_pipeline; small allowance otherwise
#   }
LABELS: dict[str, dict] = {
    "bad_pipeline": {
        "expected_rules": {
            # Pipeline integrity
            "PIPE-001",  # unpinned :latest image (line 5 + others)
            "PIPE-002",  # remote include
            "PIPE-003",  # curl|bash, eval, etc.
            # Identity & access
            "IAM-001",  # hardcoded secrets in variables
            "IAM-002",  # CI_JOB_TOKEN passed broadly
            "IAM-003",  # unmasked sensitive variables
            # Runner security
            "RUN-002",  # privileged dind
            "RUN-003",  # shared runner usage (currently fires broadly; see notes)
            # Artifact handling
            "ART-001",  # artifacts without expiry
            "ART-002",  # broad artifact paths
            # Deployment governance
            "DEP-001",  # direct-to-production
            "DEP-003",  # no manual gate for prod
            # Supply chain
            "SC-001",  # external script execution
            "SC-003",  # no dependency scanning stage
        },
        "max_false_positives": 0,
        # Rules in the catalogue that are NOT exercised by this fixture and are
        # therefore not part of recall measurement. PIPE-004 fires only on
        # deploy jobs missing an `environment:` block; bad_pipeline's
        # `deploy_prod` has one (the lack-of-protection concern is covered by
        # DEP-002 which is itself not exercised here).
        "not_exercised": {"PIPE-004", "DEP-002", "ART-003", "RUN-001", "SC-002"},
    },
    "good_pipeline": {
        "expected_rules": set(),
        "max_false_positives": 0,
        "not_exercised": set(),  # all rules in scope; none should fire
    },
    "typical_pipeline": {
        # No strict labelling — "typical" projects can fire some Mediums.
        # We treat this as an informational scan, not a pass/fail criterion.
        "expected_rules": set(),
        "max_false_positives": None,  # disable FP check
        "not_exercised": set(),
    },
    "complex_pipeline": {
        "expected_rules": set(),
        "max_false_positives": None,
        "not_exercised": set(),
    },
}


def scan(fixture: str):
    parser = GitLabCIParser()
    engine = AnalysisEngine()
    pipeline = parser.parse_file(FIXTURES / f"{fixture}.yml")
    return engine.analyse(pipeline, f"{fixture}.yml")


def evaluate(fixture: str, label: dict) -> dict:
    report = scan(fixture)
    fired = Counter(f.rule_id for f in report.findings)
    fired_set = set(fired.keys())

    expected = label["expected_rules"]
    not_exercised = label.get("not_exercised", set())

    if expected:
        hit = expected & fired_set
        missed = expected - fired_set
        recall = len(hit) / len(expected)
    else:
        hit = set()
        missed = set()
        recall = None

    # False positives = rules that fired but are NOT in expected, AND are
    # also not the rules we explicitly know aren't exercised. For good_pipeline
    # everything that fires is a FP.
    fp = fired_set - expected - not_exercised
    fp_count = sum(fired[r] for r in fp)

    return {
        "fixture": fixture,
        "score": round(report.risk_score.overall, 1) if report.risk_score else None,
        "grade": report.risk_score.grade if report.risk_score else None,
        "fired": dict(fired),
        "expected": sorted(expected),
        "hit": sorted(hit),
        "missed": sorted(missed),
        "recall": recall,
        "false_positives": sorted(fp),
        "false_positive_count": fp_count,
    }


def main() -> int:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    results = [evaluate(name, label) for name, label in LABELS.items()]

    failures: list[str] = []
    out: list[str] = []
    out.append("# ciguard — Labelled Fixture Validation\n")
    out.append("Validates PRD acceptance criteria 1 (≥90% TP on `bad_pipeline.yml`) and 2 (zero FPs on `good_pipeline.yml`).\n")

    for r in results:
        out.append(f"\n## `{r['fixture']}.yml`\n")
        out.append(f"- Score: **{r['score']}** ({r['grade']})")
        out.append(f"- Rules fired: {r['fired'] or 'none'}")
        if r["expected"]:
            out.append(f"- Expected to fire ({len(r['expected'])}): {r['expected']}")
            out.append(f"- Hit ({len(r['hit'])}): {r['hit']}")
            if r["missed"]:
                out.append(f"- **MISSED ({len(r['missed'])}): {r['missed']}**")
            out.append(f"- Recall: **{r['recall']*100:.1f}%**")
        if r["false_positives"]:
            out.append(f"- **False positives ({r['false_positive_count']} findings across {len(r['false_positives'])} rules): {r['false_positives']}**")

        # Pass/fail
        label = LABELS[r["fixture"]]
        if r["recall"] is not None and r["recall"] < 0.90:
            failures.append(f"{r['fixture']}: recall {r['recall']*100:.1f}% < 90%")
        if label["max_false_positives"] is not None and r["false_positive_count"] > label["max_false_positives"]:
            failures.append(
                f"{r['fixture']}: {r['false_positive_count']} false positives "
                f"(max allowed: {label['max_false_positives']})"
            )

    out.append("\n## Verdict\n")
    if failures:
        out.append("❌ **FAIL** — PRD acceptance criteria not met:")
        for f in failures:
            out.append(f"- {f}")
    else:
        out.append("✅ **PASS** — PRD acceptance criteria 1 & 2 met.")

    summary = "\n".join(out) + "\n"
    print(summary)
    (RESULTS_DIR / "FIXTURE_VALIDATION.md").write_text(summary)
    (RESULTS_DIR / "fixture_validation.json").write_text(json.dumps(results, indent=2, default=list))

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
