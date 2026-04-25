"""
Jenkins corpus validator (v0.4.x).

Pulls real-world `Jenkinsfile`s from public GitHub-hosted projects, runs the
ciguard Jenkinsfile parser + analyser against each, and writes a markdown
summary to `tests/corpus_results/JENKINS_SUMMARY.md`. Per-pipeline JSON is also
written for follow-up triage.

Run from the project root with the project venv:
    ./venv/bin/python scripts/validate_jenkins_corpus.py
    ./venv/bin/python scripts/validate_jenkins_corpus.py --refresh   # re-fetch
    ./venv/bin/python scripts/validate_jenkins_corpus.py --extra owner/repo@main:Jenkinsfile

GitHub raw URL format:
    https://raw.githubusercontent.com/<owner>/<repo>/<ref>/<path>

No auth needed for public repos. We try `main` then `master` if no ref is
given. Path defaults to `Jenkinsfile`. Fetch / parse / analyse failures are
reported in the summary; they are signal, not script bugs.

Scripted Pipelines (no top-level `pipeline {}` block) are flagged separately —
they are out of scope for v0.4 and surface as `is_scripted=True` from the
parser. Track the ratio so we know how big the gap is.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ciguard.analyzer.engine import AnalysisEngine
from ciguard.models.pipeline import Severity
from ciguard.parser.jenkinsfile import JenkinsfileParser

CORPUS_DIR = ROOT / "tests" / "corpus_jenkins"
RESULTS_DIR = ROOT / "tests" / "corpus_results"

# Curated seed list. Each entry: "<owner>/<repo>[@<ref>][:<path>]"
# ref defaults to main->master fallback. path defaults to Jenkinsfile.
# Mix of substantive Declarative Pipelines (Jenkins core, BlueOcean, CasC)
# and large open-source projects that publish Jenkinsfiles publicly. Apache
# projects use GitHub mirrors that match gitbox.
SEED_PROJECTS = [
    "jenkinsci/jenkins",                                # Jenkins core itself
    "jenkinsci/configuration-as-code-plugin",
    "jenkinsci/blueocean-plugin",
    "jenkinsci/pipeline-model-definition-plugin",
    "jenkinsci/git-plugin",
    "jenkinsci/credentials-plugin",
    "jenkinsci/junit-plugin",
    "jenkinsci/workflow-cps-plugin",
    "jenkinsci/sshd-plugin",
    "jenkinsci/docker",                                 # official Jenkins images
    "jenkinsci/docker-inbound-agent",
    "jenkinsci/docker-agent",
    "jenkinsci/plugin-installation-manager-tool",
    "apache/maven",
    "apache/groovy",
    "apache/karaf",
    "apache/cassandra",
    "apache/incubator-pekko",
    "AdoptOpenJDK/openjdk-build",
    "eclipse-jgit/jgit",
]

GITHUB_RAW = "https://raw.githubusercontent.com/{slug}/{ref}/{path}"
USER_AGENT = "ciguard-jenkins-corpus-validator/1.0 (research; static analysis only)"
FETCH_TIMEOUT = 15


@dataclass
class Result:
    slug: str
    ref: Optional[str] = None
    path: str = "Jenkinsfile"
    fetch_ok: bool = False
    fetch_error: str = ""
    bytes: int = 0
    parse_ok: bool = False
    parse_error: str = ""
    parse_warnings: list[str] = field(default_factory=list)
    style: str = "declarative"           # declarative | node-scripted | shared-library | scripted-unparseable
    is_scripted: bool = False            # legacy: True only when style == "scripted-unparseable"
    analyse_ok: bool = False
    analyse_error: str = ""
    duration_ms: float = 0.0
    stage_count: int = 0
    finding_counts: Counter = field(default_factory=Counter)
    score: Optional[float] = None
    grade: Optional[str] = None


def parse_entry(entry: str) -> tuple[str, Optional[str], str]:
    slug = entry
    ref: Optional[str] = None
    path = "Jenkinsfile"
    if "@" in slug:
        slug, rest = slug.split("@", 1)
        if ":" in rest:
            ref, path = rest.split(":", 1)
        else:
            ref = rest
    elif ":" in slug:
        slug, path = slug.split(":", 1)
    return slug, ref, path


def safe_filename(slug: str, path: str) -> str:
    suffix = "" if path == "Jenkinsfile" else "__" + path.replace("/", "_")
    return slug.replace("/", "__") + suffix + ".Jenkinsfile"


def fetch(slug: str, ref: Optional[str], path: str, refresh: bool) -> tuple[Path, str, str]:
    """Returns (file_path, ref_used, error). error is "" on success."""
    out_path = CORPUS_DIR / safe_filename(slug, path)
    if out_path.exists() and not refresh:
        return out_path, ref or "cached", ""

    refs_to_try = [ref] if ref else ["main", "master"]
    last_err = ""
    for r in refs_to_try:
        url = GITHUB_RAW.format(slug=slug, ref=r, path=path)
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
                data = resp.read()
            out_path.write_bytes(data)
            return out_path, r, ""
        except urllib.error.HTTPError as e:
            last_err = f"HTTP {e.code} on ref={r}"
        except urllib.error.URLError as e:
            last_err = f"URL error on ref={r}: {e.reason}"
        except Exception as e:  # noqa: BLE001
            last_err = f"{type(e).__name__} on ref={r}: {e}"
    return out_path, "", last_err


def scan_one(slug: str, ref: Optional[str], path: str, refresh: bool) -> Result:
    r = Result(slug=slug, ref=ref, path=path)
    file_path, ref_used, fetch_err = fetch(slug, ref, path, refresh)
    if fetch_err:
        r.fetch_error = fetch_err
        return r
    r.fetch_ok = True
    r.ref = ref_used
    r.bytes = file_path.stat().st_size

    parser = JenkinsfileParser()
    engine = AnalysisEngine()
    t0 = time.perf_counter()
    try:
        jfile = parser.parse_file(file_path)
        r.parse_ok = True
        r.style = jfile.style
        r.is_scripted = jfile.is_scripted
        r.parse_warnings = list(jfile.parse_warnings)
        # Count every stage including parallel children — the model has no
        # built-in walker for this so we inline one.
        def _count(stage) -> int:
            return 1 + sum(_count(s) for s in stage.parallel_stages)
        r.stage_count = sum(_count(s) for s in jfile.stages)
    except Exception as e:  # noqa: BLE001
        r.parse_error = f"{type(e).__name__}: {e}"
        r.duration_ms = (time.perf_counter() - t0) * 1000
        return r

    if r.is_scripted:
        # Out of scope for v0.4 — engine would produce nothing useful.
        r.analyse_ok = True
        r.duration_ms = (time.perf_counter() - t0) * 1000
        return r

    try:
        report = engine.analyse(jfile, pipeline_name=slug)
        for sev in Severity:
            r.finding_counts[sev.value] = len(report.findings_by_severity(sev))
        if report.risk_score is not None:
            r.score = round(report.risk_score.overall, 1)
            r.grade = report.risk_score.grade
        r.analyse_ok = True
    except Exception as e:  # noqa: BLE001
        r.analyse_error = f"{type(e).__name__}: {e}"
    r.duration_ms = (time.perf_counter() - t0) * 1000
    return r


def write_summary(results: list[Result]) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    md = RESULTS_DIR / "JENKINS_SUMMARY.md"
    json_out = RESULTS_DIR / "jenkins_results.json"

    fetched = [r for r in results if r.fetch_ok]
    parsed = [r for r in fetched if r.parse_ok]
    by_style: dict[str, list[Result]] = {
        "declarative": [],
        "node-scripted": [],
        "shared-library": [],
        "scripted-unparseable": [],
    }
    for r in parsed:
        by_style.setdefault(r.style, []).append(r)
    in_scope = [r for r in parsed if r.style != "scripted-unparseable"]
    out_of_scope = by_style["scripted-unparseable"]
    analysed = [r for r in in_scope if r.analyse_ok]
    durations = [r.duration_ms for r in in_scope if r.duration_ms]

    lines = []
    lines.append("# ciguard — Jenkins Corpus Validation\n")
    lines.append(f"Run timestamp (UTC): {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())}\n")
    lines.append("\n## Aggregate\n")
    lines.append(f"- Projects attempted: **{len(results)}**")
    lines.append(f"- Fetched OK: **{len(fetched)}**  (failed: {len(results) - len(fetched)})")
    lines.append(f"- Parsed OK: **{len(parsed)}** of {len(fetched)} fetched")
    lines.append(
        f"- By shape: declarative={len(by_style['declarative'])}, "
        f"node-scripted={len(by_style['node-scripted'])}, "
        f"shared-library={len(by_style['shared-library'])}, "
        f"scripted-unparseable={len(out_of_scope)}"
    )
    lines.append(f"- In scope (parsed + analysed): **{len(in_scope)}** / Out of scope: **{len(out_of_scope)}**")
    lines.append(f"- Analysed OK: **{len(analysed)}** of {len(in_scope)} in-scope")
    if durations:
        lines.append(
            f"- Parse + analyse time per pipeline: "
            f"min {min(durations):.1f} ms / mean {sum(durations)/len(durations):.1f} ms / "
            f"max {max(durations):.1f} ms"
        )
    if analysed:
        total = Counter()
        for r in analysed:
            total.update(r.finding_counts)
        lines.append(
            "- Total findings across in-scope corpus: "
            + ", ".join(f"{sev}={total[sev]}" for sev in ["Critical", "High", "Medium", "Low", "Info"])
        )

    lines.append("\n## Per-project\n")
    lines.append("| Project | Ref | KB | Style | Stages | Crit | High | Med | Low | Info | Score | Grade | ms | Status |")
    lines.append("|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|:-:|---:|---|")
    for r in results:
        if not r.fetch_ok:
            status = f"FETCH: {r.fetch_error}"
            lines.append(f"| `{r.slug}` | – | – | – | – | – | – | – | – | – | – | – | – | {status} |")
            continue
        if not r.parse_ok:
            status = f"PARSE: {r.parse_error}"
            lines.append(
                f"| `{r.slug}` | {r.ref} | {r.bytes/1024:.1f} | – | – | – | – | – | – | – | – | – | "
                f"{r.duration_ms:.1f} | {status} |"
            )
            continue
        if r.style == "scripted-unparseable":
            status = "SCRIPTED-UNPARSEABLE (free-form Groovy out of scope)"
            lines.append(
                f"| `{r.slug}` | {r.ref} | {r.bytes/1024:.1f} | {r.style} | – | – | – | – | – | – | – | – | "
                f"{r.duration_ms:.1f} | {status} |"
            )
            continue
        if not r.analyse_ok:
            status = f"ANALYSE: {r.analyse_error}"
        else:
            status = "ok"
        lines.append(
            f"| `{r.slug}` | {r.ref} | {r.bytes/1024:.1f} | {r.style} | {r.stage_count} | "
            f"{r.finding_counts['Critical']} | {r.finding_counts['High']} | "
            f"{r.finding_counts['Medium']} | {r.finding_counts['Low']} | "
            f"{r.finding_counts['Info']} | "
            f"{r.score if r.score is not None else '–'} | "
            f"{r.grade or '–'} | {r.duration_ms:.1f} | {status} |"
        )

    lines.append("\n## Notes\n")
    lines.append(
        "- ciguard handles four Jenkinsfile shapes (v0.4.1+): **declarative**, **node-scripted** "
        "(top-level `node {}` blocks), **shared-library** (single `buildPlugin(...)`-style call → "
        "JKN-LIB-001 Info), and **scripted-unparseable** (free-form Groovy with `def` / control "
        "flow / multiple statements — out of scope, the engine produces an empty report)."
    )
    lines.append(
        "- Parse failures on real-world Jenkinsfiles are *signal*: each one points to a Groovy "
        "construct the hand-rolled parser does not yet handle. Worth investigating before adding "
        "more rules."
    )
    lines.append(
        "- An in-scope pipeline reporting 0 findings is *informational*: the project may be well-"
        "secured, or the rules don't cover the relevant surface yet. Spot-check by hand for "
        "calibration."
    )
    lines.append(
        "- Findings counts are NOT validated against ground truth here. This run measures *coverage* "
        "and *parser stability* across real-world inputs; precision/recall is measured against "
        "labelled fixtures by `scripts/validate_fixtures.py`."
    )

    md.write_text("\n".join(lines) + "\n")
    json_out.write_text(json.dumps(
        [{
            "slug": r.slug, "ref": r.ref, "path": r.path,
            "fetch_ok": r.fetch_ok, "fetch_error": r.fetch_error, "bytes": r.bytes,
            "parse_ok": r.parse_ok, "parse_error": r.parse_error,
            "parse_warnings": r.parse_warnings, "style": r.style,
            "is_scripted": r.is_scripted,
            "analyse_ok": r.analyse_ok, "analyse_error": r.analyse_error,
            "duration_ms": round(r.duration_ms, 2),
            "stage_count": r.stage_count,
            "finding_counts": dict(r.finding_counts),
            "score": r.score, "grade": r.grade,
        } for r in results],
        indent=2,
    ))
    return md


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate ciguard against real-world public Jenkinsfiles")
    ap.add_argument("--refresh", action="store_true", help="Re-fetch Jenkinsfiles even if cached locally")
    ap.add_argument("--extra", action="append", default=[], help="Extra entries: <owner>/<repo>[@ref][:path]")
    ap.add_argument("--only", action="append", default=[], help="Only scan these slugs (substring match)")
    args = ap.parse_args()

    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    targets = SEED_PROJECTS + args.extra
    if args.only:
        targets = [t for t in targets if any(o in t for o in args.only)]

    results: list[Result] = []
    for entry in targets:
        slug, ref, path = parse_entry(entry)
        print(f"  → {slug} ({ref or 'main/master'})", flush=True)
        results.append(scan_one(slug, ref, path, args.refresh))

    md = write_summary(results)
    fetched = sum(1 for r in results if r.fetch_ok)
    parsed = sum(1 for r in results if r.parse_ok)
    in_scope = sum(1 for r in results if r.parse_ok and r.style != "scripted-unparseable")
    analysed = sum(1 for r in results if r.analyse_ok and r.style != "scripted-unparseable")
    by_style: Counter = Counter(r.style for r in results if r.parse_ok)
    print(f"\nDone. {fetched}/{len(results)} fetched, {parsed} parsed, "
          f"{in_scope} in-scope, {analysed} analysed.")
    print(f"Shapes: {dict(by_style)}")
    print(f"Summary: {md}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
