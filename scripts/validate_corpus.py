"""
Phase A corpus validator.

Pulls real-world `.gitlab-ci.yml` files from public GitLab projects, runs the
ciguard parser + analyser against each, and writes a markdown summary to
`tests/corpus_results/SUMMARY.md`. Per-pipeline JSON is also written for
follow-up triage.

Run from the project root with the project venv:
    ./venv/bin/python scripts/validate_corpus.py
    ./venv/bin/python scripts/validate_corpus.py --refresh   # re-fetch YAMLs
    ./venv/bin/python scripts/validate_corpus.py --extra org/proj@main:.gitlab-ci.yml

GitLab raw URL format:
    https://gitlab.com/<group>/<project>/-/raw/<ref>/<path>

No auth is needed for public projects. We try `main` then `master` if no ref
is specified. Fetch failures and parse failures are reported in the summary;
they are signal, not bugs to fix in this script.
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
from ciguard.parser.gitlab_parser import GitLabCIParser

CORPUS_DIR = ROOT / "tests" / "corpus"
RESULTS_DIR = ROOT / "tests" / "corpus_results"

# Curated seed list. Each entry: "<group>/<project>[@<ref>][:<path>]"
# ref defaults to main->master fallback. path defaults to .gitlab-ci.yml.
# This is a starter set; URLs may break as upstream projects evolve.
SEED_PROJECTS = [
    "gitlab-org/gitlab",                         # the GitLab project itself
    "gitlab-org/gitlab-runner",
    "gitlab-org/cli",
    "gitlab-org/gitlab-foss",
    "gitlab-org/release-cli",
    "gitlab-org/security-products/gemnasium-db",
    "gnome/glib",
    "gnome/gtk",
    "inkscape/inkscape",
    "meltano/meltano",
    "veloren/veloren",
    "fdroid/fdroidclient",
    "wireshark/wireshark",
    "postmarketos/pmaports",
    "thorium/thorium",
    "tezos/tezos",
    "kicad/code/kicad",
    "freedesktop-sdk/freedesktop-sdk",
    "BuildStream/buildstream",
    "graphviz/graphviz",
]

GITLAB_RAW = "https://gitlab.com/{slug}/-/raw/{ref}/{path}"
USER_AGENT = "ciguard-corpus-validator/1.0 (research; static analysis only)"
FETCH_TIMEOUT = 15


@dataclass
class Result:
    slug: str
    ref: Optional[str] = None
    path: str = ".gitlab-ci.yml"
    fetch_ok: bool = False
    fetch_error: str = ""
    bytes: int = 0
    parse_ok: bool = False
    parse_error: str = ""
    analyse_ok: bool = False
    analyse_error: str = ""
    duration_ms: float = 0.0
    job_count: int = 0
    finding_counts: Counter = field(default_factory=Counter)
    score: Optional[float] = None
    grade: Optional[str] = None


def parse_entry(entry: str) -> tuple[str, Optional[str], str]:
    slug = entry
    ref: Optional[str] = None
    path = ".gitlab-ci.yml"
    if "@" in slug:
        slug, rest = slug.split("@", 1)
        if ":" in rest:
            ref, path = rest.split(":", 1)
        else:
            ref = rest
    elif ":" in slug:
        slug, path = slug.split(":", 1)
    return slug, ref, path


def safe_filename(slug: str) -> str:
    return slug.replace("/", "__") + ".yml"


def fetch(slug: str, ref: Optional[str], path: str, refresh: bool) -> tuple[Path, str, str]:
    """Returns (file_path, ref_used, error). error is "" on success."""
    out_path = CORPUS_DIR / safe_filename(slug)
    if out_path.exists() and not refresh:
        return out_path, ref or "cached", ""

    refs_to_try = [ref] if ref else ["main", "master"]
    last_err = ""
    for r in refs_to_try:
        url = GITLAB_RAW.format(slug=slug, ref=r, path=path)
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

    parser = GitLabCIParser()
    engine = AnalysisEngine()
    t0 = time.perf_counter()
    try:
        pipeline = parser.parse_file(file_path)
        r.parse_ok = True
        r.job_count = len(pipeline.jobs)
    except Exception as e:  # noqa: BLE001
        r.parse_error = f"{type(e).__name__}: {e}"
        r.duration_ms = (time.perf_counter() - t0) * 1000
        return r
    try:
        report = engine.analyse(pipeline, pipeline_name=slug)
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
    md = RESULTS_DIR / "SUMMARY.md"
    json_out = RESULTS_DIR / "results.json"

    fetched = [r for r in results if r.fetch_ok]
    parsed = [r for r in fetched if r.parse_ok]
    analysed = [r for r in parsed if r.analyse_ok]
    durations = [r.duration_ms for r in analysed]

    lines = []
    lines.append("# ciguard — Phase A Corpus Validation\n")
    lines.append(f"Run timestamp (UTC): {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())}\n")
    lines.append("\n## Aggregate\n")
    lines.append(f"- Projects attempted: **{len(results)}**")
    lines.append(f"- Fetched OK: **{len(fetched)}**  (failed: {len(results) - len(fetched)})")
    lines.append(f"- Parsed OK: **{len(parsed)}** of {len(fetched)} fetched")
    lines.append(f"- Analysed OK: **{len(analysed)}** of {len(parsed)} parsed")
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
            "- Total findings across corpus: "
            + ", ".join(f"{sev}={total[sev]}" for sev in ["Critical", "High", "Medium", "Low", "Info"])
        )

    lines.append("\n## Per-project\n")
    lines.append("| Project | Ref | KB | Jobs | Crit | High | Med | Low | Info | Score | Grade | ms | Status |")
    lines.append("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|:-:|---:|---|")
    for r in results:
        if not r.fetch_ok:
            status = f"FETCH: {r.fetch_error}"
            lines.append(f"| `{r.slug}` | – | – | – | – | – | – | – | – | – | – | – | {status} |")
            continue
        if not r.parse_ok:
            status = f"PARSE: {r.parse_error}"
            lines.append(
                f"| `{r.slug}` | {r.ref} | {r.bytes/1024:.1f} | – | – | – | – | – | – | – | – | "
                f"{r.duration_ms:.1f} | {status} |"
            )
            continue
        if not r.analyse_ok:
            status = f"ANALYSE: {r.analyse_error}"
        else:
            status = "ok"
        lines.append(
            f"| `{r.slug}` | {r.ref} | {r.bytes/1024:.1f} | {r.job_count} | "
            f"{r.finding_counts['Critical']} | {r.finding_counts['High']} | "
            f"{r.finding_counts['Medium']} | {r.finding_counts['Low']} | "
            f"{r.finding_counts['Info']} | "
            f"{r.score if r.score is not None else '–'} | "
            f"{r.grade or '–'} | {r.duration_ms:.1f} | {status} |"
        )

    lines.append("\n## Notes\n")
    lines.append(
        "- Parse failures on real-world YAMLs are *signal*: each one points to a GitLab CI "
        "construct ciguard's parser does not yet handle (anchors, complex `extends` chains, "
        "`!reference`, remote `include:`s, Mermaid blocks in comments, etc.)."
    )
    lines.append(
        "- A pipeline reporting 0 findings is suspicious — either the project is well-secured, "
        "or our rules aren't covering enough surface area. Spot-check a sample by hand."
    )
    lines.append(
        "- Findings counts here are NOT validated against ground truth. This run measures "
        "*coverage and stability* across real-world inputs; recall/precision require labelled fixtures."
    )

    md.write_text("\n".join(lines) + "\n")
    json_out.write_text(json.dumps(
        [{
            "slug": r.slug, "ref": r.ref, "path": r.path,
            "fetch_ok": r.fetch_ok, "fetch_error": r.fetch_error, "bytes": r.bytes,
            "parse_ok": r.parse_ok, "parse_error": r.parse_error,
            "analyse_ok": r.analyse_ok, "analyse_error": r.analyse_error,
            "duration_ms": round(r.duration_ms, 2),
            "job_count": r.job_count,
            "finding_counts": dict(r.finding_counts),
            "score": r.score, "grade": r.grade,
        } for r in results],
        indent=2,
    ))
    return md


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate ciguard against real-world public GitLab CI files")
    ap.add_argument("--refresh", action="store_true", help="Re-fetch YAMLs even if cached locally")
    ap.add_argument("--extra", action="append", default=[], help="Extra entries: <group>/<project>[@ref][:path]")
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
    analysed = sum(1 for r in results if r.analyse_ok)
    print(f"\nDone. {fetched}/{len(results)} fetched, {parsed} parsed, {analysed} analysed.")
    print(f"Summary: {md}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
