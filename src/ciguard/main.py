"""
ciguard CLI entry point.

Usage:
  python main.py scan --input pipeline.yml --output report.html
  python main.py scan --input pipeline.yml --output report.json
  python main.py scan --input pipeline.yml --output report.pdf --format pdf
  python main.py scan --input pipeline.yml --policies policies/
  python main.py scan --input pipeline.yml  (prints summary to terminal)
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

# Allow running as `python src/main.py` from the project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from ciguard.analyzer.engine import AnalysisEngine
from ciguard.models.jenkinsfile import Jenkinsfile
from ciguard.models.pipeline import Severity
from ciguard.models.workflow import Workflow
from ciguard.parser.github_actions import GitHubActionsParser, detect_format
from ciguard.parser.gitlab_parser import GitLabCIParser
from ciguard.parser.jenkinsfile import JenkinsfileParser, looks_like_jenkinsfile
from ciguard.policy.builtin import BUILTIN_POLICIES
from ciguard.policy.evaluator import PolicyEvaluator
from ciguard.policy.loader import load_policies_from_directory, load_policies_from_file
from ciguard.reporter.html_report import HTMLReporter

# ANSI colours for terminal output
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_BLUE   = "\033[94m"
_GREEN  = "\033[92m"
_CYAN   = "\033[96m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"
_RESET  = "\033[0m"

_SEV_COLOUR = {
    Severity.CRITICAL: _RED,
    Severity.HIGH:     _YELLOW,
    Severity.MEDIUM:   _BLUE,
    Severity.LOW:      _GREEN,
    Severity.INFO:     _CYAN,
}

_POLICY_SEV_COLOUR = {
    "critical": _RED,
    "high":     _YELLOW,
    "medium":   _BLUE,
    "low":      _GREEN,
}


def cmd_scan(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"{_RED}Error:{_RESET} File not found: {input_path}", file=sys.stderr)
        return 1

    if getattr(args, "no_scanners", False):
        import os
        os.environ["CIGUARD_NO_SCANNERS"] = "1"

    step = 1
    total_steps = 3
    if args.llm:
        total_steps += 1
    if args.policies:
        total_steps += 1

    # ---- Parse (auto-detect platform unless --platform overrides)
    print(f"{_DIM}[{step}/{total_steps}]{_RESET} Parsing {input_path.name} ...", end=" ", flush=True)
    step += 1
    try:
        platform = args.platform
        if platform == "auto":
            # Filename / content sniff first — Jenkinsfiles aren't YAML so we
            # can't probe them with `yaml.safe_load` without raising.
            if looks_like_jenkinsfile(input_path):
                platform = "jenkins"
            else:
                import yaml
                with open(input_path, "r", encoding="utf-8") as fh:
                    raw_peek = yaml.safe_load(fh)
                platform = (
                    detect_format(raw_peek) if isinstance(raw_peek, dict) else "gitlab-ci"
                )

        if platform == "github-actions":
            workflow = GitHubActionsParser().parse_file(input_path)
            pipeline = None
            jenkinsfile = None
            target_for_summary = workflow
        elif platform == "jenkins":
            jenkinsfile = JenkinsfileParser().parse_file(input_path)
            workflow = None
            pipeline = None
            target_for_summary = jenkinsfile
        else:
            pipeline = GitLabCIParser().parse_file(input_path)
            workflow = None
            jenkinsfile = None
            target_for_summary = pipeline
    except Exception as exc:
        print(f"{_RED}FAILED{_RESET}")
        print(f"  {exc}", file=sys.stderr)
        return 1

    if isinstance(target_for_summary, Workflow):
        print(
            f"{_GREEN}OK{_RESET}  "
            f"({len(workflow.jobs)} jobs, GitHub Actions workflow)"
        )
    elif isinstance(target_for_summary, Jenkinsfile):
        if jenkinsfile.style == "scripted-unparseable":
            print(
                f"{_YELLOW}WARN{_RESET}  "
                f"(free-form Scripted Pipeline — ciguard cannot model arbitrary "
                f"Groovy control flow; file a feature request if this matters)"
            )
        elif jenkinsfile.style == "shared-library":
            lib = jenkinsfile.shared_library_call
            print(
                f"{_YELLOW}OK{_RESET}  "
                f"(delegates to shared-library call `{lib.name}(...)` — "
                f"audit the library separately; JKN-LIB-001 will fire)"
            )
        elif jenkinsfile.style == "node-scripted":
            print(
                f"{_GREEN}OK{_RESET}  "
                f"({len(jenkinsfile.stages)} stages, Jenkins node-style Scripted Pipeline)"
            )
        else:
            print(
                f"{_GREEN}OK{_RESET}  "
                f"({len(jenkinsfile.stages)} stages, Jenkins Declarative Pipeline)"
            )
    else:
        print(
            f"{_GREEN}OK{_RESET}  "
            f"({len(pipeline.jobs)} jobs, {len(pipeline.stages)} stages, GitLab CI)"
        )

    # ---- Analyse
    print(f"{_DIM}[{step}/{total_steps}]{_RESET} Running security rules ...", end=" ", flush=True)
    step += 1
    engine = AnalysisEngine(sca_offline=getattr(args, "offline", False))
    report = engine.analyse(target_for_summary, pipeline_name=input_path.name)
    total = report.summary["total"]
    crits = report.summary["by_severity"].get("Critical", 0)
    highs = report.summary["by_severity"].get("High", 0)
    print(
        f"{_GREEN}OK{_RESET}  "
        f"({total} findings — "
        f"{_RED}{crits} Critical{_RESET}, "
        f"{_YELLOW}{highs} High{_RESET})"
    )

    # ---- Policy evaluation (optional). Built-in policies declare which
    # platforms they apply to (`platforms: ["gitlab-ci"]` or `["github-actions"]`);
    # the evaluator filters by `report.platform`, so we always pass the full
    # built-in set. User-supplied policies default to all-platforms.
    pipeline_for_policy = report.pipeline   # synthesised Pipeline for GHA path
    if args.policies:
        print(f"{_DIM}[{step}/{total_steps}]{_RESET} Evaluating policies ...", end=" ", flush=True)
        step += 1
        policies_path = Path(args.policies)
        custom_policies = []
        if policies_path.is_dir():
            custom_policies = load_policies_from_directory(policies_path)
        elif policies_path.is_file():
            custom_policies = load_policies_from_file(policies_path)
        else:
            print(f"{_YELLOW}SKIP{_RESET}  (path not found: {policies_path})")
            custom_policies = []

        all_policies = BUILTIN_POLICIES + custom_policies
        pol_evaluator = PolicyEvaluator()
        pol_report = pol_evaluator.evaluate(all_policies, pipeline_for_policy, report)
        report.policy_report = pol_report
        pc = _GREEN if pol_report.failed == 0 else _RED
        print(
            f"{_GREEN}OK{_RESET}  "
            f"({pol_report.policies_evaluated} policies — "
            f"{pc}{pol_report.failed} failed{_RESET}, "
            f"{_GREEN}{pol_report.passed} passed{_RESET})"
        )
    elif not args.no_builtin_policies:
        pol_evaluator = PolicyEvaluator()
        pol_report = pol_evaluator.evaluate(BUILTIN_POLICIES, pipeline_for_policy, report)
        report.policy_report = pol_report

    # ---- LLM enrichment (optional)
    if args.llm:
        # v0.9.1 (issue #12): require explicit --llm-consent acknowledgement
        # before sending any payload to a third-party provider. Without it,
        # error out with a one-time message naming exactly what would be sent.
        if not getattr(args, "llm_consent", False):
            print(
                f"\n{_RED}Error:{_RESET} --llm requires --llm-consent.\n"
                f"  LLM enrichment will send the following to "
                f"{args.llm_provider or 'the configured provider'}:\n"
                f"    - rule names, severities, categories\n"
                f"    - finding locations and pipeline name "
                f"({_BOLD}use --redact-locations to hash these{_RESET})\n"
                f"    - finding descriptions, remediation text, compliance mappings\n"
                f"  Evidence fields (which may contain masked credential fragments) "
                f"are always stripped.\n"
                f"\n  Re-run with --llm-consent to acknowledge, or omit --llm "
                f"to skip enrichment.",
                file=sys.stderr,
            )
            return 1

        from ciguard.llm.client import detect_provider
        from ciguard.llm.enricher import enrich_report

        provider = args.llm_provider or detect_provider()
        if not provider:
            print(
                f"\n{_YELLOW}Warning:{_RESET} --llm flag set but no API key found. "
                "Set ANTHROPIC_API_KEY or OPENAI_API_KEY.",
                file=sys.stderr,
            )
        else:
            redact = getattr(args, "redact_locations", False)
            redact_label = " [redacted locations]" if redact else ""
            print(
                f"{_DIM}[{step}/{total_steps}]{_RESET} Generating insights via "
                f"{provider}{redact_label} ...",
                end=" ", flush=True,
            )
            step += 1
            try:
                insights = enrich_report(
                    report,
                    provider=provider,
                    model=args.llm_model,
                    redact_locations=redact,
                )
                report.llm_insights = insights
                print(f"{_GREEN}OK{_RESET}  (model: {insights.model_used})")
            except Exception as exc:
                print(f"{_YELLOW}SKIP{_RESET}  ({exc})")

    # ---- Apply .ciguardignore suppressions (v0.7) — runs before baseline
    # diff so suppressed findings don't show up as "new" against an old
    # baseline that pre-dated the suppression. Suppressed findings are
    # preserved on `report.suppressed` for audit, but removed from
    # `report.findings` so all downstream logic (severity counts, exit
    # codes, baseline comparison, reporters) treats them as resolved.
    if not getattr(args, "no_ignore_file", False):
        from ciguard.ignore import (
            apply_ignores,
            discover_ignore_file,
            load_ignore_file,
        )

        ignore_path: Optional[Path] = None
        if args.ignore_file:
            ignore_path = Path(args.ignore_file)
            if not ignore_path.exists():
                print(
                    f"  {_YELLOW}Warning:{_RESET} --ignore-file {ignore_path} "
                    f"does not exist; continuing without suppressions.",
                    file=sys.stderr,
                )
                ignore_path = None
        else:
            ignore_path = discover_ignore_file(input_path)

        if ignore_path is not None:
            try:
                load_result = load_ignore_file(ignore_path)
            except ValueError as exc:
                print(f"  {_RED}Error:{_RESET} {exc}", file=sys.stderr)
                return 1
            if load_result.rules:
                kept, suppressed, expired_warnings = apply_ignores(
                    report.findings, load_result.rules
                )
                report.findings = kept
                report.suppressed = suppressed
                report.ignore_warnings = expired_warnings
                report.ignore_file_path = str(ignore_path)
                # Recompute summary + risk score so the post-suppression
                # posture is reflected in terminal output, exit code, and
                # baseline diff. Reuses the same engine instance for SCA
                # client + flag consistency.
                report.summary = engine._build_summary(report.findings)
                report.risk_score = engine._calculate_risk(report.findings)
                if suppressed:
                    print(
                        f"  {_DIM}↓{_RESET} {len(suppressed)} finding"
                        f"{'s' if len(suppressed) != 1 else ''} suppressed by "
                        f"{ignore_path.name}"
                    )
                for w in expired_warnings:
                    print(f"  {_YELLOW}Warning:{_RESET} {w}", file=sys.stderr)

    # ---- Baseline diff (v0.5)
    baseline_path: Optional[Path] = None
    if args.baseline:
        baseline_path = Path(args.baseline)
    elif args.update_baseline:
        # User asked to write the baseline but didn't say where — use default.
        from ciguard.analyzer.baseline import default_baseline_path
        baseline_path = default_baseline_path(input_path)

    if args.baseline and baseline_path is not None:
        from ciguard.analyzer.baseline import compute_delta, load_baseline
        if baseline_path.exists():
            try:
                baseline_data = load_baseline(baseline_path)
                report.delta = compute_delta(report, baseline_data, baseline_path)
                d = report.delta
                delta_colour = _RED if d.has_regressions else _GREEN
                print(
                    f"  {_DIM}Δ{_RESET} {delta_colour}{len(d.new)} new{_RESET}, "
                    f"{_GREEN}{len(d.resolved)} resolved{_RESET}, "
                    f"{_DIM}{len(d.unchanged)} unchanged{_RESET}  "
                    f"(baseline: {baseline_path.name})"
                )
            except Exception as exc:
                print(
                    f"  {_YELLOW}Warning:{_RESET} could not read baseline at "
                    f"{baseline_path}: {exc}",
                    file=sys.stderr,
                )
        else:
            print(
                f"  {_YELLOW}Warning:{_RESET} --baseline {baseline_path} does not "
                f"exist yet. Run `ciguard baseline -i {input_path}` to seed it, "
                f"or use --update-baseline to write one from this scan.",
                file=sys.stderr,
            )

    # ---- Write report
    output = args.output
    fmt    = (getattr(args, "format", None) or "").lower()
    print(f"{_DIM}[{step}/{total_steps}]{_RESET} Writing report ...", end=" ", flush=True)

    if output is None:
        print("\n")
        _print_terminal_report(report)
        return 2 if crits > 0 else (1 if highs > 0 else 0)

    output_path = Path(output)
    suffix = output_path.suffix.lower()

    # Determine format: explicit --format overrides suffix
    if fmt == "pdf" or suffix == ".pdf":
        try:
            from ciguard.reporter.pdf_report import PDFReporter
            PDFReporter().write(report, output_path)
            print(f"{_GREEN}OK{_RESET}  → {output_path}")
        except ImportError as exc:
            print(f"{_RED}FAILED{_RESET}")
            print(f"  PDF requires reportlab: pip install reportlab\n  {exc}", file=sys.stderr)
            return 1
    elif suffix == ".html" or fmt == "html":
        reporter = HTMLReporter()
        reporter.write(report, output_path)
        print(f"{_GREEN}OK{_RESET}  → {output_path}")
    elif suffix == ".json" or fmt == "json":
        from ciguard.reporter.json_report import JSONReporter
        JSONReporter().write(report, output_path)
        print(f"{_GREEN}OK{_RESET}  → {output_path}")
    elif suffix == ".sarif" or fmt == "sarif":
        from ciguard.reporter.sarif_report import SARIFReporter
        SARIFReporter().write(report, output_path)
        print(f"{_GREEN}OK{_RESET}  → {output_path}")
    else:
        print(f"{_RED}FAILED{_RESET}")
        print(f"  Unknown format {suffix!r}. Use .html, .json, .pdf, or .sarif", file=sys.stderr)
        return 1

    # ---- Update baseline if requested (v0.5)
    if args.update_baseline and baseline_path is not None:
        from ciguard.analyzer.baseline import write_baseline
        write_baseline(report, baseline_path)
        print(f"  {_DIM}Baseline updated: {baseline_path}{_RESET}")

    _print_terminal_report(report)

    # ---- Exit code
    # --fail-on-new (v0.5) overrides the default severity-based exit logic
    # when set. Designed for CI: a clean delta = exit 0 even if absolute
    # findings exist, because they were already in the baseline.
    if args.fail_on_new is not None:
        if args.fail_on_new == "none":
            return 0
        if report.delta is None:
            print(
                f"\n{_YELLOW}Warning:{_RESET} --fail-on-new requires a readable "
                f"baseline; exit code will fall back to default severity logic.",
                file=sys.stderr,
            )
        else:
            from ciguard.models.pipeline import Severity
            threshold = Severity(args.fail_on_new)
            new_above = report.delta.new_at_or_above(threshold)
            return 1 if new_above else 0

    final_crits = report.summary["by_severity"].get("Critical", 0)
    final_highs = report.summary["by_severity"].get("High", 0)
    return 2 if final_crits > 0 else (1 if final_highs > 0 else 0)


def cmd_baseline(args: argparse.Namespace) -> int:
    """Run a scan and write its findings as a baseline JSON file.
    Lighter than `cmd_scan` — no policies, no LLM, no terminal report,
    no other output. Just: parse → analyse → write baseline."""
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"{_RED}Error:{_RESET} File not found: {input_path}", file=sys.stderr)
        return 1

    print(f"{_DIM}[1/3]{_RESET} Parsing {input_path.name} ...", end=" ", flush=True)
    try:
        platform = args.platform
        if platform == "auto":
            if looks_like_jenkinsfile(input_path):
                platform = "jenkins"
            else:
                import yaml
                with open(input_path, "r", encoding="utf-8") as fh:
                    raw_peek = yaml.safe_load(fh)
                platform = (
                    detect_format(raw_peek) if isinstance(raw_peek, dict) else "gitlab-ci"
                )
        if platform == "github-actions":
            target = GitHubActionsParser().parse_file(input_path)
        elif platform == "jenkins":
            target = JenkinsfileParser().parse_file(input_path)
        else:
            target = GitLabCIParser().parse_file(input_path)
    except Exception as exc:
        print(f"{_RED}FAILED{_RESET}")
        print(f"  {exc}", file=sys.stderr)
        return 1
    print(f"{_GREEN}OK{_RESET}")

    print(f"{_DIM}[2/3]{_RESET} Running security rules ...", end=" ", flush=True)
    report = AnalysisEngine().analyse(target, pipeline_name=input_path.name)
    print(f"{_GREEN}OK{_RESET}  ({report.summary['total']} findings captured)")

    print(f"{_DIM}[3/3]{_RESET} Writing baseline ...", end=" ", flush=True)
    from ciguard.analyzer.baseline import default_baseline_path, write_baseline
    out_path = Path(args.output) if args.output else default_baseline_path(input_path)
    write_baseline(report, out_path)
    print(f"{_GREEN}OK{_RESET}  → {out_path}")
    print(
        f"\n  Baseline written. Use `ciguard scan -i {input_path} "
        f"--baseline {out_path}` on subsequent runs to see the delta."
    )
    return 0


def cmd_scan_repo(args: argparse.Namespace) -> int:
    """Discover and scan every pipeline file under a directory tree.

    Slice 9 / v0.9.0. Wraps `repo_scan.scan_repo` with a terminal table,
    aggregate severity summary, optional JSON output (`--output`), and
    `--fail-on` threshold gating. Exit code:
      0 — clean (or `--fail-on` not breached)
      1 — `--fail-on` breached
      2 — bad arguments / scan path missing
    """
    from ciguard.repo_scan import scan_repo

    repo_path = Path(args.repo_path)
    if not repo_path.exists():
        print(f"{_RED}Error:{_RESET} Path not found: {repo_path}", file=sys.stderr)
        return 2

    if getattr(args, "no_scanners", False):
        import os
        os.environ["CIGUARD_NO_SCANNERS"] = "1"

    print(f"{_DIM}Scanning {repo_path} ...{_RESET}", flush=True)
    result = scan_repo(
        repo_path,
        offline=args.offline,
        fail_on=(None if args.fail_on == "none" else args.fail_on),
        no_ignore_file=args.no_ignore_file,
    )

    if "error" in result:
        print(f"{_RED}Error:{_RESET} {result['error']}", file=sys.stderr)
        return 2

    files = result["files"]
    if not files:
        print(f"{_YELLOW}No pipeline files discovered under {repo_path}.{_RESET}")
        print(f"  {_DIM}Discovery looks for .gitlab-ci.yml, .github/workflows/*.yml, "
              f"Jenkinsfile, *.jenkinsfile, and *.groovy with pipeline markers.{_RESET}")
        # Still write an empty result if --output was given
        if args.output:
            _write_repo_scan_output(args.output, result)
        return 0

    grade_colours = {"A": _GREEN, "B": _CYAN, "C": _YELLOW, "D": _YELLOW, "F": _RED}
    print(f"\n{_BOLD}{'=' * 78}{_RESET}")
    print(f"{_BOLD}  ciguard Repo Scan — {repo_path}{_RESET}")
    print(f"{'=' * 78}")
    print(f"  {result['files_scanned']} pipeline file(s) discovered\n")

    # Per-file table
    print(f"  {_BOLD}{'Path':<46} {'Platform':<14} {'Grade':<8} {'Findings':>9}{_RESET}")
    print(f"  {'─' * 76}")
    for f in files:
        path = f["path"]
        if len(path) > 44:
            path = "…" + path[-43:]
        if "error" in f:
            print(f"  {path:<46} {f['platform']:<14} {_RED}{'ERR':<8}{_RESET} "
                  f"{_DIM}{f['error'][:30]}{_RESET}")
            continue
        gc = grade_colours.get(f["grade"], _RESET)
        grade_label = f"{f['grade']} {f['score']:.0f}"
        print(f"  {path:<46} {f['platform']:<14} {gc}{grade_label:<8}{_RESET} "
              f"{f['findings_total']:>9}")

    # Aggregate
    print(f"\n  {_BOLD}Aggregate findings: {result['total_findings']}{_RESET}")
    by_sev = result["by_severity"]
    bits = []
    for sev_name in ["Critical", "High", "Medium", "Low", "Info"]:
        count = by_sev.get(sev_name, 0)
        if count > 0:
            sev_enum = Severity(sev_name)
            colour = _SEV_COLOUR[sev_enum]
            bits.append(f"{colour}{sev_name} {count}{_RESET}")
    if bits:
        print(f"  {'  '.join(bits)}")
    else:
        print(f"  {_GREEN}No findings.{_RESET}")

    # Threshold
    if args.fail_on != "none":
        if result["fails_threshold"]:
            print(f"\n  {_RED}{_BOLD}FAIL{_RESET}  threshold `--fail-on={args.fail_on}` breached.")
        else:
            print(f"\n  {_GREEN}{_BOLD}PASS{_RESET}  threshold `--fail-on={args.fail_on}` not breached.")

    if args.output:
        _write_repo_scan_output(args.output, result)
        print(f"\n  Aggregate JSON written to {args.output}")

    print()
    return 1 if (args.fail_on != "none" and result["fails_threshold"]) else 0


def _write_repo_scan_output(output_path: str, result: dict) -> None:
    import json
    Path(output_path).write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")


def _print_terminal_report(report) -> None:
    import textwrap

    score = report.risk_score
    grade_colours = {"A": _GREEN, "B": _CYAN, "C": _YELLOW, "D": _YELLOW, "F": _RED}
    gc = grade_colours.get(score.grade, _RESET)

    print(f"\n{_BOLD}{'=' * 60}{_RESET}")
    print(f"{_BOLD}  ciguard Scan Results — {report.pipeline_name}{_RESET}")
    print(f"{'=' * 60}")
    print(f"  Risk Score : {gc}{_BOLD}{score.overall}/100{_RESET}  Grade: {gc}{_BOLD}{score.grade}{_RESET}")
    print(f"{'=' * 60}\n")

    print(f"  {_BOLD}Category Scores:{_RESET}")
    cats = [
        ("Pipeline Integrity", score.pipeline_integrity),
        ("Identity & Access",  score.identity_access),
        ("Runner Security",    score.runner_security),
        ("Artifact Handling",  score.artifact_handling),
        ("Deployment Gov.",    score.deployment_governance),
        ("Supply Chain",       score.supply_chain),
    ]
    for name, s in cats:
        bar_len = int(s / 5)  # 20 chars = 100
        bar_colour = _GREEN if s >= 75 else (_YELLOW if s >= 50 else _RED)
        bar = f"{bar_colour}{'█' * bar_len}{'░' * (20 - bar_len)}{_RESET}"
        print(f"  {name:<22} {bar} {s:5.1f}/100")

    print(f"\n  {_BOLD}Findings by Severity:{_RESET}")
    for sev in Severity:
        count = report.summary["by_severity"].get(sev.value, 0)
        if count > 0:
            colour = _SEV_COLOUR[sev]
            print(f"  {colour}{sev.value:<12}{_RESET} {count}")

    if report.findings:
        print(f"\n  {_BOLD}Top Findings:{_RESET}")
        for finding in report.sorted_findings()[:10]:
            c = _SEV_COLOUR[finding.severity]
            print(f"  {c}[{finding.severity.value[:4]}]{_RESET} "
                  f"{finding.rule_id:<10} {finding.name}  "
                  f"{_DIM}({finding.location}){_RESET}")

    # Policy report summary
    if report.policy_report:
        pr = report.policy_report
        pc = _GREEN if pr.failed == 0 else _RED
        print(f"\n  {_BOLD}Policy Report  {_DIM}({pr.pass_rate:.0f}% pass rate){_RESET}")
        print(f"  {'─' * 58}")
        print(f"  {_GREEN}{pr.passed} passed{_RESET}  {pc}{pr.failed} failed{_RESET}  "
              f"({pr.policies_evaluated} total)")
        failures = [r for r in pr.results if not r.passed]
        if failures:
            print(f"\n  {_BOLD}Policy Failures:{_RESET}")
            for r in failures:
                c = _POLICY_SEV_COLOUR.get(r.policy.severity.value, _RESET)
                print(f"  {c}[{r.policy.severity.value[:4].upper()}]{_RESET} "
                      f"{r.policy.id:<10} {r.policy.name}")
                print(f"         {_DIM}{r.evidence}{_RESET}")

    if report.llm_insights:
        ins = report.llm_insights
        print(f"\n  {_BOLD}AI Insights  {_DIM}({ins.provider} / {ins.model_used}){_RESET}")
        print(f"  {'─' * 58}")
        for line in textwrap.wrap(ins.executive_summary, width=70):
            print(f"  {line}")
        if ins.developer_actions:
            print(f"\n  {_BOLD}Action Plan:{_RESET}")
            for i, action in enumerate(ins.developer_actions, 1):
                for j, line in enumerate(textwrap.wrap(action, width=66)):
                    prefix = f"  {i}. " if j == 0 else "     "
                    print(f"{prefix}{line}")

    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="ciguard",
        description="ciguard — CI/CD Pipeline Security Auditor",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan a pipeline file")
    scan_parser.add_argument(
        "--input", "-i", default=None,
        help="Path to the pipeline YAML file (.gitlab-ci.yml or .github/workflows/*.yml)."
    )
    scan_parser.add_argument(
        "files", nargs="*",
        help="Positional pipeline file path(s). When provided, --input is "
             "ignored. Multiple paths are scanned in sequence (used by the "
             "pre-commit hook entry). Exit code is the worst code across the "
             "batch (Critical > High > clean).",
    )
    scan_parser.add_argument(
        "--output", "-o", default=None,
        help="Output path for the report (.html, .json, or .pdf)."
    )
    scan_parser.add_argument(
        "--format", "-f", default=None, choices=["html", "json", "pdf", "sarif"],
        help="Output format override (html, json, pdf, sarif).",
    )
    scan_parser.add_argument(
        "--platform", "-p", default="auto",
        choices=["auto", "gitlab-ci", "github-actions", "jenkins"],
        help="Pipeline platform. `auto` (default) inspects the file to decide.",
    )
    scan_parser.add_argument(
        "--policies", default=None,
        help="Path to a YAML policy file or directory of policy files.",
    )
    scan_parser.add_argument(
        "--no-builtin-policies", action="store_true", default=False,
        help="Disable the 7 built-in policies.",
    )
    scan_parser.add_argument(
        "--llm", action="store_true",
        help="Enable LLM enrichment (requires ANTHROPIC_API_KEY or OPENAI_API_KEY).",
    )
    scan_parser.add_argument(
        "--llm-provider", choices=["anthropic", "openai"], default=None,
        help="LLM provider. Default: auto-detected from environment variables.",
    )
    scan_parser.add_argument(
        "--llm-model", default=None,
        help="Override the LLM model (e.g. claude-haiku-4-5-20251001, gpt-4o-mini).",
    )
    # ---- LLM privacy flags (v0.9.1, issue #12)
    scan_parser.add_argument(
        "--llm-consent", action="store_true", default=False,
        help="Acknowledge that --llm sends rule/location/description/compliance "
             "metadata to the third-party LLM provider. Required when --llm is "
             "set; ciguard refuses to call the LLM otherwise. Evidence fields "
             "(which may contain masked credential fragments) are always stripped.",
    )
    scan_parser.add_argument(
        "--redact-locations", action="store_true", default=False,
        help="Hash finding locations and the pipeline name before they reach "
             "the LLM provider. Insights stay rule-level actionable; only your "
             "file-system layout is concealed. Recommended for regulated workloads.",
    )
    # ---- SCA flags (v0.6)
    scan_parser.add_argument(
        "--offline", action="store_true", default=False,
        help="Disable network lookups for SCA enrichment (endoflife.date EOL "
             "data). Uses on-disk cache only. Required for air-gapped CI "
             "environments. Cache lives at `~/.ciguard/cache/` by default.",
    )

    # ---- Hardened-mode flag (v0.9.1, issue #13)
    scan_parser.add_argument(
        "--no-scanners", action="store_true", default=False,
        help="Disable all external-binary scanner integrations (Semgrep, "
             "OpenSSF Scorecard, GitLab native). Sets `CIGUARD_NO_SCANNERS=1` "
             "so any in-process caller honours it. Use alongside `--offline` "
             "for fully hardened, network-free runs. See README → Network Egress.",
    )

    # ---- .ciguardignore flags (v0.7)
    scan_parser.add_argument(
        "--ignore-file", default=None,
        help="Path to a .ciguardignore YAML file. If omitted, ciguard walks "
             "up from the input file looking for one (stops at .git or root). "
             "Every entry must include a written `reason` — naked rule-id "
             "disables are rejected by design. See the README for format.",
    )
    scan_parser.add_argument(
        "--no-ignore-file", action="store_true", default=False,
        help="Disable .ciguardignore discovery and processing entirely. "
             "Useful for verifying baseline posture without suppressions.",
    )

    # ---- Baseline / delta flags (v0.5)
    scan_parser.add_argument(
        "--baseline", default=None,
        help="Path to a baseline JSON file. Findings absent from the baseline "
             "are flagged as `new`; findings only in the baseline as `resolved`. "
             "Default location: `.ciguard/baseline.json` next to the input file.",
    )
    scan_parser.add_argument(
        "--update-baseline", action="store_true", default=False,
        help="After scanning, write the current findings as the new baseline "
             "(at the path given by --baseline, or the default location). "
             "Use this to acknowledge findings as the new accepted state.",
    )
    scan_parser.add_argument(
        "--fail-on-new", default=None,
        choices=["Critical", "High", "Medium", "Low", "Info", "none"],
        help="Exit non-zero if any *new* finding at this severity or above "
             "appears since the baseline. Requires --baseline. `none` disables "
             "all severity-based exit codes (returns 0 unless an error occurred).",
    )

    # ---- `scan-repo` subcommand (v0.9.0): walk a directory tree, scan
    # every recognised pipeline file, print a per-file table + aggregate
    # severity counts, and exit non-zero when `--fail-on` is breached.
    # Discovery foundation shipped with v0.8.x for the MCP `scan_repo`
    # tool; this slice exposes it as a first-class CLI verb.
    scan_repo_parser = subparsers.add_parser(
        "scan-repo",
        help="Auto-discover and scan every pipeline file under a directory.",
    )
    scan_repo_parser.add_argument(
        "repo_path",
        help="Path to the repository root to scan.",
    )
    scan_repo_parser.add_argument(
        "--output", "-o", default=None,
        help="Path to write the aggregate JSON result (per-file summaries + "
             "totals). Terminal report is always printed.",
    )
    scan_repo_parser.add_argument(
        "--fail-on", default="none",
        choices=["Critical", "High", "Medium", "Low", "Info", "none"],
        help="Exit non-zero (1) if any finding at this severity or above "
             "appears across the scan. `none` (default) makes the command "
             "purely informational — exit 0 unless an error occurred.",
    )
    scan_repo_parser.add_argument(
        "--offline", action="store_true", default=False,
        help="Disable SCA HTTP lookups (endoflife.date, OSV.dev). Uses the "
             "on-disk cache only — required for air-gapped CI runners.",
    )
    scan_repo_parser.add_argument(
        "--no-scanners", action="store_true", default=False,
        help="Disable external-binary scanner integrations (Semgrep, "
             "Scorecard, GitLab native). Sets CIGUARD_NO_SCANNERS=1.",
    )
    scan_repo_parser.add_argument(
        "--no-ignore-file", action="store_true", default=False,
        help="Disable .ciguardignore discovery and processing. Useful for "
             "verifying baseline posture without per-file suppressions.",
    )

    # ---- `mcp` subcommand (v0.8.0): launch the MCP stdio server. No CLI
    # output (would corrupt the stdio protocol). Requires the optional
    # `mcp` extra: `pip install 'ciguard[mcp]'`. Exits non-zero with a
    # clear message if the extra isn't installed.
    mcp_parser = subparsers.add_parser(
        "mcp",
        help="Launch the ciguard Model Context Protocol server (stdio "
             "transport). Exposes scan / scan_repo / explain_rule / "
             "diff_baseline / list_rules tools to MCP-compatible AI "
             "clients (Claude Desktop, Claude Code, Cursor). "
             "Requires `pip install 'ciguard[mcp]'`.",
    )
    # No flags currently — stdio is the only supported transport. Future
    # SSE / HTTP transports would add flags here.
    del mcp_parser  # silence unused; argparse keeps a reference internally

    # ---- `baseline` subcommand: write a baseline from a fresh scan, no report.
    baseline_parser = subparsers.add_parser(
        "baseline",
        help="Run a scan and write its findings as a baseline JSON file. "
             "Use this once to seed the baseline; thereafter, `scan --baseline` "
             "diffs against it.",
    )
    baseline_parser.add_argument(
        "--input", "-i", required=True,
        help="Path to the pipeline file (.gitlab-ci.yml, .github/workflows/*.yml, or Jenkinsfile).",
    )
    baseline_parser.add_argument(
        "--output", "-o", default=None,
        help="Where to write the baseline JSON. Default: `.ciguard/baseline.json` "
             "next to the input file.",
    )
    baseline_parser.add_argument(
        "--platform", "-p", default="auto",
        choices=["auto", "gitlab-ci", "github-actions", "jenkins"],
        help="Pipeline platform. `auto` (default) inspects the file to decide.",
    )

    args = parser.parse_args()

    if args.command == "scan":
        # Positional file paths take precedence over --input. Used by the
        # pre-commit hook entry, which appends matched filenames after the
        # command. Multiple paths → sequential scans, worst exit code wins.
        files = list(getattr(args, "files", []) or [])
        if files:
            worst_rc = 0
            for path in files:
                args.input = path
                rc = cmd_scan(args)
                if rc > worst_rc:
                    worst_rc = rc
            return worst_rc
        if args.input is None:
            print(
                f"{_RED}Error:{_RESET} `ciguard scan` requires --input or a "
                "positional file path.",
                file=sys.stderr,
            )
            return 1
        return cmd_scan(args)
    elif args.command == "scan-repo":
        return cmd_scan_repo(args)
    elif args.command == "baseline":
        return cmd_baseline(args)
    elif args.command == "mcp":
        # Enterprise gate (v0.8.0). Sysadmins managing corporate fleets can
        # set CIGUARD_MCP_DISABLED=1 (via MDM / Group Policy / shell profile)
        # to prevent individual devs from running a local ciguard MCP server.
        # Common rationale: the org standardises on a centralised MCP
        # gateway that proxies, audits, and authorises tool traffic — local
        # MCP servers would bypass that control plane.
        import os
        disabled_raw = os.environ.get("CIGUARD_MCP_DISABLED", "").strip().lower()
        if disabled_raw in {"1", "true", "yes", "on"}:
            print(
                f"{_RED}Error:{_RESET} ciguard MCP server is disabled by "
                "policy (CIGUARD_MCP_DISABLED is set in this environment).",
                file=sys.stderr,
            )
            print(
                f"  {_DIM}Contact your administrator if you need MCP access. "
                f"This typically means the org has standardised on a "
                f"centralised MCP gateway.{_RESET}",
                file=sys.stderr,
            )
            return 2
        try:
            from ciguard.mcp.server import run_stdio
        except ImportError as exc:
            print(
                f"{_RED}Error:{_RESET} MCP support requires the optional "
                "extra. Install with: pip install 'ciguard[mcp]'",
                file=sys.stderr,
            )
            print(f"  {exc}", file=sys.stderr)
            return 1
        run_stdio()
        return 0
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
