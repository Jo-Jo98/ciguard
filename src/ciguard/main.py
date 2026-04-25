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
    engine = AnalysisEngine()
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
            print(
                f"{_DIM}[{step}/{total_steps}]{_RESET} Generating insights via {provider} ...",
                end=" ", flush=True,
            )
            step += 1
            try:
                insights = enrich_report(report, provider=provider, model=args.llm_model)
                report.llm_insights = insights
                print(f"{_GREEN}OK{_RESET}  (model: {insights.model_used})")
            except Exception as exc:
                print(f"{_YELLOW}SKIP{_RESET}  ({exc})")

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

    _print_terminal_report(report)
    return 2 if crits > 0 else (1 if highs > 0 else 0)


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
        "--input", "-i", required=True,
        help="Path to the pipeline YAML file (.gitlab-ci.yml or .github/workflows/*.yml)."
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

    args = parser.parse_args()

    if args.command == "scan":
        return cmd_scan(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
