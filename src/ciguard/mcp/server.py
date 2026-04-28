"""
ciguard MCP server (v0.8.0).

Exposes five tools over the Model Context Protocol stdio transport:

  - ciguard.scan(file_path, platform="auto", offline=False, ignore_file=None)
        Run a scan on a single pipeline file. Returns the full Report
        as JSON (findings, risk score, summary, suppressed, etc.).

  - ciguard.scan_repo(repo_path, fail_on=None, offline=False)
        Auto-discover every pipeline file in a directory tree, scan each,
        return a per-file summary + aggregated severity counts.

  - ciguard.explain_rule(rule_id)
        Return canonical metadata for a single rule (name, severity,
        category, description, remediation, compliance mappings,
        platforms, sample evidence).

  - ciguard.diff_baseline(file_path, baseline_path)
        Run a scan and compute the v0.5 baseline delta. Returns
        new / resolved / unchanged finding lists + score delta.

  - ciguard.list_rules(platform=None, severity=None)
        Enumerate rules from the catalog, optionally filtered.

Why this matters: ciguard becomes a building block for AI agents, not just
a CLI. Claude can chain `scan + explain_rule` to produce remediation
guidance, or `scan + diff_baseline` to draft a PR description that
distinguishes new findings from pre-existing ones.

Implementation note: the MCP `Server` class doesn't strictly require any
asyncio knowledge from the caller — the SDK handles concurrency. All
five tool handlers are synchronous wrappers around ciguard's existing
in-process API.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool
    _MCP_AVAILABLE = True
except ImportError:
    _MCP_AVAILABLE = False

from ..analyzer.engine import AnalysisEngine
from ..ignore import (
    apply_ignores,
    discover_ignore_file,
    load_ignore_file,
)
from ..models.jenkinsfile import Jenkinsfile
from ..models.workflow import Workflow
from ..parser.github_actions import GitHubActionsParser, detect_format
from ..parser.gitlab_parser import GitLabCIParser
from ..parser.jenkinsfile import JenkinsfileParser, looks_like_jenkinsfile
from ..rule_catalog import get_catalog


SERVER_NAME = "ciguard"
SERVER_VERSION = "0.8.0"


# ---------------------------------------------------------------------------
# Helpers — shared parsing / scanning logic
# ---------------------------------------------------------------------------


def _detect_platform(path: Path, override: str = "auto") -> str:
    if override != "auto":
        return override
    if looks_like_jenkinsfile(path):
        return "jenkins"
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        return detect_format(raw) if isinstance(raw, dict) else "gitlab-ci"
    except Exception:
        return "gitlab-ci"


def _scan_one(
    path: Path,
    *,
    platform: str = "auto",
    offline: bool = False,
    ignore_file: Optional[Path] = None,
    no_ignore: bool = False,
):
    plat = _detect_platform(path, platform)
    if plat == "github-actions":
        target = GitHubActionsParser().parse_file(path)
    elif plat == "jenkins":
        target = JenkinsfileParser().parse_file(path)
    else:
        target = GitLabCIParser().parse_file(path)
    engine = AnalysisEngine(sca_offline=offline)
    report = engine.analyse(target, pipeline_name=path.name)

    if not no_ignore:
        ig_path = ignore_file
        if ig_path is None:
            ig_path = discover_ignore_file(path)
        if ig_path is not None and ig_path.exists():
            try:
                load_result = load_ignore_file(ig_path)
            except ValueError as exc:
                # Surface to caller — but don't crash the scan.
                report.ignore_warnings.append(str(exc))
                load_result = None
            if load_result is not None and load_result.rules:
                kept, suppressed, expired = apply_ignores(
                    report.findings, load_result.rules
                )
                report.findings = kept
                report.suppressed = suppressed
                report.ignore_warnings.extend(expired)
                report.ignore_file_path = str(ig_path)
                report.summary = engine._build_summary(report.findings)
                report.risk_score = engine._calculate_risk(report.findings)
    return report


def _report_to_dict(report) -> Dict[str, Any]:
    """Serialise a Report for return to the MCP client. Pydantic's
    `model_dump(mode='json')` handles enums, dates, and nested models
    consistently."""
    return report.model_dump(mode="json")


def _platform_for_target(target) -> str:
    if isinstance(target, Workflow):
        return "github-actions"
    if isinstance(target, Jenkinsfile):
        return "jenkins"
    return "gitlab-ci"


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


def _tool_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    file_path = Path(args["file_path"]).expanduser()
    if not file_path.exists():
        return {"error": f"File not found: {file_path}"}
    platform = args.get("platform", "auto")
    offline = bool(args.get("offline", False))
    no_ignore = bool(args.get("no_ignore_file", False))
    ignore_file = args.get("ignore_file")
    ignore_path = Path(ignore_file).expanduser() if ignore_file else None
    report = _scan_one(
        file_path,
        platform=platform,
        offline=offline,
        ignore_file=ignore_path,
        no_ignore=no_ignore,
    )
    return _report_to_dict(report)


def _tool_scan_repo(args: Dict[str, Any]) -> Dict[str, Any]:
    from ..repo_scan import scan_repo
    return scan_repo(
        Path(args["repo_path"]).expanduser(),
        offline=bool(args.get("offline", False)),
        fail_on=args.get("fail_on"),
        no_ignore_file=bool(args.get("no_ignore_file", False)),
    )


def _tool_explain_rule(args: Dict[str, Any]) -> Dict[str, Any]:
    rule_id = str(args["rule_id"]).strip()
    catalog = get_catalog()
    spec = catalog.get(rule_id)
    if spec is None:
        return {
            "error": f"Rule {rule_id!r} not found in catalog.",
            "hint": (
                "The catalog is harvested from the labelled bad fixtures at "
                "ciguard startup. Some rules (notably PIPE-004, RUN-001, "
                "DEP-002, and the SCA-* family) do not fire on those fixtures "
                "and are not yet enumerated. Use list_rules() to see what's "
                "available, or run a scan against a real pipeline that "
                "triggers the rule."
            ),
        }
    return {
        "rule_id":         spec.rule_id,
        "name":            spec.name,
        "description":     spec.description,
        "severity":        spec.severity,
        "category":        spec.category,
        "remediation":     spec.remediation,
        "compliance":      spec.compliance,
        "platforms":       spec.platforms,
        "sample_evidence": spec.sample_evidence,
        "sample_location": spec.sample_location,
    }


def _tool_diff_baseline(args: Dict[str, Any]) -> Dict[str, Any]:
    file_path = Path(args["file_path"]).expanduser()
    baseline_path = Path(args["baseline_path"]).expanduser()
    if not file_path.exists():
        return {"error": f"File not found: {file_path}"}
    if not baseline_path.exists():
        return {"error": f"Baseline not found: {baseline_path}"}

    from ..analyzer.baseline import compute_delta, load_baseline

    platform = args.get("platform", "auto")
    offline = bool(args.get("offline", False))
    report = _scan_one(file_path, platform=platform, offline=offline)
    try:
        baseline_data = load_baseline(baseline_path)
        report.delta = compute_delta(report, baseline_data, baseline_path)
    except Exception as exc:
        return {"error": f"Failed to compute delta: {exc}"}

    return {
        "file_path":     str(file_path),
        "baseline_path": str(baseline_path),
        "score_delta":   report.delta.score_delta,
        "new":           [f.model_dump(mode="json") for f in report.delta.new],
        "resolved":      [f.model_dump(mode="json") for f in report.delta.resolved],
        "unchanged_count": len(report.delta.unchanged),
        "current_total": len(report.findings),
    }


def _tool_list_rules(args: Dict[str, Any]) -> Dict[str, Any]:
    platform_filter = args.get("platform")
    severity_filter = args.get("severity")
    catalog = get_catalog()

    out: List[Dict[str, Any]] = []
    for rule_id in sorted(catalog.keys()):
        spec = catalog[rule_id]
        if platform_filter and platform_filter not in spec.platforms:
            continue
        if severity_filter and spec.severity != severity_filter:
            continue
        out.append({
            "rule_id":   spec.rule_id,
            "name":      spec.name,
            "severity":  spec.severity,
            "category":  spec.category,
            "platforms": spec.platforms,
        })

    return {
        "count": len(out),
        "filter": {
            "platform": platform_filter,
            "severity": severity_filter,
        },
        "rules": out,
    }


# ---------------------------------------------------------------------------
# Tool registry — name → (handler, schema)
# ---------------------------------------------------------------------------


_TOOL_REGISTRY = {
    "ciguard.scan": (
        _tool_scan,
        Tool(
            name="ciguard.scan",
            description=(
                "Scan a single CI/CD pipeline file (.gitlab-ci.yml, GitHub "
                "Actions workflow, or Jenkinsfile) for security misconfigurations. "
                "Returns the full Report including findings, risk score, "
                "category breakdown, suppressed findings, and policy results. "
                "Auto-detects the platform from filename + content."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Absolute or ~-relative path to the pipeline file.",
                    },
                    "platform": {
                        "type": "string",
                        "enum": ["auto", "gitlab-ci", "github-actions", "jenkins"],
                        "default": "auto",
                        "description": "Force a specific platform parser. Defaults to auto-detect.",
                    },
                    "offline": {
                        "type": "boolean",
                        "default": False,
                        "description": "Disable SCA network lookups (endoflife.date / OSV.dev). Cache-only.",
                    },
                    "ignore_file": {
                        "type": ["string", "null"],
                        "description": "Path to a .ciguardignore file. If omitted, ciguard walks up from file_path.",
                    },
                    "no_ignore_file": {
                        "type": "boolean",
                        "default": False,
                        "description": "Disable .ciguardignore discovery entirely.",
                    },
                },
                "required": ["file_path"],
            },
        ) if _MCP_AVAILABLE else None,
    ),
    "ciguard.scan_repo": (
        _tool_scan_repo,
        Tool(
            name="ciguard.scan_repo",
            description=(
                "Walk a directory tree, find every recognised pipeline file "
                "(.gitlab-ci.yml, .github/workflows/*.yml, Jenkinsfile, *.groovy "
                "with pipeline markers), scan all of them, return a per-file "
                "summary + aggregated severity counts. The right tool for "
                "monorepo / multi-platform repos."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "repo_path": {
                        "type": "string",
                        "description": "Absolute or ~-relative path to the repo root.",
                    },
                    "offline": {
                        "type": "boolean",
                        "default": False,
                        "description": "Disable SCA network lookups across all scans.",
                    },
                    "fail_on": {
                        "type": ["string", "null"],
                        "enum": ["Critical", "High", "Medium", "Low", "Info", None],
                        "description": "If any finding at this severity or above is present, fails_threshold=true.",
                    },
                    "no_ignore_file": {
                        "type": "boolean",
                        "default": False,
                        "description": "Disable .ciguardignore discovery for every file in the walk.",
                    },
                },
                "required": ["repo_path"],
            },
        ) if _MCP_AVAILABLE else None,
    ),
    "ciguard.explain_rule": (
        _tool_explain_rule,
        Tool(
            name="ciguard.explain_rule",
            description=(
                "Return canonical metadata for a single ciguard rule: full "
                "name, description, severity, category, remediation guidance, "
                "and compliance mappings (ISO 27001 / SOC 2 / NIST CSF). Use "
                "this to enrich a finding with context an LLM can reason about."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "rule_id": {
                        "type": "string",
                        "description": "e.g. PIPE-001, IAM-002, GHA-SC-001, JKN-RUN-001, SCA-EOL-001.",
                    },
                },
                "required": ["rule_id"],
            },
        ) if _MCP_AVAILABLE else None,
    ),
    "ciguard.diff_baseline": (
        _tool_diff_baseline,
        Tool(
            name="ciguard.diff_baseline",
            description=(
                "Run a scan against a pipeline file AND compare to a baseline "
                "JSON file (produced by `ciguard baseline`). Returns the "
                "fingerprint-based delta — new / resolved / unchanged-count "
                "and score change. Useful for drafting PR descriptions or "
                "answering 'what changed since last release?'."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path":     {"type": "string", "description": "Pipeline file to scan."},
                    "baseline_path": {"type": "string", "description": "Baseline JSON file to diff against."},
                    "platform":      {"type": "string", "default": "auto",
                                      "enum": ["auto", "gitlab-ci", "github-actions", "jenkins"]},
                    "offline":       {"type": "boolean", "default": False},
                },
                "required": ["file_path", "baseline_path"],
            },
        ) if _MCP_AVAILABLE else None,
    ),
    "ciguard.list_rules": (
        _tool_list_rules,
        Tool(
            name="ciguard.list_rules",
            description=(
                "Enumerate ciguard's rules from the catalog. Optionally filter "
                "by platform (gitlab-ci / github-actions / jenkins / cross-platform) "
                "or by severity (Critical / High / Medium / Low / Info). "
                "Note: catalog covers the rules that fire on labelled bad "
                "fixtures; some rules (PIPE-004, RUN-001, DEP-002, SCA-*) "
                "may not appear until they fire on a real scan."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "platform": {
                        "type": ["string", "null"],
                        "enum": ["gitlab-ci", "github-actions", "jenkins", "cross-platform", None],
                    },
                    "severity": {
                        "type": ["string", "null"],
                        "enum": ["Critical", "High", "Medium", "Low", "Info", None],
                    },
                },
            },
        ) if _MCP_AVAILABLE else None,
    ),
}


def _all_tools() -> List["Tool"]:
    return [t for (_h, t) in _TOOL_REGISTRY.values() if t is not None]


def _dispatch(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    entry = _TOOL_REGISTRY.get(name)
    if entry is None:
        return {"error": f"Unknown tool: {name}"}
    handler, _schema = entry
    try:
        return handler(args)
    except Exception as exc:
        return {"error": f"{name} raised: {type(exc).__name__}: {exc}"}


# ---------------------------------------------------------------------------
# MCP server wiring
# ---------------------------------------------------------------------------


def build_server() -> "Server":
    """Construct the MCP Server instance with all tool handlers registered.
    Importable as `ciguard.mcp.build_server` for callers that want to embed
    ciguard's MCP surface in a larger server (e.g. a multi-tool server)."""
    if not _MCP_AVAILABLE:
        raise ImportError(
            "MCP SDK is not installed. Install with: pip install 'ciguard[mcp]'"
        )

    server = Server(SERVER_NAME)

    @server.list_tools()
    async def list_tools() -> List[Tool]:
        return _all_tools()

    @server.call_tool()
    async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
        result = _dispatch(name, arguments or {})
        return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]

    return server


def run_stdio() -> None:
    """Entry point for `ciguard mcp`. Runs the server over the standard
    MCP stdio transport (which is what every desktop MCP client expects)."""
    if not _MCP_AVAILABLE:
        raise ImportError(
            "MCP SDK is not installed. Install with: pip install 'ciguard[mcp]'"
        )
    import asyncio

    async def _main() -> None:
        server = build_server()
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    asyncio.run(_main())


__all__ = [
    "SERVER_NAME",
    "SERVER_VERSION",
    "build_server",
    "run_stdio",
]
