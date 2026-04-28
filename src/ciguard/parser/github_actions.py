"""
GitHub Actions workflow parser.

Parses `.github/workflows/*.yml` files into a `Workflow` model. Mirrors
the `GitLabCIParser` API (parse_file / parse) so the analyzer / CLI /
web layers can dispatch by file format without caring about platform
specifics.

Supports the standard GHA YAML shapes:
- top-level `on:` as string, list, or mapping
- `permissions:` as scalar ("read-all"/"write-all") or mapping
- `jobs.<id>` as either a normal job (with steps) or a reusable workflow
  call (`uses:` at the job level)
- step-level `with:`, `env:`, `if:`, `working-directory`, `continue-on-error`
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Union

import yaml

from ..models.workflow import Job, Step, Workflow


class GitHubActionsParser:
    """Parse a single GitHub Actions workflow YAML file into a Workflow model."""

    MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MB; same DoS guard as the GitLab parser

    def parse_file(self, path: str | Path) -> Workflow:
        path = Path(path)
        size = path.stat().st_size
        if size > self.MAX_FILE_BYTES:
            raise ValueError(
                f"File too large ({size:,} bytes). "
                f"Maximum supported size is {self.MAX_FILE_BYTES:,} bytes."
            )
        with open(path, "r", encoding="utf-8") as fh:
            try:
                raw = yaml.safe_load(fh)
            except yaml.YAMLError as exc:
                raise ValueError(f"Invalid YAML: {exc}") from exc
        if not isinstance(raw, dict):
            raise ValueError(f"Expected a YAML mapping, got {type(raw).__name__}")
        return self.parse(raw)

    def parse(self, data: Dict[str, Any]) -> Workflow:
        # YAML's literal `on:` value is sometimes parsed as Python `True` because
        # YAML 1.1 treats `on`/`off` as boolean literals when unquoted. Guard for it.
        on_value = data.get("on", data.get(True, {}))

        wf = Workflow(
            name=data.get("name"),
            on=on_value if on_value is not None else {},
            permissions=data.get("permissions"),
            env=self._coerce_str_map(data.get("env", {})),
            defaults=data.get("defaults") or {},
            concurrency=data.get("concurrency"),
            jobs=self._parse_jobs(data.get("jobs", {})),
        )
        return wf

    # ------------------------------------------------------------------
    # Jobs
    # ------------------------------------------------------------------

    def _parse_jobs(self, jobs_raw: Any) -> List[Job]:
        if not isinstance(jobs_raw, dict):
            return []
        jobs: List[Job] = []
        for job_id, job_data in jobs_raw.items():
            if not isinstance(job_data, dict):
                continue
            jobs.append(self._parse_job(str(job_id), job_data))
        return jobs

    def _parse_job(self, job_id: str, data: Dict[str, Any]) -> Job:
        return Job(
            id=job_id,
            name=data.get("name"),
            **{"runs-on": data.get("runs-on", "ubuntu-latest")},
            needs=self._coerce_str_list(data.get("needs", [])),
            **{"if": data.get("if")},
            permissions=data.get("permissions"),
            environment=data.get("environment"),
            env=self._coerce_str_map(data.get("env", {})),
            steps=self._parse_steps(data.get("steps", [])),
            container=data.get("container"),
            services=self._coerce_services(data.get("services", {})),
            strategy=data.get("strategy"),
            **{"timeout-minutes": data.get("timeout-minutes")},
            **{"continue-on-error": data.get("continue-on-error")},
            uses=data.get("uses"),
            secrets=data.get("secrets"),
        )

    # ------------------------------------------------------------------
    # Steps
    # ------------------------------------------------------------------

    def _parse_steps(self, steps_raw: Any) -> List[Step]:
        if not isinstance(steps_raw, list):
            return []
        steps: List[Step] = []
        for s in steps_raw:
            if not isinstance(s, dict):
                continue
            steps.append(Step(
                name=s.get("name"),
                run=s.get("run"),
                uses=s.get("uses"),
                **{"with": self._coerce_any_map(s.get("with", {}))},
                env=self._coerce_str_map(s.get("env", {})),
                **{"if": s.get("if")},
                shell=s.get("shell"),
                **{"working-directory": s.get("working-directory")},
                **{"continue-on-error": s.get("continue-on-error")},
            ))
        return steps

    # ------------------------------------------------------------------
    # Coercion helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _coerce_str_list(v: Any) -> List[str]:
        if isinstance(v, str):
            return [v]
        if isinstance(v, list):
            return [str(x) for x in v]
        return []

    @staticmethod
    def _coerce_str_map(v: Any) -> Dict[str, str]:
        if not isinstance(v, dict):
            return {}
        return {str(k): str(val) for k, val in v.items()}

    @staticmethod
    def _coerce_any_map(v: Any) -> Dict[str, Any]:
        if not isinstance(v, dict):
            return {}
        return {str(k): val for k, val in v.items()}

    @staticmethod
    def _coerce_services(v: Any) -> Dict[str, Dict[str, Any]]:
        if not isinstance(v, dict):
            return {}
        out: Dict[str, Dict[str, Any]] = {}
        for k, body in v.items():
            if isinstance(body, dict):
                out[str(k)] = body
        return out


# ---------------------------------------------------------------------------
# Format auto-detection
# ---------------------------------------------------------------------------

# Top-level keys that strongly suggest GitLab CI:
_GITLAB_HINT_KEYS = {"stages", "include", "before_script", "after_script", "default", "workflow"}


def detect_format(data: Dict[str, Any]) -> str:
    """Return 'github-actions' or 'gitlab-ci' based on top-level YAML shape.

    Heuristic, conservative: if a workflow has an `on:` trigger AND a `jobs:`
    block where each job has `runs-on:` or `uses:`, it's GHA. If it has
    GitLab-only keys (`stages`, `include`, `before_script`), it's GitLab CI.
    Ambiguous files default to gitlab-ci to preserve backward compatibility
    with the v0.1.x CLI behaviour.
    """
    if not isinstance(data, dict):
        return "gitlab-ci"

    # The YAML 1.1 `on:` -> True boolean coercion
    has_on = "on" in data or True in data

    gitlab_hits = sum(1 for k in _GITLAB_HINT_KEYS if k in data)
    if gitlab_hits >= 1:
        return "gitlab-ci"

    if "jobs" in data and isinstance(data["jobs"], dict) and has_on:
        # Any job with runs-on or uses → almost certainly GHA
        for job in data["jobs"].values():
            if isinstance(job, dict) and ("runs-on" in job or "uses" in job):
                return "github-actions"

    return "gitlab-ci"


def parse_file(path: str | Path) -> Union[Workflow, "Pipeline"]:  # noqa: F821
    """Auto-detect the file format and dispatch to the right parser.

    Returns either a `Workflow` (GHA) or a `Pipeline` (GitLab CI).
    Callers can dispatch on the return type, or pass `--format` to the CLI
    to override detection when needed.
    """
    path = Path(path)
    with open(path, "r", encoding="utf-8") as fh:
        try:
            raw = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"Expected a YAML mapping, got {type(raw).__name__}")

    fmt = detect_format(raw)
    if fmt == "github-actions":
        return GitHubActionsParser().parse(raw)

    # Lazy import to avoid a circular dep with gitlab_parser at module load time.
    from .gitlab_parser import GitLabCIParser
    return GitLabCIParser().parse(raw)
