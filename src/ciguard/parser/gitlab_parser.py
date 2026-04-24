"""
GitLab CI YAML parser.

Parses .gitlab-ci.yml files and constructs a Pipeline model.
Handles all GitLab CI constructs including anchors, aliases,
extends, includes, matrices, and environment definitions.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from ..models.pipeline import Artifact, Environment, Job, Pipeline


class _GitLabSafeLoader(yaml.SafeLoader):
    """SafeLoader extended with GitLab CI custom tags (e.g. ``!reference``)."""


def _construct_reference(loader: yaml.SafeLoader, node: yaml.Node) -> str:
    """Render ``!reference [.job, key]`` as a marker string.

    GitLab uses ``!reference`` to splice values from elsewhere in the YAML
    tree at job-execution time. Static analysis cannot safely resolve those
    references (they may point into hidden jobs, includes, etc.), so we
    record the target as an opaque marker. The marker is intentionally
    distinctive so it does not accidentally match script-pattern rules
    (no ``curl``, no ``eval``, no shell metacharacters).
    """
    if isinstance(node, yaml.SequenceNode):
        parts = loader.construct_sequence(node, deep=True)
        target = ".".join(str(p) for p in parts)
        return f"<<reference: {target}>>"
    return "<<reference>>"


_GitLabSafeLoader.add_constructor("!reference", _construct_reference)


# Keywords that are NOT job definitions
RESERVED_KEYWORDS = {
    "stages",
    "variables",
    "image",
    "services",
    "before_script",
    "after_script",
    "cache",
    "include",
    "default",
    "workflow",
}


class GitLabCIParser:
    """Parse .gitlab-ci.yml into a Pipeline model."""

    # 10 MB limit — prevents YAML bomb / anchor expansion DoS
    MAX_FILE_BYTES = 10 * 1024 * 1024

    def parse_file(self, path: str | Path) -> Pipeline:
        """Parse a .gitlab-ci.yml file from disk."""
        path = Path(path)
        size = path.stat().st_size
        if size > self.MAX_FILE_BYTES:
            raise ValueError(
                f"File too large ({size:,} bytes). "
                f"Maximum supported size is {self.MAX_FILE_BYTES:,} bytes."
            )
        with open(path, "r", encoding="utf-8") as fh:
            try:
                raw = yaml.load(fh, Loader=_GitLabSafeLoader)  # SafeLoader subclass; GitLab !reference handled
            except yaml.YAMLError as exc:
                raise ValueError(f"Invalid YAML: {exc}") from exc
        if not isinstance(raw, dict):
            raise ValueError(f"Expected a YAML mapping, got {type(raw).__name__}")
        return self.parse(raw)

    def parse(self, data: Dict[str, Any]) -> Pipeline:
        """Parse a pre-loaded YAML dict into a Pipeline."""
        pipeline = Pipeline()

        pipeline.stages = self._parse_stages(data.get("stages", []))
        pipeline.variables = self._parse_variables(data.get("variables", {}))
        pipeline.image = self._parse_image(data.get("image"))
        pipeline.services = self._parse_services(data.get("services", []))
        pipeline.before_script = self._coerce_script(data.get("before_script", []))
        pipeline.after_script = self._coerce_script(data.get("after_script", []))
        pipeline.cache = data.get("cache")
        pipeline.includes = self._parse_includes(data.get("include"))
        pipeline.default = data.get("default") or {}
        pipeline.workflow = data.get("workflow")

        # Everything else is a job definition (including hidden jobs starting with .)
        for key, value in data.items():
            if key in RESERVED_KEYWORDS:
                continue
            if not isinstance(value, dict):
                continue
            job = self._parse_job(key, value)
            pipeline.jobs.append(job)

        # If no stages were declared, derive from jobs
        if not pipeline.stages:
            seen: list[str] = []
            for job in pipeline.jobs:
                if job.stage and job.stage not in seen:
                    seen.append(job.stage)
            pipeline.stages = seen or ["test"]

        return pipeline

    # ------------------------------------------------------------------
    # Global section parsers
    # ------------------------------------------------------------------

    def _parse_stages(self, stages: Any) -> List[str]:
        if not stages:
            return []
        if isinstance(stages, list):
            return [str(s) for s in stages]
        return [str(stages)]

    def _parse_variables(self, variables: Any) -> Dict[str, str]:
        if not variables:
            return {}
        result: Dict[str, str] = {}
        for k, v in variables.items():
            if isinstance(v, dict):
                # GitLab extended variable syntax: {value: "...", masked: true, ...}
                result[str(k)] = str(v.get("value", ""))
            elif v is None:
                result[str(k)] = ""
            else:
                result[str(k)] = str(v)
        return result

    def _parse_image(self, image: Any) -> Optional[str]:
        if image is None:
            return None
        if isinstance(image, str):
            return image
        if isinstance(image, dict):
            return image.get("name") or ""
        return None

    def _parse_services(self, services: Any) -> List[str]:
        if not services:
            return []
        result: List[str] = []
        for s in services:
            if isinstance(s, str):
                result.append(s)
            elif isinstance(s, dict):
                name = s.get("name", "")
                if name:
                    result.append(name)
        return result

    def _parse_includes(self, include: Any) -> List[Dict[str, Any]]:
        """Normalise all include forms into a list of dicts."""
        if include is None:
            return []
        if isinstance(include, str):
            return [{"local": include}]
        if isinstance(include, dict):
            return [include]
        if isinstance(include, list):
            result: List[Dict[str, Any]] = []
            for item in include:
                if isinstance(item, str):
                    result.append({"local": item})
                elif isinstance(item, dict):
                    result.append(item)
            return result
        return []

    # ------------------------------------------------------------------
    # Job parser
    # ------------------------------------------------------------------

    def _parse_job(self, name: str, data: Dict[str, Any]) -> Job:
        job = Job(name=name)

        job.stage = data.get("stage", "test")
        job.image = self._parse_image(data.get("image"))
        job.services = self._parse_services(data.get("services", []))
        job.script = self._coerce_script(data.get("script", []))
        job.before_script = self._coerce_script(data.get("before_script", []))
        job.after_script = self._coerce_script(data.get("after_script", []))
        job.variables = self._parse_variables(data.get("variables", {}))
        job.rules = data.get("rules") or []
        job.only = data.get("only")
        # Pydantic alias handles "except" → "except_"
        job.except_ = data.get("except")
        job.when = data.get("when", "on_success")
        job.allow_failure = data.get("allow_failure", False)
        job.tags = self._coerce_list(data.get("tags", []))
        job.dependencies = self._coerce_list(data.get("dependencies", []))
        job.needs = data.get("needs") or []
        job.extends = data.get("extends")
        job.timeout = data.get("timeout")
        job.retry = data.get("retry")
        job.parallel = data.get("parallel")
        job.coverage = data.get("coverage")
        job.interruptible = bool(data.get("interruptible", False))
        job.resource_group = data.get("resource_group")
        job.trigger = data.get("trigger")
        job.id_tokens = data.get("id_tokens")
        job.secrets = data.get("secrets")
        job.cache = data.get("cache")

        env = data.get("environment")
        if env is not None:
            job.environment = self._parse_environment(env)

        artifacts = data.get("artifacts")
        if artifacts is not None and isinstance(artifacts, dict):
            job.artifacts = self._parse_artifacts(artifacts)

        return job

    def _parse_environment(self, env: Any) -> Environment:
        if isinstance(env, str):
            return Environment(name=env)
        if isinstance(env, dict):
            return Environment(
                name=env.get("name", ""),
                url=env.get("url"),
                action=env.get("action"),
                auto_stop_in=env.get("auto_stop_in"),
                on_stop=env.get("on_stop"),
                deployment_tier=env.get("deployment_tier"),
            )
        return Environment(name=str(env))

    def _parse_artifacts(self, artifacts: Dict[str, Any]) -> Artifact:
        return Artifact(
            paths=self._coerce_list(artifacts.get("paths", [])),
            exclude=self._coerce_list(artifacts.get("exclude", [])),
            expire_in=artifacts.get("expire_in"),
            name=artifacts.get("name"),
            when=artifacts.get("when"),
            reports=artifacts.get("reports") or {},
            untracked=bool(artifacts.get("untracked", False)),
            expose_as=artifacts.get("expose_as"),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _coerce_script(self, value: Any) -> List[str]:
        """Normalise script blocks (string or list) to a flat list of strings."""
        if not value:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            result: List[str] = []
            for item in value:
                if isinstance(item, str):
                    result.append(item)
                elif isinstance(item, list):
                    result.extend(str(i) for i in item)
                else:
                    result.append(str(item))
            return result
        return [str(value)]

    def _coerce_list(self, value: Any) -> List[str]:
        if not value:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(i) for i in value]
        return [str(value)]
