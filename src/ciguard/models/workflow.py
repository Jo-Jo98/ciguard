"""
GitHub Actions workflow data model.

GitHub Actions has a different shape from GitLab CI — events trigger
workflows, workflows contain jobs, jobs contain steps, and steps either
`run:` shell commands or `uses:` reusable actions. The action references
themselves are the highest-value supply-chain surface (every `uses:` is
external code that runs with the workflow's permissions).

This model is intentionally separate from `Pipeline` (the GitLab CI model)
because forcing one shape onto both leaks abstractions in both directions.
The shared output contract is `Finding` / `Report` from `pipeline.py`, so
the analyzer/reporter/policy stack works for both platforms unchanged.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class Step(BaseModel):
    """A single step inside a job. Either `run` (shell) or `uses` (action ref)."""
    name: Optional[str] = None
    run: Optional[str] = None              # shell script body
    uses: Optional[str] = None             # action reference, e.g. "actions/checkout@v4"
    with_inputs: Dict[str, Any] = Field(default_factory=dict, alias="with")
    env: Dict[str, str] = Field(default_factory=dict)
    if_condition: Optional[str] = Field(default=None, alias="if")
    shell: Optional[str] = None
    working_directory: Optional[str] = Field(default=None, alias="working-directory")
    continue_on_error: Optional[bool] = Field(default=None, alias="continue-on-error")

    model_config = {"populate_by_name": True, "extra": "ignore"}

    def is_action(self) -> bool:
        return self.uses is not None

    def is_shell(self) -> bool:
        return self.run is not None

    def action_ref_pinned_to_sha(self) -> bool:
        """True if `uses:` pins to a 40-char commit SHA.

        Tag refs (`@v4`, `@main`) are mutable and a known supply-chain risk —
        the same security pattern as GitLab CI's `include: project: ref:`.
        """
        if not self.uses or "@" not in self.uses:
            return False
        ref = self.uses.rsplit("@", 1)[1]
        # 40 hex chars
        return len(ref) == 40 and all(c in "0123456789abcdef" for c in ref.lower())

    def script_lines(self) -> List[str]:
        """Return the `run:` body split into lines (empty list for action steps)."""
        if not self.run:
            return []
        return [line for line in self.run.splitlines() if line.strip()]


class Job(BaseModel):
    """A GitHub Actions job. Contains steps; runs on a runner."""
    id: str                                # the YAML key (jobs.<id>)
    name: Optional[str] = None             # optional display name
    runs_on: Union[str, List[str]] = Field(default="ubuntu-latest", alias="runs-on")
    needs: List[str] = Field(default_factory=list)
    if_condition: Optional[str] = Field(default=None, alias="if")
    permissions: Optional[Union[str, Dict[str, str]]] = None
    environment: Optional[Union[str, Dict[str, Any]]] = None
    env: Dict[str, str] = Field(default_factory=dict)
    steps: List[Step] = Field(default_factory=list)
    container: Optional[Union[str, Dict[str, Any]]] = None
    services: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    strategy: Optional[Dict[str, Any]] = None
    timeout_minutes: Optional[int] = Field(default=None, alias="timeout-minutes")
    continue_on_error: Optional[bool] = Field(default=None, alias="continue-on-error")
    uses: Optional[str] = None             # reusable workflow reference
    secrets: Optional[Union[str, Dict[str, Any]]] = None

    model_config = {"populate_by_name": True, "extra": "ignore"}

    def is_reusable_workflow_call(self) -> bool:
        """True if this job calls a reusable workflow (jobs.<id>.uses)."""
        return self.uses is not None

    def all_run_lines(self) -> List[str]:
        """Flatten every shell-step line in the job."""
        return [line for step in self.steps for line in step.script_lines()]

    def container_image(self) -> Optional[str]:
        """Return the container image string if specified, else None."""
        if isinstance(self.container, str):
            return self.container
        if isinstance(self.container, dict):
            return self.container.get("image")
        return None

    def targets_environment(self) -> Optional[str]:
        """The named GitHub environment (gates protection rules), or None."""
        if isinstance(self.environment, str):
            return self.environment
        if isinstance(self.environment, dict):
            return self.environment.get("name")
        return None


class Workflow(BaseModel):
    """A GitHub Actions workflow file (.github/workflows/*.yml)."""
    name: Optional[str] = None
    on: Union[str, List[str], Dict[str, Any]] = Field(default_factory=dict)
    permissions: Optional[Union[str, Dict[str, str]]] = None
    env: Dict[str, str] = Field(default_factory=dict)
    defaults: Dict[str, Any] = Field(default_factory=dict)
    concurrency: Optional[Union[str, Dict[str, Any]]] = None
    jobs: List[Job] = Field(default_factory=list)

    model_config = {"populate_by_name": True, "extra": "ignore"}

    def event_names(self) -> List[str]:
        """Return the list of trigger event names regardless of `on:` shape."""
        if isinstance(self.on, str):
            return [self.on]
        if isinstance(self.on, list):
            return [str(x) for x in self.on]
        if isinstance(self.on, dict):
            return list(self.on.keys())
        return []

    def has_event(self, name: str) -> bool:
        return name in self.event_names()

    def all_action_uses(self) -> List[str]:
        """Every `uses:` reference across all step-level and job-level
        action calls — the supply-chain surface of the workflow."""
        refs: List[str] = []
        for job in self.jobs:
            if job.uses:
                refs.append(job.uses)
            for step in job.steps:
                if step.uses:
                    refs.append(step.uses)
        return refs

    def all_run_lines(self) -> List[str]:
        return [line for job in self.jobs for line in job.all_run_lines()]
