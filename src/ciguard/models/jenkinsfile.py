"""
Jenkins Declarative Pipeline data model.

Jenkinsfiles are Groovy DSL, not YAML. The Declarative form is a
restricted DSL with a fixed top-level skeleton:

    pipeline {
      agent       { ... }   // any | none | label | docker | kubernetes
      environment { ... }   // KEY = 'literal' | KEY = credentials('id')
      options     { ... }
      parameters  { ... }
      triggers    { ... }
      tools       { ... }
      stages {
        stage('Build') {
          agent       { ... }
          when        { ... }
          environment { ... }
          steps {
            sh '...'
            bat '...'
            powershell '...'
            withCredentials([...]) { ... }
            // any DSL step
          }
          post { ... }
        }
      }
      post { always { ... } success { ... } failure { ... } }
    }

This model only captures the surface that security rules need to reason
about — agents (where code runs), environment bindings (secret leakage),
shell steps (the supply-chain blast radius). It is intentionally NOT a
full Groovy AST.

Scripted Pipelines (no top-level `pipeline {}` block) are out of scope
for v0.4 — the parser surfaces a parse warning rather than guessing.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class Agent(BaseModel):
    """Where a stage (or the whole pipeline) runs.

    `kind` is the Declarative agent directive: `any`, `none`, `label`,
    `docker`, `dockerfile`, `kubernetes`, or `node`. For `docker` we
    surface the image string and the optional `args` (which often hides
    privileged mounts and `--privileged` flags).
    """
    kind: str = "any"
    label: Optional[str] = None
    image: Optional[str] = None         # for docker / dockerfile / kubernetes
    args: Optional[str] = None          # docker args
    raw: Optional[str] = None           # whole agent block source for diagnostics


class EnvBinding(BaseModel):
    """A single `KEY = value` line inside an environment { } block.

    `source` distinguishes literal strings from `credentials('id')` wraps
    and from arbitrary Groovy expressions. Only `literal` values are a
    secret-leak candidate; `credentials` is the safe path."""
    key: str
    value: str
    source: str = "literal"              # "literal" | "credentials" | "expression"
    credential_id: Optional[str] = None  # set when source == "credentials"


class Step(BaseModel):
    """A statement inside a `steps { }` block.

    For `sh`/`bat`/`powershell` the `script` field holds the captured
    string body — that is what shell-pattern rules pattern-match against.
    For everything else we keep the `raw` text and a best-effort `kind`.
    """
    kind: str                            # "sh" | "bat" | "powershell" | "withCredentials" | "echo" | "other"
    script: Optional[str] = None         # captured body for sh/bat/powershell
    raw: str = ""                        # the whole statement source

    def script_lines(self) -> List[str]:
        if not self.script:
            return []
        return [ln for ln in self.script.splitlines() if ln.strip()]


class Stage(BaseModel):
    """A stage inside `stages { }`. Nested `parallel` stages flatten into
    `parallel_stages` for v0.4 — full nested-stage trees are a v0.4.x follow-up."""
    name: str
    agent: Optional[Agent] = None
    when: Optional[str] = None           # raw text; condition parsing is out of scope
    environment: List[EnvBinding] = Field(default_factory=list)
    steps: List[Step] = Field(default_factory=list)
    post_blocks: Dict[str, List[Step]] = Field(default_factory=dict)
    parallel_stages: List["Stage"] = Field(default_factory=list)

    def all_step_scripts(self) -> List[str]:
        out: List[str] = []
        for s in self.steps:
            if s.script:
                out.append(s.script)
        for sub in self.parallel_stages:
            out.extend(sub.all_step_scripts())
        return out


class Jenkinsfile(BaseModel):
    """A parsed Declarative Pipeline."""
    agent: Optional[Agent] = None
    environment: List[EnvBinding] = Field(default_factory=list)
    options: List[str] = Field(default_factory=list)         # raw option statements
    parameters: List[str] = Field(default_factory=list)
    triggers: List[str] = Field(default_factory=list)
    tools: Dict[str, str] = Field(default_factory=dict)
    stages: List[Stage] = Field(default_factory=list)
    post_blocks: Dict[str, List[Step]] = Field(default_factory=dict)

    # Diagnostics
    is_scripted: bool = False            # True if no `pipeline {}` block was found
    parse_warnings: List[str] = Field(default_factory=list)

    def all_agents(self) -> List[Agent]:
        """Top-level agent + every per-stage agent (recursing into parallel)."""
        out: List[Agent] = []
        if self.agent:
            out.append(self.agent)
        def walk(stage: Stage) -> None:
            if stage.agent:
                out.append(stage.agent)
            for sub in stage.parallel_stages:
                walk(sub)
        for s in self.stages:
            walk(s)
        return out

    def all_env_bindings(self) -> List[EnvBinding]:
        """Top-level environment + every per-stage environment block."""
        out: List[EnvBinding] = list(self.environment)
        def walk(stage: Stage) -> None:
            out.extend(stage.environment)
            for sub in stage.parallel_stages:
                walk(sub)
        for s in self.stages:
            walk(s)
        return out

    def all_step_scripts(self) -> List[tuple[str, str]]:
        """Return `(stage_name, script_body)` tuples for every captured
        sh/bat/powershell step in the file. Excludes `script {}` Groovy
        blocks — those are surfaced by `all_steps()` for callers that
        want to reason about them separately."""
        out: List[tuple[str, str]] = []
        def walk(stage: Stage) -> None:
            for st in stage.steps:
                if st.script and st.kind in ("sh", "bat", "powershell"):
                    out.append((stage.name, st.script))
            for sub in stage.parallel_stages:
                walk(sub)
        for s in self.stages:
            walk(s)
        return out

    def all_steps(self) -> List[tuple[str, "Step"]]:
        """Return `(stage_name, step)` tuples for every step in every
        stage (including parallel children). Lets rules filter by
        `step.kind` without re-walking the tree themselves."""
        out: List[tuple[str, Step]] = []
        def walk(stage: Stage) -> None:
            for st in stage.steps:
                out.append((stage.name, st))
            for sub in stage.parallel_stages:
                walk(sub)
        for s in self.stages:
            walk(s)
        return out


Stage.model_rebuild()
