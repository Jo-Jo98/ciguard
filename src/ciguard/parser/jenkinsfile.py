"""
Jenkins Declarative + Scripted Pipeline parser.

Jenkinsfiles are Groovy DSL, not YAML, so we cannot use `yaml.safe_load`.
A full Groovy AST parser would be massive; instead we hand-roll a small
Groovy-aware *block tokenizer* that handles the syntactic features we
care about — comments, single/double/triple-quoted strings, escape
sequences, nested braces — and extracts the pipeline skeleton.

This is intentionally pragmatic: we capture exactly the surface that
security rules reason about (agents, environment bindings, shell step
bodies). Anything we cannot confidently parse is left as raw text and
tracked in `parse_warnings`.

We recognise three shapes (in priority order):

  1. **Declarative** (`pipeline { ... }`) — fixed sections, easy parse.
  2. **Node-scripted** (`node('label') { stage('…') { sh '…' } }`) —
     the second-most-common real-world shape, especially for older
     Jenkinsfiles. Synthesises an `Agent` from the node label and walks
     the body for `stage('…') { … }` blocks.
  3. **Shared-library call** (a single top-level `buildPlugin(...)` style
     invocation) — dominates the `jenkinsci/*` plugin repos. Recognise
     the shape, surface as `style="shared-library"`, let JKN-LIB-001
     fire to flag the coverage gap.

Anything else (free-form Groovy with `def`, `if`, multiple statements,
etc.) sets `is_scripted=True` / `style="scripted-unparseable"` — security
analysis of arbitrary Groovy is out of scope.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional, Tuple

from ..models.jenkinsfile import (
    Agent,
    EnvBinding,
    Jenkinsfile,
    SharedLibraryCall,
    Stage,
    Step,
)


# ---------------------------------------------------------------------------
# Source preprocessing — strip comments, preserve strings
# ---------------------------------------------------------------------------

def _strip_groovy_comments(src: str) -> str:
    """Remove `//` line comments and `/* */` block comments without touching
    comment-like text inside string literals. Returns a string of the same
    length (comments replaced with spaces) so that any byte offset still
    aligns with the original source — useful for future diagnostics."""
    out = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        # Triple-quoted strings (Groovy supports both ''' and """)
        if c in ("'", '"') and i + 2 < n and src[i + 1] == c and src[i + 2] == c:
            quote = c * 3
            end = src.find(quote, i + 3)
            if end == -1:
                out.append(src[i:])
                break
            out.append(src[i:end + 3])
            i = end + 3
            continue
        # Single-line strings (handle escapes)
        if c in ("'", '"'):
            j = i + 1
            while j < n:
                if src[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if src[j] == c:
                    j += 1
                    break
                j += 1
            out.append(src[i:j])
            i = j
            continue
        # Line comment
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            if j == -1:
                j = n
            out.append(" " * (j - i))
            i = j
            continue
        # Block comment
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            if j == -1:
                # unterminated — drop the rest
                out.append(" " * (n - i))
                break
            out.append(" " * (j + 2 - i))
            i = j + 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# Brace-balanced block extraction
# ---------------------------------------------------------------------------

def _find_matching_brace(src: str, open_idx: int) -> int:
    """Given the index of an opening `{`, return the index of its matching
    `}`. Tracks string literals so braces inside strings don't count.
    Returns -1 if unbalanced."""
    assert src[open_idx] == "{"
    depth = 0
    i = open_idx
    n = len(src)
    while i < n:
        c = src[i]
        # Triple strings
        if c in ("'", '"') and i + 2 < n and src[i + 1] == c and src[i + 2] == c:
            quote = c * 3
            end = src.find(quote, i + 3)
            if end == -1:
                return -1
            i = end + 3
            continue
        if c in ("'", '"'):
            j = i + 1
            while j < n:
                if src[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if src[j] == c:
                    j += 1
                    break
                j += 1
            i = j
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


# Match a directive header: `name` or `name(args)` followed by `{` or a value.
# Captures the name as group 1 and any parenthesised args as group 2.
_DIRECTIVE_HEADER_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*(\([^)]*\))?\s*", re.DOTALL)


def _extract_block(src: str, name: str, start: int = 0) -> Optional[Tuple[int, int, str]]:
    """Find the first `<name> { ... }` block at brace-depth 0 of `src`,
    starting at offset `start`. Skips matches inside nested braces and
    inside string literals. This is the standard "find a top-level
    directive in this block body" operation.

    Returns (header_start, body_start, body_end_exclusive) or None.
    The header_start points at the `n` of `name`; body is between the
    matching braces (exclusive)."""
    pattern = re.compile(rf"\b{re.escape(name)}\b\s*\{{", re.DOTALL)
    n = len(src)
    i = start
    depth = 0
    while i < n:
        c = src[i]
        # Triple strings
        if c in ("'", '"') and i + 2 < n and src[i + 1] == c and src[i + 2] == c:
            quote = c * 3
            end = src.find(quote, i + 3)
            if end == -1:
                return None
            i = end + 3
            continue
        if c in ("'", '"'):
            j = i + 1
            while j < n:
                if src[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if src[j] == c:
                    j += 1
                    break
                j += 1
            i = j
            continue
        if c == "{":
            depth += 1
            i += 1
            continue
        if c == "}":
            depth -= 1
            i += 1
            continue
        if depth == 0:
            m = pattern.match(src, i)
            if m:
                open_brace = m.end() - 1
                close_brace = _find_matching_brace(src, open_brace)
                if close_brace == -1:
                    return None
                return (m.start(), open_brace + 1, close_brace)
        i += 1
    return None


# ---------------------------------------------------------------------------
# String-literal helpers
# ---------------------------------------------------------------------------

# Captures the *body* of the first single-, double-, or triple-quoted string
# starting at the cursor. Used for `sh '...'`, `image '...'`, etc.
def _read_string_arg(src: str, start: int) -> Optional[Tuple[str, int]]:
    """If the next non-whitespace token at `start` is a string literal,
    return (string_body, end_index_exclusive). Otherwise None."""
    i = start
    n = len(src)
    while i < n and src[i] in " \t\r\n":
        i += 1
    if i >= n or src[i] not in ("'", '"'):
        return None
    quote_char = src[i]
    # Triple?
    if i + 2 < n and src[i + 1] == quote_char and src[i + 2] == quote_char:
        triple = quote_char * 3
        end = src.find(triple, i + 3)
        if end == -1:
            return None
        return (src[i + 3:end], end + 3)
    # Single
    j = i + 1
    body_chars: List[str] = []
    while j < n:
        if src[j] == "\\" and j + 1 < n:
            body_chars.append(src[j + 1])
            j += 2
            continue
        if src[j] == quote_char:
            return ("".join(body_chars), j + 1)
        body_chars.append(src[j])
        j += 1
    return None


# ---------------------------------------------------------------------------
# Agent block parsing
# ---------------------------------------------------------------------------

# `agent any` / `agent none` (no braces)
_AGENT_BARE_RE = re.compile(r"\bagent\s+(any|none)\b", re.DOTALL)


def _parse_agent_body(body: str, raw: str) -> Agent:
    """Parse what's inside `agent { ... }`. Recognises:
        label 'foo'
        docker { image '...' args '...' }
        docker '...'
        dockerfile { ... }
        kubernetes { ... }
        node { label '...' }"""
    # docker { ... } block
    blk = _extract_block(body, "docker")
    if blk:
        _, bs, be = blk
        inner = body[bs:be]
        image = _extract_string_directive(inner, "image")
        args = _extract_string_directive(inner, "args")
        return Agent(kind="docker", image=image, args=args, raw=raw.strip())
    # docker 'image' (single-arg shorthand)
    m = re.search(r"\bdocker\s+(['\"])", body)
    if m:
        s = _read_string_arg(body, m.start() + len("docker"))
        if s:
            return Agent(kind="docker", image=s[0], raw=raw.strip())
    # dockerfile / kubernetes blocks
    for kind in ("dockerfile", "kubernetes"):
        blk = _extract_block(body, kind)
        if blk:
            _, bs, be = blk
            inner = body[bs:be]
            image = _extract_string_directive(inner, "image")
            return Agent(kind=kind, image=image, raw=raw.strip())
    # node { label '...' }
    blk = _extract_block(body, "node")
    if blk:
        _, bs, be = blk
        inner = body[bs:be]
        label = _extract_string_directive(inner, "label")
        return Agent(kind="node", label=label, raw=raw.strip())
    # bare `label 'foo'`
    label = _extract_string_directive(body, "label")
    if label is not None:
        return Agent(kind="label", label=label, raw=raw.strip())
    return Agent(kind="any", raw=raw.strip())


def _extract_string_directive(body: str, name: str) -> Optional[str]:
    """Find `<name> '<value>'` (or "<value>") inside `body`. Returns the
    value or None if the directive is absent or the value isn't a string."""
    pattern = re.compile(rf"\b{re.escape(name)}\b", re.DOTALL)
    m = pattern.search(body)
    if not m:
        return None
    s = _read_string_arg(body, m.end())
    if s is None:
        return None
    return s[0]


def _parse_agent_directive(parent_body: str) -> Optional[Agent]:
    """Parse the `agent` directive at the top of a pipeline / stage body."""
    # Block form first
    blk = _extract_block(parent_body, "agent")
    if blk:
        hs, bs, be = blk
        return _parse_agent_body(parent_body[bs:be], parent_body[hs:be + 1])
    # Bare form
    m = _AGENT_BARE_RE.search(parent_body)
    if m:
        return Agent(kind=m.group(1), raw=m.group(0))
    return None


# ---------------------------------------------------------------------------
# Environment block parsing
# ---------------------------------------------------------------------------

# `KEY = 'literal'` | `KEY = "literal"` | `KEY = credentials('id')` | `KEY = expr`
_ENV_LINE_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)(?=\n\s*[A-Za-z_][A-Za-z0-9_]*\s*=|\Z)",
    re.DOTALL,
)


def _parse_environment_body(body: str) -> List[EnvBinding]:
    """Pull KEY = value bindings out of an environment { } body."""
    out: List[EnvBinding] = []
    for m in _ENV_LINE_RE.finditer(body.strip()):
        key = m.group(1)
        rhs = m.group(2).strip().rstrip(",;")
        out.append(_classify_env_value(key, rhs))
    return out


def _classify_env_value(key: str, rhs: str) -> EnvBinding:
    """Classify a `KEY = <rhs>` right-hand side as literal / credentials / expr."""
    # credentials('id') wrap
    cred_m = re.match(r"credentials\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", rhs)
    if cred_m:
        return EnvBinding(key=key, value=rhs, source="credentials", credential_id=cred_m.group(1))
    # plain string literal
    s = _read_string_arg(rhs, 0)
    if s is not None and s[1] >= len(rhs.rstrip()):
        return EnvBinding(key=key, value=s[0], source="literal")
    # any other expression (e.g. `${env.FOO}`, `sh(...)`, function call)
    return EnvBinding(key=key, value=rhs, source="expression")


# ---------------------------------------------------------------------------
# Steps block parsing
# ---------------------------------------------------------------------------

# Match `sh ...`, `bat ...`, `powershell ...` with either bare-string or
# (script: '...') named-arg form.
_STEP_KEYWORDS = ("sh", "bat", "powershell", "pwsh")
_STEP_KEYWORD_RE = re.compile(
    rf"\b(?P<kw>{'|'.join(_STEP_KEYWORDS)})\b",
    re.DOTALL,
)


def _parse_steps_body(body: str) -> List[Step]:
    """Walk a `steps { }` body and return Step records.

    Handles `sh '...'`, triple-quoted heredoc `sh` bodies, the
    parenthesised named-arg form `sh(script: '...', returnStdout: true)`,
    and falls back to a coarse capture of any other DSL step (kind=other).
    """
    out: List[Step] = []
    i = 0
    n = len(body)
    while i < n:
        # Skip whitespace
        while i < n and body[i] in " \t\r\n":
            i += 1
        if i >= n:
            break

        # `script { ... }` — dynamic Groovy block inside a Declarative steps
        # body. Bypasses the Declarative whitelist and is the canonical way
        # to slip arbitrary Groovy into an otherwise-restricted pipeline.
        m_script = re.match(r"script\s*\{", body[i:])
        if m_script:
            brace_open = i + m_script.end() - 1
            brace_close = _find_matching_brace(body, brace_open)
            if brace_close == -1:
                break
            inner = body[brace_open + 1:brace_close]
            out.append(Step(kind="script", script=inner, raw=body[i:brace_close + 1]))
            i = brace_close + 1
            continue

        # `withCredentials([...]) { ... }` — preserve the whole inner block
        if body.startswith("withCredentials", i):
            paren_open = body.find("(", i)
            paren_close = _find_matching_paren(body, paren_open) if paren_open != -1 else -1
            if paren_close == -1:
                # malformed, skip rest
                break
            brace_open = body.find("{", paren_close)
            if brace_open == -1:
                break
            brace_close = _find_matching_brace(body, brace_open)
            if brace_close == -1:
                break
            inner = body[brace_open + 1:brace_close]
            inner_steps = _parse_steps_body(inner)
            # Surface inner sh/bat/powershell as their own Steps so rules see them.
            out.extend(inner_steps)
            out.append(Step(kind="withCredentials", raw=body[i:brace_close + 1]))
            i = brace_close + 1
            continue

        # sh / bat / powershell / pwsh
        m = _STEP_KEYWORD_RE.match(body, i)
        if m:
            kw = m.group("kw")
            after = m.end()
            script, end_idx = _read_step_script(body, after)
            kind = "powershell" if kw == "pwsh" else kw
            raw = body[i:end_idx] if end_idx > i else body[i:after]
            out.append(Step(kind=kind, script=script, raw=raw))
            i = end_idx
            continue

        # Fallback: capture up to the next newline as an opaque step
        nl = body.find("\n", i)
        if nl == -1:
            nl = n
        snippet = body[i:nl].strip()
        if snippet:
            out.append(Step(kind="other", raw=snippet))
        i = nl + 1
    return out


def _read_step_script(body: str, after_kw: int) -> Tuple[Optional[str], int]:
    """After matching `sh`/`bat`/`powershell`, read the script argument.

    Supports the bare-string form (`sh '...'`, `sh "..."`), the triple-
    quoted heredoc form (`sh '''...'''`), and the parenthesised named-arg
    form (`sh(script: '...', returnStdout: true)`).

    Returns (script_body, end_index_exclusive). end_index points one past
    the consumed argument; if we can't parse it we return (None, after_kw)
    so the caller advances and treats the line as opaque.
    """
    n = len(body)
    i = after_kw
    while i < n and body[i] in " \t":
        i += 1
    if i >= n:
        return None, after_kw
    # Bare string form: `sh '…'`
    if body[i] in ("'", '"'):
        s = _read_string_arg(body, i)
        if s is None:
            return None, after_kw
        return s[0], s[1]
    # Parenthesised form: `sh(script: '…', …)`
    if body[i] == "(":
        close = _find_matching_paren(body, i)
        if close == -1:
            return None, after_kw
        inner = body[i + 1:close]
        # Look for `script:` named arg, fall back to first string literal
        m = re.search(r"\bscript\s*:", inner)
        if m:
            s = _read_string_arg(inner, m.end())
            if s is not None:
                return s[0], close + 1
        s = _read_string_arg(inner, 0)
        if s is not None:
            return s[0], close + 1
        return None, close + 1
    return None, after_kw


def _find_matching_paren(src: str, open_idx: int) -> int:
    if open_idx < 0 or open_idx >= len(src) or src[open_idx] != "(":
        return -1
    depth = 0
    i = open_idx
    n = len(src)
    while i < n:
        c = src[i]
        if c in ("'", '"') and i + 2 < n and src[i + 1] == c and src[i + 2] == c:
            quote = c * 3
            end = src.find(quote, i + 3)
            if end == -1:
                return -1
            i = end + 3
            continue
        if c in ("'", '"'):
            j = i + 1
            while j < n:
                if src[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if src[j] == c:
                    j += 1
                    break
                j += 1
            i = j
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


# ---------------------------------------------------------------------------
# Stage parsing
# ---------------------------------------------------------------------------

# `stage('Name') { ... }` — capture name + body span.
_STAGE_HEADER_RE = re.compile(r"\bstage\s*\(\s*(['\"])(.*?)\1\s*\)\s*\{", re.DOTALL)


def _parse_stages_body(stages_body: str) -> List[Stage]:
    """Walk a `stages { }` body and return a Stage for each `stage('…') { … }`."""
    out: List[Stage] = []
    i = 0
    while True:
        m = _STAGE_HEADER_RE.search(stages_body, i)
        if not m:
            break
        name = m.group(2)
        open_brace = m.end() - 1
        close_brace = _find_matching_brace(stages_body, open_brace)
        if close_brace == -1:
            break
        inner = stages_body[open_brace + 1:close_brace]
        out.append(_parse_stage_body(name, inner))
        i = close_brace + 1
    return out


def _parse_stage_body(name: str, body: str) -> Stage:
    stage = Stage(name=name)
    # Per-stage agent
    stage.agent = _parse_agent_directive(body)
    # Per-stage environment
    env_blk = _extract_block(body, "environment")
    if env_blk:
        _, bs, be = env_blk
        stage.environment = _parse_environment_body(body[bs:be])
    # `when` block — capture raw text only
    when_blk = _extract_block(body, "when")
    if when_blk:
        _, bs, be = when_blk
        stage.when = body[bs:be].strip()
    # Steps
    steps_blk = _extract_block(body, "steps")
    if steps_blk:
        _, bs, be = steps_blk
        stage.steps = _parse_steps_body(body[bs:be])
    # Parallel stages — `parallel { stage('…') { … } stage(…) { … } }`
    par_blk = _extract_block(body, "parallel")
    if par_blk:
        _, bs, be = par_blk
        stage.parallel_stages = _parse_stages_body(body[bs:be])
    # Post block
    post_blk = _extract_block(body, "post")
    if post_blk:
        _, bs, be = post_blk
        stage.post_blocks = _parse_post_body(body[bs:be])
    return stage


def _parse_post_body(body: str) -> dict:
    """A `post { always {…} success {…} … }` body. Returns a dict of
    condition -> List[Step]."""
    out: dict = {}
    for cond in ("always", "success", "failure", "unstable", "changed", "fixed", "regression", "aborted", "cleanup"):
        blk = _extract_block(body, cond)
        if blk:
            _, bs, be = blk
            out[cond] = _parse_steps_body(body[bs:be])
    return out


# ---------------------------------------------------------------------------
# Top-level parser
# ---------------------------------------------------------------------------

class JenkinsfileParser:
    """Parse a Jenkins Declarative Pipeline file into a Jenkinsfile model."""

    MAX_FILE_BYTES = 10 * 1024 * 1024

    def parse_file(self, path: str | Path) -> Jenkinsfile:
        path = Path(path)
        size = path.stat().st_size
        if size > self.MAX_FILE_BYTES:
            raise ValueError(
                f"File too large ({size:,} bytes). "
                f"Maximum supported size is {self.MAX_FILE_BYTES:,} bytes."
            )
        with open(path, "r", encoding="utf-8") as fh:
            return self.parse(fh.read())

    def parse(self, source: str) -> Jenkinsfile:
        cleaned = _strip_groovy_comments(source)

        # 1. Declarative — `pipeline { ... }` at top level.
        blk = _extract_block(cleaned, "pipeline")
        if blk is not None:
            _, bs, be = blk
            jf = self._parse_pipeline_body(cleaned[bs:be])
            jf.style = "declarative"
            return jf

        # 2. Node-scripted — one or more top-level `node(...) { ... }` blocks.
        node_blocks = _find_top_level_node_blocks(cleaned)
        if node_blocks:
            return self._parse_node_style(node_blocks)

        # 3. Shared-library call — a single top-level `buildPlugin(...)`-style
        #    invocation that comprises the entire pipeline.
        sl = _detect_shared_library(cleaned)
        if sl is not None:
            return Jenkinsfile(
                style="shared-library",
                shared_library_call=sl,
                parse_warnings=[
                    f"File delegates to shared-library call `{sl.name}(...)`. "
                    "ciguard cannot audit the library body from this file alone."
                ],
            )

        # 4. Free-form Scripted — give up.
        return Jenkinsfile(
            is_scripted=True,
            style="scripted-unparseable",
            parse_warnings=[
                "Free-form Scripted Pipeline (no `pipeline {}`, no top-level "
                "`node {}`, not a shared-library call). ciguard cannot model "
                "arbitrary Groovy control flow."
            ],
        )

    def _parse_node_style(self, node_blocks: List[Tuple[Optional[str], str]]) -> Jenkinsfile:
        """Build a Jenkinsfile model from a list of top-level `node(...) { … }`
        blocks. Each node block contributes:

          - one Agent (top-level if there's only one node block, otherwise
            the first node's agent becomes top-level and the rest become
            per-stage agents on synthetic stages);
          - stages parsed from `stage('…') { … }` calls inside the node body
            (or one synthetic "main" stage if no `stage(...)` blocks are
            present)."""
        jf = Jenkinsfile(style="node-scripted")
        # First node block sets the top-level agent (most common case is one node).
        first_label, first_body = node_blocks[0]
        jf.agent = _agent_from_node_label(first_label)
        jf.stages.extend(_parse_node_body_stages(first_body, jf.agent))

        # Multiple top-level `node` blocks: append their stages too. Each
        # subsequent node may have a different label, so attach the agent
        # to its synthetic stages so JKN-PIPE-001 / JKN-RUN-* still see it.
        for label, body in node_blocks[1:]:
            agent = _agent_from_node_label(label)
            extra = _parse_node_body_stages(body, agent)
            for s in extra:
                if s.agent is None:
                    s.agent = agent
            jf.stages.extend(extra)
        return jf

    def _parse_pipeline_body(self, body: str) -> Jenkinsfile:
        jf = Jenkinsfile()

        # Top-level agent
        jf.agent = _parse_agent_directive(body)

        # Top-level environment
        env_blk = _extract_block(body, "environment")
        if env_blk:
            _, bs, be = env_blk
            jf.environment = _parse_environment_body(body[bs:be])

        # tools { jdk 'name'; maven 'name' }
        tools_blk = _extract_block(body, "tools")
        if tools_blk:
            _, bs, be = tools_blk
            jf.tools = _parse_tools_body(body[bs:be])

        # options / parameters / triggers — keep raw lines for future rules
        for kw, dest in (("options", jf.options), ("parameters", jf.parameters), ("triggers", jf.triggers)):
            blk = _extract_block(body, kw)
            if blk:
                _, bs, be = blk
                dest.extend([ln.strip() for ln in body[bs:be].splitlines() if ln.strip()])

        # stages
        stages_blk = _extract_block(body, "stages")
        if stages_blk:
            _, bs, be = stages_blk
            jf.stages = _parse_stages_body(body[bs:be])

        # top-level post
        post_blk = _extract_block(body, "post")
        if post_blk:
            _, bs, be = post_blk
            jf.post_blocks = _parse_post_body(body[bs:be])

        return jf


def _parse_tools_body(body: str) -> dict:
    """A `tools { jdk 'name'; maven 'name' }` body. Returns kind -> name."""
    out: dict = {}
    # Match `<kind> '<name>'` or `<kind> "<name>"` allowing newlines/semicolons between.
    for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)\s+(['\"])(.*?)\2", body):
        out[m.group(1)] = m.group(3)
    return out


# ---------------------------------------------------------------------------
# Node-scripted parsing (v0.4.1)
# ---------------------------------------------------------------------------

# `node` followed by an optional ('label') and a `{`.
_NODE_HEADER_RE = re.compile(r"\bnode\b\s*(\(([^)]*)\))?\s*\{", re.DOTALL)


def _find_top_level_node_blocks(src: str) -> List[Tuple[Optional[str], str]]:
    """Return [(label, body)] for each top-level `node(...) { ... }` block.

    `label` is None if the node call had no string argument or had a
    closure / map argument we don't try to parse. Walks at brace-depth 0
    only — nested `node {}` inside a parallel branch is not considered
    top-level."""
    out: List[Tuple[Optional[str], str]] = []
    n = len(src)
    i = 0
    depth = 0
    while i < n:
        c = src[i]
        # Skip strings (triple, then single)
        if c in ("'", '"') and i + 2 < n and src[i + 1] == c and src[i + 2] == c:
            quote = c * 3
            end = src.find(quote, i + 3)
            if end == -1:
                break
            i = end + 3
            continue
        if c in ("'", '"'):
            j = i + 1
            while j < n:
                if src[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if src[j] == c:
                    j += 1
                    break
                j += 1
            i = j
            continue
        if c == "{":
            depth += 1
            i += 1
            continue
        if c == "}":
            depth -= 1
            i += 1
            continue
        if depth == 0:
            m = _NODE_HEADER_RE.match(src, i)
            if m:
                label: Optional[str] = None
                paren_inner = m.group(2)
                if paren_inner is not None:
                    s = _read_string_arg(paren_inner.strip(), 0)
                    if s is not None:
                        label = s[0]
                open_brace = m.end() - 1
                close_brace = _find_matching_brace(src, open_brace)
                if close_brace == -1:
                    break
                out.append((label, src[open_brace + 1:close_brace]))
                i = close_brace + 1
                continue
        i += 1
    return out


def _agent_from_node_label(label: Optional[str]) -> Agent:
    """Synthesise an Agent from a `node('label')` argument. `node()` or
    `node` with no arg → `agent any` equivalent (worth flagging via
    JKN-RUN-001). `node('linux')` → `agent { label 'linux' }` equivalent."""
    if label:
        return Agent(kind="label", label=label, raw=f"node('{label}')")
    return Agent(kind="any", raw="node")


def _parse_node_body_stages(body: str, agent: Agent) -> List[Stage]:
    """Walk a node body for top-level `stage('name') { … }` blocks. Steps
    inside Scripted stages are not wrapped in `steps { }` — they are
    direct statements — so the body of each stage is parsed straight via
    `_parse_steps_body`. Returns synthesised stages.

    If no `stage(...)` blocks are present, the entire node body is treated
    as a single synthetic "main" stage. This is rare but happens in
    minimal Scripted pipelines that just put `sh '...'` inside `node {}`."""
    stages: List[Stage] = []
    i = 0
    while True:
        m = _STAGE_HEADER_RE.search(body, i)
        if not m:
            break
        name = m.group(2)
        open_brace = m.end() - 1
        close_brace = _find_matching_brace(body, open_brace)
        if close_brace == -1:
            break
        inner = body[open_brace + 1:close_brace]
        stage = Stage(name=name, agent=agent)
        stage.steps = _parse_steps_body(inner)
        stages.append(stage)
        i = close_brace + 1
    if not stages:
        # Fall back: treat the whole node body as one stage. Strip leading
        # whitespace; if there's nothing actionable left, skip.
        stripped = body.strip()
        if stripped:
            stage = Stage(name="main", agent=agent)
            stage.steps = _parse_steps_body(body)
            stages.append(stage)
    return stages


# ---------------------------------------------------------------------------
# Shared-library call detection (v0.4.1)
# ---------------------------------------------------------------------------

# Reserved names that must NOT be treated as shared-library calls — they
# have their own parser paths or imply free-form Scripted code.
_RESERVED_TOP_LEVEL_NAMES = frozenset({
    "pipeline", "node", "stage", "stages", "steps", "def", "class",
    "if", "for", "while", "return", "import", "package", "library",
    "withCredentials", "withEnv", "timeout", "lock", "parallel", "sh",
    "bat", "powershell", "pwsh", "echo", "script",
})


def _detect_shared_library(src: str) -> Optional[SharedLibraryCall]:
    """If `src` (after comment stripping) is *exactly* a single top-level
    function call — optionally preceded by a shebang and `@Library(...)`
    annotation lines — return a SharedLibraryCall describing it. Otherwise
    None.

    The canonical case is the `jenkinsci/*` plugin pattern:

        @Library('common-jenkinsci') _
        buildPlugin(useContainerAgent: true, configurations: [...])

    Multi-statement files, files with `def` assignments, files with
    control flow — none of these qualify as a clean shared-library call."""
    stripped = src.strip()
    # Strip optional shebang line.
    if stripped.startswith("#!"):
        nl = stripped.find("\n")
        if nl == -1:
            return None
        stripped = stripped[nl + 1:].strip()
    # Strip any number of leading `@Annotation(...) _?` lines (the trailing
    # underscore is a Jenkins convention for global library imports).
    while stripped.startswith("@"):
        # Find the end of the annotation: balance parens, then consume
        # the rest of the line (which may have a trailing `_`).
        if "(" in stripped.split("\n", 1)[0]:
            paren_open = stripped.index("(")
            paren_close = _find_matching_paren(stripped, paren_open)
            if paren_close == -1:
                return None
            after = paren_close + 1
        else:
            after = len(stripped.split("\n", 1)[0])
        # Consume rest of line including optional trailing `_`.
        nl = stripped.find("\n", after)
        if nl == -1:
            return None
        stripped = stripped[nl + 1:].strip()

    # Must now look exactly like `name(args)` with nothing after.
    m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", stripped)
    if not m:
        return None
    name = m.group(1)
    if name in _RESERVED_TOP_LEVEL_NAMES:
        return None
    paren_open = m.end() - 1
    paren_close = _find_matching_paren(stripped, paren_open)
    if paren_close == -1:
        return None
    # Anything non-whitespace after the closing paren disqualifies — multi-
    # statement Scripted is not a shared-library call.
    trailing = stripped[paren_close + 1:].strip()
    if trailing:
        return None
    raw_args = stripped[paren_open + 1:paren_close].strip()
    return SharedLibraryCall(name=name, raw_args=raw_args)


# ---------------------------------------------------------------------------
# Format detection helper
# ---------------------------------------------------------------------------

def looks_like_jenkinsfile(path: Path, peek_bytes: int = 4096) -> bool:
    """Heuristic: filename is `Jenkinsfile` (any case) OR the first ~4KB
    of the file contain a `pipeline {` token at top level. Used by the
    CLI auto-detect path before we even try to YAML-parse the file."""
    if path.name.lower() == "jenkinsfile" or path.suffix.lower() in (".jenkinsfile", ".groovy"):
        return True
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(peek_bytes)
    except OSError:
        return False
    head = _strip_groovy_comments(head)
    return bool(re.search(r"\bpipeline\s*\{", head))
