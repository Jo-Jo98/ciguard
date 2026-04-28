"""Atheris coverage-guided fuzz harness for ciguard's three parsers.

Dispatches a single FuzzedDataProvider stream into one of:
  GitLabCIParser    — YAML-driven, uses yaml.SafeLoader
  GitHubActionsParser — YAML-driven, uses yaml.SafeLoader
  JenkinsfileParser  — hand-rolled Groovy-aware parser (highest-risk surface
                       per Cycle 1 threat model — no upstream parser library
                       to inherit hardening from)

Designed for the weekly cron in `.github/workflows/atheris-fuzz.yml`. Cycle 1
ran 220k iterations in ~2 minutes against three parsers and surfaced no
crashes; weekly 1M-iteration runs are cheap and catch regressions across new
rule additions or parser refactors.

Run locally:
  pip install -e ".[fuzz]"   # adds atheris to dev deps
  python tests/fuzz/fuzz_parsers.py -atheris_runs=200000

Run in CI: see .github/workflows/atheris-fuzz.yml.

Expected exceptions are caught silently — only crashes (uncaught exceptions
NOT in EXPECTED), hangs, or sanitizer-detected memory bugs cause failure.
"""
import sys

import atheris

with atheris.instrument_imports():
    from ciguard.parser.gitlab_parser import GitLabCIParser
    from ciguard.parser.github_actions import GitHubActionsParser
    from ciguard.parser.jenkinsfile import JenkinsfileParser

# Exceptions expected on bad input. Anything outside this set is a real bug.
EXPECTED = (
    ValueError,
    KeyError,
    TypeError,
    AttributeError,
    UnicodeDecodeError,
    UnicodeEncodeError,
)

_gitlab = GitLabCIParser()
_gha = GitHubActionsParser()
_jenkins = JenkinsfileParser()


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    target = fdp.ConsumeIntInRange(0, 2)
    # Cap input size at 64KB. Realistic pipeline files sit in 1-30KB range;
    # the cap stops the fuzzer wasting iterations on multi-MB inputs that
    # mostly exercise YAML's tokenizer rather than ciguard's logic.
    payload = fdp.ConsumeUnicodeNoSurrogates(65536)

    try:
        if target == 0:
            # Both YAML parsers expect a parsed dict; mirror what the real
            # CLI path does (yaml.safe_load → parse).
            import yaml
            doc = yaml.safe_load(payload)
            if isinstance(doc, dict):
                _gitlab.parse(doc)
        elif target == 1:
            import yaml
            doc = yaml.safe_load(payload)
            if isinstance(doc, dict):
                _gha.parse(doc)
        else:
            # Jenkinsfile parser is hand-rolled and accepts raw text.
            _jenkins.parse(payload)
    except EXPECTED:
        # Bad input → handled exception. Not a bug.
        pass
    except yaml.YAMLError:
        # YAML parse error from a fuzzed string is expected and not a ciguard bug.
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    # Force-import yaml here so atheris.instrument_imports (above) instruments
    # the parsers' YAML lib alongside ciguard. The reference assignment below
    # ensures static analysers see the import as used.
    import yaml
    _ = yaml.__name__
    main()
