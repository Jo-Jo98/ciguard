"""
ciguard LLM client.

Supports Anthropic Claude (primary) and OpenAI (fallback).
API keys via environment variables:
  ANTHROPIC_API_KEY  -> Claude (default provider)
  OPENAI_API_KEY     -> OpenAI

Only sanitised scan data is sent — evidence fields containing
partial credential values are excluded before calling the API.
"""
from __future__ import annotations

import os
from typing import Optional

DEFAULT_ANTHROPIC_MODEL = "claude-haiku-4-5-20251001"
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"


def call_llm(
    prompt: str,
    system: str,
    provider: str = "anthropic",
    model: Optional[str] = None,
) -> str:
    """Call the LLM and return the response text."""
    if provider == "anthropic":
        return _call_anthropic(prompt, system, model or DEFAULT_ANTHROPIC_MODEL)
    if provider == "openai":
        return _call_openai(prompt, system, model or DEFAULT_OPENAI_MODEL)
    raise ValueError(f"Unknown LLM provider: {provider!r}. Use 'anthropic' or 'openai'.")


def detect_provider() -> Optional[str]:
    """Return the first provider with a key set in the environment."""
    if os.getenv("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.getenv("OPENAI_API_KEY"):
        return "openai"
    return None


# ---------------------------------------------------------------------------
# Provider implementations
# ---------------------------------------------------------------------------

def _call_anthropic(prompt: str, system: str, model: str) -> str:
    try:
        import anthropic
    except ImportError as exc:
        raise RuntimeError(
            "anthropic package not installed. Run: pip install anthropic"
        ) from exc

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY environment variable is not set.")

    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model=model,
        max_tokens=1024,
        system=system,
        messages=[{"role": "user", "content": prompt}],
    )
    return message.content[0].text


def _call_openai(prompt: str, system: str, model: str) -> str:
    try:
        import openai
    except ImportError as exc:
        raise RuntimeError(
            "openai package not installed. Run: pip install openai"
        ) from exc

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY environment variable is not set.")

    client = openai.OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
        max_tokens=1024,
    )
    return response.choices[0].message.content
