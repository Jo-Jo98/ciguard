"""
ciguard scanner integration base class.

All external scanner integrations extend ScannerBase.
They follow the same contract:
  - is_available() — returns True if the tool is installed
  - scan(path) — runs the tool and returns a list of ScannerFindings
  - name — short identifier used in attribution

Scanners are optional — the tool works fully without any of them.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel


class ScannerFinding(BaseModel):
    """A finding produced by an external scanner tool."""
    scanner:     str         # scanner name, e.g. "semgrep", "scorecard"
    rule_id:     str         # tool-specific rule / check ID
    name:        str
    description: str
    severity:    str         # "Critical" | "High" | "Medium" | "Low" | "Info"
    location:    str         # file path or check name
    evidence:    str = ""
    remediation: str = ""
    url:         Optional[str] = None  # link to rule docs


class ScannerBase(ABC):
    """Abstract base for all external scanner integrations."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Short lower-case identifier, e.g. 'semgrep'."""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the underlying CLI tool is installed."""

    @abstractmethod
    def scan(self, path: Path) -> List[ScannerFinding]:
        """Run the scanner against ``path`` (a file or directory).
        Returns scanner findings.  Must not raise — return [] on error.
        """
