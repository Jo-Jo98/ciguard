"""
Inventory data models (Slice 14b).

A live audit of the CI/CD *tooling* a customer runs (Jenkins / GitLab
self-host / GitHub Enterprise / Nexus / Artifactory / SonarQube /
ArgoCD / Harbor) — distinct from the *pipeline-content* scanning that
the rest of ciguard does. Each tool gets one `InventoryEntry`; the full
sweep returns one `InventoryReport`.

Two pydantic models so we can serialise to JSON / HTML and round-trip
through reports the same way pipeline `Report` already does.
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class InventoryEntry(BaseModel):
    """One row in the infrastructure inventory.

    `tool` is the canonical short name (e.g. `jenkins`, `gitlab-self-host`,
    `github-enterprise`). `version` is the literal version string the
    server returned. `eol_date` / `eos_date` are ISO date strings populated
    when endoflife.date has a matching cycle for `version`.

    `error` carries a human-readable message when the probe ran but
    couldn't resolve the version (network timeout, auth failed, server
    returned malformed JSON). Empty `error` + non-empty `version` = clean
    probe. Non-empty `error` is also reported in the audit so the
    operator can debug without re-running.

    `configured` is False for tools the operator has not provided env vars
    for. The runner emits one entry per *known* tool — but only entries
    where `configured=True` actually attempted the probe."""
    tool: str
    base_url: Optional[str] = None
    configured: bool = False
    version: Optional[str] = None
    edition: Optional[str] = None
    license: Optional[str] = None
    eol_date: Optional[str] = None
    eos_date: Optional[str] = None
    days_until_eol: Optional[int] = None
    days_until_eos: Optional[int] = None
    notes: List[str] = Field(default_factory=list)
    error: Optional[str] = None
    raw: dict = Field(default_factory=dict)

    @property
    def status(self) -> str:
        """Single-word status for table rendering. Order of precedence:
        unconfigured < error < end-of-life < end-of-support < ok."""
        if not self.configured:
            return "unconfigured"
        if self.error:
            return "error"
        if self.days_until_eol is not None and self.days_until_eol < 0:
            return "end-of-life"
        if self.days_until_eos is not None and self.days_until_eos < 0:
            return "end-of-support"
        if self.days_until_eol is not None and self.days_until_eol <= 180:
            return "approaching-eol"
        return "ok"


class InventoryReport(BaseModel):
    """Output of one `ciguard inventory` run."""
    entries: List[InventoryEntry] = Field(default_factory=list)
    scan_timestamp: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z"
    )
    scanner_version: str = "ciguard"

    @property
    def configured_count(self) -> int:
        return sum(1 for e in self.entries if e.configured)

    @property
    def has_findings(self) -> bool:
        """True when at least one configured entry is not `ok` (i.e. there's
        something an auditor should look at)."""
        return any(
            e.status not in {"ok", "unconfigured"}
            for e in self.entries
        )
