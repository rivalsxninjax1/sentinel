"""DeterministicScanner — the interface every custom (non-external-tool) detection
engine implements (docs/architecture.md §46: "if no mature tool solves it, implement
a focused deterministic scanner").

Unlike SecurityToolAdapter (app/tools/base.py), scanners here use SENTINEL's own
SentinelHTTPClient directly — no subprocess, no external binary. Scope and rate
limiting are already enforced by SentinelHTTPClient itself, so scanners don't need to
re-check scope; they just need to build a request and interpret the response.

Every scanner declares a `required_mode` — the minimum scan mode it needs to run.
`mode_allows()` is the single place that ordering is defined, so a new scanner can't
accidentally get the comparison backwards.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from app.core.http_client import SentinelHTTPClient
from app.tools.models import NormalizedFinding

_MODE_ORDER = {"passive": 0, "safe": 1, "active": 2}


def mode_allows(configured_mode: str, required_mode: str) -> bool:
    """True if a scan running in `configured_mode` is permitted to run a scanner
    that needs at least `required_mode`."""
    return _MODE_ORDER.get(configured_mode, -1) >= _MODE_ORDER.get(required_mode, 99)


@dataclass
class ScanTarget:
    url: str
    method: str = "GET"
    parameter_name: str | None = None
    parameter_location: str | None = None  # "query" | "form"


class DeterministicScanner(ABC):
    name: str
    vulnerability_class: str
    required_mode: str  # "passive" | "safe" | "active"

    @abstractmethod
    async def scan(
        self, target: ScanTarget, http_client: SentinelHTTPClient
    ) -> list[NormalizedFinding]:
        """Run this scanner's test against `target`. Findings returned here are
        candidates — see docs/architecture.md §21-22: nothing produced by a scanner
        is "confirmed" until Phase 9's Verification Engine says so. Every finding's
        metadata should include a `confidence` hint (default "low" if unsure)."""
        raise NotImplementedError
