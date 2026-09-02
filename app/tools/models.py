"""Shared data shapes for the tool-adapter layer."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class NormalizedFinding:
    """The only shape the rest of SENTINEL understands from an external tool.

    Deliberately does NOT include a "confirmed" flag — see docs/architecture.md §21:
    every result here is still a candidate until it passes through the Verification
    Engine (Phase 9). `severity` reflects the tool's own claim, not SENTINEL's
    assessment.
    """

    tool_name: str
    tool_version: str | None
    title: str
    severity: str  # "info" | "low" | "medium" | "high" | "critical"
    matched_endpoint: str
    raw_output: str
    metadata: dict = field(default_factory=dict)
