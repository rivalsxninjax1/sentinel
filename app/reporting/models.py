"""Data shapes for an assembled report — deliberately plain dataclasses so the
three renderers (JSON/Markdown/HTML) all consume exactly the same structure and
none of them can drift from what the others show.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class CorrelationSummary:
    tool_names: list[str]
    status: str  # "agreement" | "conflicting_evidence" | "insufficient_correlation"
    combined_confidence: str
    rationale: str


@dataclass
class ReportFinding:
    id: str
    title: str
    vulnerability_class: str
    severity: str
    confidence: str
    verification_status: str
    disposition: str  # Confirmed | Likely | Potential | Informational | Requires Manual Verification
    matched_endpoint: str
    description: str
    metadata: dict
    evidence: list[str]
    created_at: datetime
    cwe_id: str | None = None
    cwe_name: str | None = None
    impact: str | None = None
    remediation: str | None = None
    approximate_cvss: float | None = None
    correlation: CorrelationSummary | None = None


@dataclass
class ReportData:
    scan_id: str
    target_name: str
    scan_mode: str
    generated_at: datetime
    findings: list[ReportFinding] = field(default_factory=list)
    excluded_false_positives: list[ReportFinding] = field(default_factory=list)
    summary_by_disposition: dict[str, int] = field(default_factory=dict)
    summary_by_severity: dict[str, int] = field(default_factory=dict)
