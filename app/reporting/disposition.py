"""Maps SENTINEL's internal (verification_status, confidence) pair onto the
report-facing disposition categories docs/architecture.md §40 requires every report
to distinguish: Confirmed | Likely | Potential | Informational | Requires Manual
Verification.

This mapping is the single place that decides what a person reading a report is
told about how certain a finding is — get it wrong here and every report downstream
inherits the mistake, so the rules are deliberately simple and documented inline
rather than clever.
"""

from __future__ import annotations

_CONFIDENCE_TO_DISPOSITION = {
    "info": "Informational",
    "low": "Potential",
    "medium": "Potential",
    "high": "Likely",
    # "confirmed" is mapped here for completeness only. As of this codebase, no
    # scanner, tool adapter, VerificationEngine, or CorrelationEngine ever sets
    # confidence to "confirmed" (see app/verification/engine.py's hard cap at
    # "high") — this branch exists so the mapping is total, not because it's
    # expected to be hit. If a future manual sign-off workflow introduces
    # "confirmed", it should map here and only here.
    "confirmed": "Confirmed",
}

_APPROXIMATE_CVSS_BY_SEVERITY = {
    "info": None,
    "low": 3.1,
    "medium": 5.4,
    "high": 7.5,
    "critical": 9.0,
}


def disposition(verification_status: str, confidence: str) -> str:
    """Returns the report-facing disposition label. `false_positive` findings
    should never reach this function at all — callers (see
    app/reporting/builder.py) exclude them from the main report before this point,
    listing them in a separate excluded/appendix section instead."""
    if verification_status in ("needs_manual_review", "unverified"):
        return "Requires Manual Verification"
    return _CONFIDENCE_TO_DISPOSITION.get(confidence, "Requires Manual Verification")


def approximate_cvss(severity: str) -> float | None:
    """A deliberately rough severity-to-CVSS-base-score approximation, NOT a real
    CVSS vector calculation (which requires attack-vector/complexity/privileges/
    scope/impact sub-metrics SENTINEL doesn't determine). Every report that
    includes this number must present it as approximate — see the renderers, which
    all label this field "Approximate CVSS (severity-based estimate)" rather than
    "CVSS Score" unqualified, to avoid overstating precision SENTINEL doesn't have.
    """
    return _APPROXIMATE_CVSS_BY_SEVERITY.get(severity)
