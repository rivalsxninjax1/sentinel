"""CorrelationEngine — groups Findings from a scan by (endpoint, vulnerability
class) and reports whether independent sources agree or conflict.

Per docs/architecture.md §24: "if multiple tools identify the same issue, combine
the evidence." This engine does NOT mutate individual Finding rows — each source's
own confidence/verification_status (set by VerificationEngine) stays exactly as
determined. Correlation is a separate, additive read-model: a `Correlation` record
summarizing a group, with its own `combined_confidence` that callers (CLI summary,
future reporting) can use for an aggregate view without SENTINEL silently
overwriting any individual source's honest assessment.

Grouping requires at least 2 findings from at least 2 DISTINCT tool/scanner names —
two results from the same scanner running twice isn't independent corroboration
(docs/architecture.md §24's example specifically combines XSStrike + a custom
reflection analyzer + browser verification — three distinct sources, not the same
one repeated).
"""

from __future__ import annotations

from dataclasses import dataclass

_CONFIDENCE_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "confirmed": 4}


@dataclass
class CorrelationGroup:
    endpoint_id: str
    vulnerability_class: str
    finding_ids: list[str]
    tool_names: list[str]
    combined_confidence: str
    status: str  # "agreement" | "conflicting_evidence" | "insufficient_correlation"
    rationale: str


class CorrelationEngine:
    def correlate(self, findings: list[dict]) -> list[CorrelationGroup]:
        """`findings` is a list of plain dicts with keys: id, endpoint_id,
        vulnerability_class, tool_name, verification_status, confidence — kept as
        dicts (not ORM rows) so this engine has no database dependency and is
        trivially unit-testable."""
        groups: dict[tuple[str, str], list[dict]] = {}
        for f in findings:
            key = (f["endpoint_id"], f["vulnerability_class"])
            groups.setdefault(key, []).append(f)

        results: list[CorrelationGroup] = []
        for (endpoint_id, vuln_class), group in groups.items():
            distinct_tools = {f["tool_name"] for f in group}
            if len(group) < 2 or len(distinct_tools) < 2:
                continue  # not enough independent corroboration to correlate

            statuses = {f["verification_status"] for f in group}
            finding_ids = [f["id"] for f in group]

            if "false_positive" in statuses and "verified" in statuses:
                results.append(
                    CorrelationGroup(
                        endpoint_id=endpoint_id,
                        vulnerability_class=vuln_class,
                        finding_ids=finding_ids,
                        tool_names=sorted(distinct_tools),
                        combined_confidence="low",
                        status="conflicting_evidence",
                        rationale=(
                            f"{len(distinct_tools)} independent sources disagree: at "
                            f"least one verified this as a false positive via baseline "
                            f"comparison while another marked it verified — treat as "
                            f"NOT confirmed pending manual review"
                        ),
                    )
                )
                continue

            if statuses == {"verified"}:
                results.append(
                    CorrelationGroup(
                        endpoint_id=endpoint_id,
                        vulnerability_class=vuln_class,
                        finding_ids=finding_ids,
                        tool_names=sorted(distinct_tools),
                        combined_confidence="high",
                        status="agreement",
                        rationale=(
                            f"{len(distinct_tools)} independent sources "
                            f"({', '.join(sorted(distinct_tools))}) all verified this "
                            f"finding via baseline comparison"
                        ),
                    )
                )
                continue

            results.append(
                CorrelationGroup(
                    endpoint_id=endpoint_id,
                    vulnerability_class=vuln_class,
                    finding_ids=finding_ids,
                    tool_names=sorted(distinct_tools),
                    combined_confidence=_highest_individual_confidence(group),
                    status="insufficient_correlation",
                    rationale=(
                        f"{len(distinct_tools)} independent sources flagged the same "
                        f"issue but not all were verified — no confidence escalation applied"
                    ),
                )
            )

        return results


def _highest_individual_confidence(group: list[dict]) -> str:
    return max(group, key=lambda f: _CONFIDENCE_RANK.get(f["confidence"], 0))["confidence"]
