"""ReportBuilder — assembles a ReportData object from a scan's persisted Findings,
Evidence, and Correlations. This is the only place database rows get converted into
report-facing shapes; all three renderers consume the same ReportData, so none of
them can show different numbers for the same scan.

Per docs/architecture.md §40 ("do not present speculative findings as confirmed")
and the non-negotiable rule against reporting speculative results: findings whose
`verification_status` is `"false_positive"` are excluded from the main report
entirely and listed separately (`excluded_false_positives`) for audit-trail
transparency, never mixed into the primary findings list.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.reporting.disposition import approximate_cvss, disposition
from app.reporting.knowledge_base import get_knowledge
from app.reporting.models import CorrelationSummary, ReportData, ReportFinding
from app.storage.repository import FindingsRepository, ScanRepository, TargetRepository


class ReportBuilder:
    def __init__(
        self,
        scan_repo: ScanRepository,
        target_repo: TargetRepository,
        findings_repo: FindingsRepository,
    ) -> None:
        self._scans = scan_repo
        self._targets = target_repo
        self._findings = findings_repo

    async def build(self, scan_id: str) -> ReportData:
        scan = await self._scans.get(scan_id)
        if scan is None:
            raise ValueError(f"No such scan: {scan_id}")
        target = await self._targets.get(scan.target_id)

        all_findings = await self._findings.list_findings_for_scan(scan_id)
        correlations = await self._findings.list_correlations_for_scan(scan_id)

        # Map finding_id -> CorrelationSummary for O(1) lookup while building
        # ReportFinding objects below.
        correlation_by_finding_id: dict[str, CorrelationSummary] = {}
        for corr in correlations:
            summary = CorrelationSummary(
                tool_names=corr.tool_names_json,
                status=corr.status,
                combined_confidence=corr.combined_confidence,
                rationale=corr.rationale,
            )
            for finding_id in corr.finding_ids_json:
                correlation_by_finding_id[finding_id] = summary

        included: list[ReportFinding] = []
        excluded: list[ReportFinding] = []

        for f in all_findings:
            evidence_rows = await self._findings.list_evidence_for_finding(f.id)
            evidence_text = [e.content for e in evidence_rows]

            kb = get_knowledge(f.vulnerability_class)

            report_finding = ReportFinding(
                id=f.id,
                title=f.title,
                vulnerability_class=f.vulnerability_class,
                severity=f.severity,
                confidence=f.confidence,
                verification_status=f.verification_status,
                disposition=disposition(f.verification_status, f.confidence),
                matched_endpoint=f.matched_endpoint,
                description=f.description,
                metadata=f.metadata_json or {},
                evidence=evidence_text,
                created_at=f.created_at,
                cwe_id=kb.cwe_id if kb else None,
                cwe_name=kb.cwe_name if kb else None,
                impact=kb.impact if kb else None,
                remediation=kb.remediation if kb else None,
                approximate_cvss=approximate_cvss(f.severity),
                correlation=correlation_by_finding_id.get(f.id),
            )

            if f.verification_status == "false_positive":
                excluded.append(report_finding)
            else:
                included.append(report_finding)

        summary_by_disposition: dict[str, int] = {}
        summary_by_severity: dict[str, int] = {}
        for rf in included:
            summary_by_disposition[rf.disposition] = summary_by_disposition.get(rf.disposition, 0) + 1
            summary_by_severity[rf.severity] = summary_by_severity.get(rf.severity, 0) + 1

        return ReportData(
            scan_id=scan_id,
            target_name=target.name if target else "unknown",
            scan_mode=scan.mode,
            generated_at=datetime.now(timezone.utc),
            findings=included,
            excluded_false_positives=excluded,
            summary_by_disposition=summary_by_disposition,
            summary_by_severity=summary_by_severity,
        )
