"""Markdown renderer — human-readable, suitable for pasting into an issue tracker
or reading in a terminal/editor. Findings are grouped by disposition (Confirmed
first if ever present, then Likely, Potential, Informational, Requires Manual
Verification) so the most actionable items are always at the top regardless of
scan order.
"""

from __future__ import annotations

from app.reporting.models import ReportData, ReportFinding

_DISPOSITION_ORDER = ["Confirmed", "Likely", "Potential", "Informational", "Requires Manual Verification"]


def render(report: ReportData) -> str:
    lines: list[str] = []
    lines.append(f"# SENTINEL Security Report — {report.target_name}")
    lines.append("")
    lines.append(f"- **Scan ID:** {report.scan_id}")
    lines.append(f"- **Scan mode:** {report.scan_mode}")
    lines.append(f"- **Generated:** {report.generated_at.isoformat()}")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Disposition | Count |")
    lines.append("|---|---|")
    for label in _DISPOSITION_ORDER:
        count = report.summary_by_disposition.get(label, 0)
        if count:
            lines.append(f"| {label} | {count} |")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for severity in ("critical", "high", "medium", "low", "info"):
        count = report.summary_by_severity.get(severity, 0)
        if count:
            lines.append(f"| {severity} | {count} |")
    lines.append("")

    if report.excluded_false_positives:
        lines.append(
            f"*{len(report.excluded_false_positives)} finding(s) were excluded as false "
            f"positives after baseline verification — see appendix below.*"
        )
        lines.append("")

    grouped: dict[str, list[ReportFinding]] = {}
    for f in report.findings:
        grouped.setdefault(f.disposition, []).append(f)

    for label in _DISPOSITION_ORDER:
        group = grouped.get(label)
        if not group:
            continue
        lines.append(f"## {label} ({len(group)})")
        lines.append("")
        for finding in group:
            lines.extend(_render_finding(finding))

    if report.excluded_false_positives:
        lines.append("## Appendix: Excluded False Positives")
        lines.append("")
        lines.append(
            "The following candidates were flagged by a scanner but ruled out by "
            "baseline/differential comparison (the same signature appeared even "
            "without any payload) — listed here for audit-trail transparency only, "
            "not as vulnerabilities."
        )
        lines.append("")
        for finding in report.excluded_false_positives:
            lines.append(f"- **{finding.title}** — `{finding.matched_endpoint}`")
        lines.append("")

    return "\n".join(lines)


def _render_finding(f: ReportFinding) -> list[str]:
    lines = [f"### {f.title}", ""]
    lines.append(f"- **Vulnerability class:** {f.vulnerability_class}")
    lines.append(f"- **Severity:** {f.severity}")
    lines.append(f"- **Confidence:** {f.confidence}")
    lines.append(f"- **Verification status:** {f.verification_status}")
    lines.append(f"- **Endpoint:** `{f.matched_endpoint}`")
    if f.cwe_id:
        lines.append(f"- **CWE:** {f.cwe_id} — {f.cwe_name}")
    if f.approximate_cvss is not None:
        lines.append(f"- **Approximate CVSS (severity-based estimate):** {f.approximate_cvss}")
    if f.correlation:
        lines.append(
            f"- **Correlation:** {f.correlation.status} across "
            f"{', '.join(f.correlation.tool_names)} (combined confidence: "
            f"{f.correlation.combined_confidence})"
        )
    lines.append("")
    lines.append(f"**Description:** {f.description}")
    lines.append("")
    if f.impact:
        lines.append(f"**Impact:** {f.impact}")
        lines.append("")
    if f.remediation:
        lines.append(f"**Remediation:** {f.remediation}")
        lines.append("")
    if f.evidence:
        lines.append("**Evidence:**")
        lines.append("```")
        for e in f.evidence:
            lines.append(e)
        lines.append("```")
        lines.append("")
    return lines
