"""HTML renderer — for viewing in a browser.

SECURITY NOTE, not a footnote: every string that originates from the scanned
target (finding titles built from reflected content, `matched_endpoint`,
`description`, `evidence`, and `metadata` values) is scanned/attacker-influenced
data, not SENTINEL's own text. A malicious target could shape its responses to
inject `<script>` or other markup into a finding's title/evidence specifically to
attack whoever later opens the HTML report. Every such value is passed through
`html.escape()` before being placed in output — nothing scanned-target-controlled
is ever written into this HTML unescaped. Only SENTINEL's own static labels
("Severity:", "CWE:", etc.) are written as raw HTML.
"""

from __future__ import annotations

from html import escape

from app.reporting.models import ReportData, ReportFinding

_DISPOSITION_ORDER = ["Confirmed", "Likely", "Potential", "Informational", "Requires Manual Verification"]

_DISPOSITION_COLORS = {
    "Confirmed": "#7f1d1d",
    "Likely": "#b91c1c",
    "Potential": "#b45309",
    "Informational": "#1d4ed8",
    "Requires Manual Verification": "#6b7280",
}


def render(report: ReportData) -> str:
    parts: list[str] = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        f"<title>SENTINEL Report - {escape(report.target_name)}</title>",
        "<style>",
        "body{font-family:-apple-system,Helvetica,Arial,sans-serif;max-width:900px;"
        "margin:2rem auto;padding:0 1rem;color:#1f2937;}"
        "h1{font-size:1.5rem;} h2{margin-top:2rem;border-bottom:1px solid #e5e7eb;"
        "padding-bottom:.25rem;}"
        ".finding{border:1px solid #e5e7eb;border-radius:8px;padding:1rem;margin:1rem 0;}"
        ".badge{display:inline-block;padding:.15rem .5rem;border-radius:4px;color:white;"
        "font-size:.8rem;margin-right:.5rem;}"
        "table{border-collapse:collapse;} td,th{padding:.25rem .75rem;text-align:left;"
        "border-bottom:1px solid #e5e7eb;}"
        "pre{background:#f9fafb;padding:.75rem;border-radius:6px;overflow-x:auto;}",
        "</style></head><body>",
        f"<h1>SENTINEL Security Report — {escape(report.target_name)}</h1>",
        f"<p><strong>Scan ID:</strong> {escape(report.scan_id)}<br>"
        f"<strong>Scan mode:</strong> {escape(report.scan_mode)}<br>"
        f"<strong>Generated:</strong> {escape(report.generated_at.isoformat())}</p>",
        "<h2>Summary</h2><table>",
    ]

    for label in _DISPOSITION_ORDER:
        count = report.summary_by_disposition.get(label, 0)
        if count:
            color = _DISPOSITION_COLORS.get(label, "#6b7280")
            parts.append(
                f"<tr><td><span class='badge' style='background:{color}'>"
                f"{escape(label)}</span></td><td>{count}</td></tr>"
            )
    parts.append("</table>")

    if report.excluded_false_positives:
        parts.append(
            f"<p><em>{len(report.excluded_false_positives)} finding(s) were excluded "
            f"as false positives after baseline verification — see appendix below.</em></p>"
        )

    grouped: dict[str, list[ReportFinding]] = {}
    for f in report.findings:
        grouped.setdefault(f.disposition, []).append(f)

    for label in _DISPOSITION_ORDER:
        group = grouped.get(label)
        if not group:
            continue
        parts.append(f"<h2>{escape(label)} ({len(group)})</h2>")
        for finding in group:
            parts.append(_render_finding(finding))

    if report.excluded_false_positives:
        parts.append("<h2>Appendix: Excluded False Positives</h2>")
        parts.append(
            "<p>The following candidates were flagged by a scanner but ruled out by "
            "baseline/differential comparison — listed here for audit-trail "
            "transparency only, not as vulnerabilities.</p><ul>"
        )
        for finding in report.excluded_false_positives:
            parts.append(
                f"<li><strong>{escape(finding.title)}</strong> — "
                f"<code>{escape(finding.matched_endpoint)}</code></li>"
            )
        parts.append("</ul>")

    parts.append("</body></html>")
    return "\n".join(parts)


def _render_finding(f: ReportFinding) -> str:
    color = _DISPOSITION_COLORS.get(f.disposition, "#6b7280")
    parts = [
        "<div class='finding'>",
        f"<span class='badge' style='background:{color}'>{escape(f.disposition)}</span>",
        f"<strong>{escape(f.title)}</strong>",
        "<table>",
        f"<tr><td>Vulnerability class</td><td>{escape(f.vulnerability_class)}</td></tr>",
        f"<tr><td>Severity</td><td>{escape(f.severity)}</td></tr>",
        f"<tr><td>Confidence</td><td>{escape(f.confidence)}</td></tr>",
        f"<tr><td>Verification status</td><td>{escape(f.verification_status)}</td></tr>",
        f"<tr><td>Endpoint</td><td><code>{escape(f.matched_endpoint)}</code></td></tr>",
    ]
    if f.cwe_id:
        parts.append(f"<tr><td>CWE</td><td>{escape(f.cwe_id)} — {escape(f.cwe_name or '')}</td></tr>")
    if f.approximate_cvss is not None:
        parts.append(
            f"<tr><td>Approximate CVSS (severity-based estimate)</td><td>{f.approximate_cvss}</td></tr>"
        )
    if f.correlation:
        parts.append(
            f"<tr><td>Correlation</td><td>{escape(f.correlation.status)} across "
            f"{escape(', '.join(f.correlation.tool_names))} (combined confidence: "
            f"{escape(f.correlation.combined_confidence)})</td></tr>"
        )
    parts.append("</table>")
    parts.append(f"<p><strong>Description:</strong> {escape(f.description)}</p>")
    if f.impact:
        parts.append(f"<p><strong>Impact:</strong> {escape(f.impact)}</p>")
    if f.remediation:
        parts.append(f"<p><strong>Remediation:</strong> {escape(f.remediation)}</p>")
    if f.evidence:
        parts.append("<p><strong>Evidence:</strong></p>")
        for e in f.evidence:
            parts.append(f"<pre>{escape(e)}</pre>")
    parts.append("</div>")
    return "\n".join(parts)
