import json
from datetime import datetime, timezone

from app.reporting.models import CorrelationSummary, ReportData, ReportFinding
from app.reporting.renderers import html_renderer, json_renderer, markdown_renderer


def _finding(**overrides) -> ReportFinding:
    defaults = dict(
        id="f1",
        title="Unescaped reflection via parameter 'q'",
        vulnerability_class="xss",
        severity="medium",
        confidence="medium",
        verification_status="verified",
        disposition="Potential",
        matched_endpoint="https://app.example.com/search?q=x",
        description="injected marker reflected unescaped",
        metadata={"parameter": "q"},
        evidence=["marker reflected unescaped in response body"],
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        cwe_id="CWE-79",
        cwe_name="Cross-site Scripting",
        impact="Allows script execution in victims' browsers.",
        remediation="Context-appropriate output encoding.",
        approximate_cvss=5.4,
        correlation=None,
    )
    defaults.update(overrides)
    return ReportFinding(**defaults)


def _report(**overrides) -> ReportData:
    defaults = dict(
        scan_id="scan-1",
        target_name="Example Target",
        scan_mode="safe",
        generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        findings=[_finding()],
        excluded_false_positives=[],
        summary_by_disposition={"Potential": 1},
        summary_by_severity={"medium": 1},
    )
    defaults.update(overrides)
    return ReportData(**defaults)


def test_json_renderer_round_trips_and_includes_key_fields():
    report = _report()
    output = json_renderer.render(report)
    data = json.loads(output)

    assert data["scan_id"] == "scan-1"
    assert data["target_name"] == "Example Target"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["cwe_id"] == "CWE-79"
    assert data["findings"][0]["disposition"] == "Potential"
    assert "2026-01-01" in data["generated_at"]


def test_json_renderer_includes_correlation_when_present():
    finding = _finding(
        correlation=CorrelationSummary(
            tool_names=["reflected_xss", "xsstrike"],
            status="agreement",
            combined_confidence="high",
            rationale="both sources verified",
        )
    )
    report = _report(findings=[finding])
    data = json.loads(json_renderer.render(report))

    assert data["findings"][0]["correlation"]["status"] == "agreement"


def test_markdown_renderer_includes_summary_and_finding_sections():
    report = _report()
    output = markdown_renderer.render(report)

    assert "# SENTINEL Security Report" in output
    assert "## Potential (1)" in output
    assert "Unescaped reflection via parameter 'q'" in output
    assert "CWE-79" in output
    assert "Approximate CVSS" in output


def test_markdown_renderer_includes_false_positive_appendix():
    fp_finding = _finding(id="fp1", verification_status="false_positive", title="False positive candidate")
    report = _report(excluded_false_positives=[fp_finding])
    output = markdown_renderer.render(report)

    assert "Appendix: Excluded False Positives" in output
    assert "False positive candidate" in output


def test_markdown_renderer_groups_by_disposition_in_priority_order():
    likely = _finding(id="f1", disposition="Likely", title="Likely finding")
    potential = _finding(id="f2", disposition="Potential", title="Potential finding")
    report = _report(
        findings=[potential, likely],  # deliberately out of priority order
        summary_by_disposition={"Likely": 1, "Potential": 1},
    )
    output = markdown_renderer.render(report)

    assert output.index("## Likely") < output.index("## Potential")


def test_html_renderer_escapes_hostile_title():
    hostile = _finding(title="<script>alert(document.cookie)</script>")
    report = _report(findings=[hostile])
    output = html_renderer.render(report)

    assert "<script>alert(document.cookie)</script>" not in output
    assert "&lt;script&gt;" in output


def test_html_renderer_escapes_hostile_evidence():
    hostile = _finding(evidence=["<img src=x onerror=alert(1)>"])
    report = _report(findings=[hostile])
    output = html_renderer.render(report)

    assert "<img src=x onerror=alert(1)>" not in output
    assert "&lt;img" in output


def test_html_renderer_escapes_hostile_matched_endpoint():
    hostile = _finding(matched_endpoint="https://app.example.com/x?q=<script>bad()</script>")
    report = _report(findings=[hostile])
    output = html_renderer.render(report)

    assert "<script>bad()</script>" not in output


def test_html_renderer_escapes_hostile_target_name():
    report = _report(target_name="<script>alert(1)</script>")
    output = html_renderer.render(report)

    assert "<script>alert(1)</script>" not in output
    assert "&lt;script&gt;" in output


def test_html_renderer_produces_valid_looking_document():
    report = _report()
    output = html_renderer.render(report)

    assert output.startswith("<!DOCTYPE html>")
    assert output.rstrip().endswith("</html>")
    assert "<title>" in output
