import pytest

from app.reporting.builder import ReportBuilder
from app.storage.db import get_engine, init_db, make_session_factory, session_scope
from app.storage.repository import (
    AttackSurfaceRepository,
    FindingsRepository,
    ScanRepository,
    TargetRepository,
)
from app.tools.models import NormalizedFinding


@pytest.mark.asyncio
async def test_build_excludes_false_positives_and_computes_summaries(tmp_path):
    db_path = tmp_path / "test.db"
    engine = get_engine(str(db_path))
    await init_db(engine)
    session_factory = make_session_factory(engine)

    async with session_scope(session_factory) as session:
        targets = TargetRepository(session)
        scans = ScanRepository(session)
        attack_surface = AttackSurfaceRepository(session)
        findings_repo = FindingsRepository(session)

        target = await targets.create("report-test-target", {"allow": ["app.example.com"], "deny": []})
        scan = await scans.create(target.id, "safe", {})
        host = await attack_surface.get_or_create_host(target.id, "app.example.com", scan.id)
        endpoint = await attack_surface.get_or_create_endpoint(
            host.id, "/search", "GET", scan.id, source="crawl"
        )

        # one verified, high-confidence finding -> "Likely"
        test1 = await findings_repo.create_test(scan.id, endpoint.id, "xss", "reflected_xss")
        f1 = await findings_repo.create_finding_from_normalized(
            scan.id,
            test1.id,
            NormalizedFinding(
                tool_name="reflected_xss",
                tool_version=None,
                title="XSS finding",
                severity="medium",
                matched_endpoint="https://app.example.com/search?q=x",
                raw_output="marker reflected",
                metadata={"parameter": "q", "confidence": "high", "vulnerability_class": "xss"},
            ),
        )
        await findings_repo.update_verification(f1.id, "verified", "high")

        # one false-positive finding -> excluded from main report
        test2 = await findings_repo.create_test(scan.id, endpoint.id, "ssti", "ssti")
        f2 = await findings_repo.create_finding_from_normalized(
            scan.id,
            test2.id,
            NormalizedFinding(
                tool_name="ssti",
                tool_version=None,
                title="SSTI false positive",
                severity="high",
                matched_endpoint="https://app.example.com/render?name=x",
                raw_output="49 always present",
                metadata={"parameter": "name", "confidence": "low", "vulnerability_class": "ssti"},
            ),
        )
        await findings_repo.update_verification(f2.id, "false_positive", "low")

        # one needs-manual-review finding -> "Requires Manual Verification"
        test3 = await findings_repo.create_test(scan.id, endpoint.id, "idor_bola", "idor_candidate")
        f3 = await findings_repo.create_finding_from_normalized(
            scan.id,
            test3.id,
            NormalizedFinding(
                tool_name="idor_candidate",
                tool_version=None,
                title="IDOR candidate",
                severity="info",
                matched_endpoint="https://app.example.com/orders?order_id=1",
                raw_output="object identifier param name",
                metadata={"parameter": "order_id", "confidence": "info", "vulnerability_class": "idor_bola"},
            ),
        )
        await findings_repo.update_verification(f3.id, "needs_manual_review", "info")

        scan_id = scan.id

    async with session_scope(session_factory) as session:
        builder = ReportBuilder(
            ScanRepository(session), TargetRepository(session), FindingsRepository(session)
        )
        report = await builder.build(scan_id)

    assert report.target_name == "report-test-target"
    assert len(report.findings) == 2  # f1 and f3; f2 excluded
    assert len(report.excluded_false_positives) == 1
    assert report.excluded_false_positives[0].title == "SSTI false positive"

    dispositions = {f.title: f.disposition for f in report.findings}
    assert dispositions["XSS finding"] == "Likely"
    assert dispositions["IDOR candidate"] == "Requires Manual Verification"

    assert report.summary_by_disposition["Likely"] == 1
    assert report.summary_by_disposition["Requires Manual Verification"] == 1
    assert "Likely" not in {f.disposition for f in report.excluded_false_positives}

    # knowledge base fields populated
    xss_finding = next(f for f in report.findings if f.title == "XSS finding")
    assert xss_finding.cwe_id == "CWE-79"
    assert xss_finding.approximate_cvss == 5.4
    assert xss_finding.evidence == ["marker reflected"]

    await engine.dispose()


@pytest.mark.asyncio
async def test_build_raises_for_unknown_scan(tmp_path):
    db_path = tmp_path / "test.db"
    engine = get_engine(str(db_path))
    await init_db(engine)
    session_factory = make_session_factory(engine)

    async with session_scope(session_factory) as session:
        builder = ReportBuilder(
            ScanRepository(session), TargetRepository(session), FindingsRepository(session)
        )
        with pytest.raises(ValueError):
            await builder.build("nonexistent-scan-id")

    await engine.dispose()
