import pytest

from app.storage.db import get_engine, init_db, make_session_factory, session_scope
from app.storage.repository import (
    AttackSurfaceRepository,
    FindingsRepository,
    IntelligenceRepository,
    ScanRepository,
    TargetRepository,
)
from app.tools.models import NormalizedFinding


@pytest.mark.asyncio
async def test_attack_surface_persistence_roundtrip(tmp_path):
    db_path = tmp_path / "test.db"
    engine = get_engine(str(db_path))
    await init_db(engine)
    session_factory = make_session_factory(engine)

    async with session_scope(session_factory) as session:
        targets = TargetRepository(session)
        scans = ScanRepository(session)
        attack_surface = AttackSurfaceRepository(session)

        target = await targets.create("test-target", {"allow": ["app.example.com"], "deny": []})
        scan = await scans.create(target.id, "passive", {})

        host = await attack_surface.get_or_create_host(target.id, "app.example.com", scan.id)
        same_host = await attack_surface.get_or_create_host(target.id, "app.example.com", scan.id)
        assert host.id == same_host.id  # dedup

        endpoint = await attack_surface.get_or_create_endpoint(
            host.id, "/login", "POST", scan.id, source="crawl"
        )
        same_endpoint = await attack_surface.get_or_create_endpoint(
            host.id, "/login", "POST", scan.id, source="crawl"
        )
        assert endpoint.id == same_endpoint.id  # dedup

        await attack_surface.add_parameter(endpoint.id, "username", "form", "")
        await attack_surface.add_parameter(endpoint.id, "username", "form", "")  # dedup, no error

        await attack_surface.add_form(endpoint.id, "POST", "https://app.example.com/login", [{"name": "username"}])

        await attack_surface.add_technology(host.id, "Nginx", "1.24.0", "high", "header:server")
        await attack_surface.add_technology(host.id, "Nginx", "1.24.0", "high", "header:server")  # dedup

        endpoints = await attack_surface.list_endpoints_for_host(host.id)
        assert len(endpoints) == 1
        assert len(endpoints[0].parameters) == 1
        assert len(endpoints[0].forms) == 1

        asset = await attack_surface.add_javascript_asset(
            host.id, "https://app.example.com/app.js", True, "app.js.map", scan.id
        )
        same_asset = await attack_surface.add_javascript_asset(
            host.id, "https://app.example.com/app.js", False, None, scan.id
        )
        assert asset.id == same_asset.id  # dedup by (host, url)

        intelligence = IntelligenceRepository(session)
        await intelligence.add_classification(
            scan_id=scan.id,
            endpoint_id=endpoint.id,
            parameter_id=None,
            classification="identifier",
            risk_score=8,
            recommended_tests=["bola", "authorization"],
            reason="test reason",
            source="ai",
        )
        classifications = await intelligence.list_for_scan(scan.id)
        assert len(classifications) == 1
        assert classifications[0].risk_score == 8
        assert classifications[0].source == "ai"

        findings_repo = FindingsRepository(session)
        test_record = await findings_repo.create_test(
            scan_id=scan.id,
            endpoint_id=endpoint.id,
            vulnerability_class="xss",
            scanner_name="reflected_xss",
            parameter_id=None,
        )
        normalized = NormalizedFinding(
            tool_name="reflected_xss",
            tool_version=None,
            title="Unescaped reflection via parameter 'q'",
            severity="medium",
            matched_endpoint="https://app.example.com/search?q=x",
            raw_output="marker reflected unescaped",
            metadata={"vulnerability_class": "xss", "confidence": "low"},
        )
        finding_record = await findings_repo.create_finding_from_normalized(
            scan.id, test_record.id, normalized
        )
        assert finding_record.confidence == "low"
        assert finding_record.severity == "medium"

        findings = await findings_repo.list_findings_for_scan(scan.id)
        assert len(findings) == 1

        evidence = await findings_repo.list_evidence_for_finding(finding_record.id)
        assert len(evidence) == 1
        assert evidence[0].kind == "raw_output"

        updated = await findings_repo.update_verification(finding_record.id, "verified", "medium")
        assert updated.verification_status == "verified"
        assert updated.confidence == "medium"

        findings_with_source = await findings_repo.list_findings_with_source_for_scan(scan.id)
        assert len(findings_with_source) == 1
        assert findings_with_source[0]["tool_name"] == "reflected_xss"
        assert findings_with_source[0]["endpoint_id"] == endpoint.id
        assert findings_with_source[0]["verification_status"] == "verified"

        correlation = await findings_repo.create_correlation(
            scan_id=scan.id,
            endpoint_id=endpoint.id,
            vulnerability_class="xss",
            finding_ids=[finding_record.id],
            tool_names=["reflected_xss"],
            combined_confidence="medium",
            status="insufficient_correlation",
            rationale="test rationale",
        )
        correlations = await findings_repo.list_correlations_for_scan(scan.id)
        assert len(correlations) == 1
        assert correlations[0].id == correlation.id

    await engine.dispose()
