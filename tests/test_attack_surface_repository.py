import pytest

from app.storage.db import get_engine, init_db, make_session_factory, session_scope
from app.storage.repository import (
    AttackSurfaceRepository,
    IntelligenceRepository,
    ScanRepository,
    TargetRepository,
)


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

    await engine.dispose()
