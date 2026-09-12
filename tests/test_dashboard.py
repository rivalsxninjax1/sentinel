import os

import httpx
import pytest

from app.dashboard.app import create_dashboard_app
from app.storage.db import get_engine, init_db, make_session_factory, session_scope
from app.storage.repository import (
    AttackSurfaceRepository,
    FindingsRepository,
    IntelligenceRepository,
    ScanRepository,
    TargetRepository,
)
from app.tools.models import NormalizedFinding


async def _seed_scan(db_path: str) -> str:
    engine = get_engine(db_path)
    await init_db(engine)
    session_factory = make_session_factory(engine)

    async with session_scope(session_factory) as session:
        targets = TargetRepository(session)
        scans = ScanRepository(session)
        attack_surface = AttackSurfaceRepository(session)
        findings_repo = FindingsRepository(session)
        intelligence_repo = IntelligenceRepository(session)

        target = await targets.create("dashboard-test-target", {"allow": ["app.example.com"], "deny": []})
        scan = await scans.create(target.id, "safe", {})
        host = await attack_surface.get_or_create_host(target.id, "app.example.com", scan.id)
        endpoint = await attack_surface.get_or_create_endpoint(
            host.id, "/search", "GET", scan.id, source="crawl"
        )
        await attack_surface.add_parameter(endpoint.id, "q", "query", "")
        await attack_surface.add_technology(host.id, "nginx", "1.24.0", "high", "header:server")

        test_record = await findings_repo.create_test(scan.id, endpoint.id, "xss", "reflected_xss")
        f = await findings_repo.create_finding_from_normalized(
            scan.id,
            test_record.id,
            NormalizedFinding(
                tool_name="reflected_xss",
                tool_version=None,
                title="Unescaped reflection via parameter 'q'",
                severity="medium",
                matched_endpoint="https://app.example.com/search?q=x",
                raw_output="marker reflected",
                metadata={"parameter": "q", "vulnerability_class": "xss", "confidence": "high"},
            ),
        )
        await findings_repo.update_verification(f.id, "verified", "high")

        await intelligence_repo.add_classification(
            scan_id=scan.id,
            endpoint_id=endpoint.id,
            parameter_id=None,
            classification="search",
            risk_score=3,
            recommended_tests=["xss"],
            reason="search-like parameter",
            source="ai",
        )

        await scans.update_status(scan.id, "complete")
        scan_id = scan.id

    await engine.dispose()
    return scan_id


async def _client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


@pytest.mark.asyncio
async def test_dashboard_initializes_database_when_never_touched_before(tmp_path):
    """Regression test: create_dashboard_app() must work against a storage_path
    that no CLI command has ever run init-db against — this reproduces the exact
    'no such table: scans' crash reported when running `sentinel dashboard`
    against a fresh database. Every route must call init_db() itself, matching
    every `scan ...` CLI command's behavior."""
    db_path = str(tmp_path / "never_initialized.db")
    assert not os.path.exists(db_path)  # sanity: truly untouched

    app = create_dashboard_app(db_path)

    async with await _client(app) as client:
        response = await client.get("/")

    assert response.status_code == 200
    assert "No scans yet" in response.text


@pytest.mark.asyncio
async def test_home_lists_scans(tmp_path):
    db_path = str(tmp_path / "test.db")
    scan_id = await _seed_scan(db_path)
    app = create_dashboard_app(db_path)

    async with await _client(app) as client:
        response = await client.get("/")

    assert response.status_code == 200
    assert "dashboard-test-target" in response.text
    assert scan_id in response.text


@pytest.mark.asyncio
async def test_home_handles_no_scans(tmp_path):
    db_path = str(tmp_path / "empty.db")
    from app.storage.db import get_engine as _ge, init_db as _init

    engine = await _init_empty_db(db_path)

    app = create_dashboard_app(db_path)
    async with await _client(app) as client:
        response = await client.get("/")

    assert response.status_code == 200
    assert "No scans yet" in response.text


async def _init_empty_db(db_path: str):
    from app.storage.db import get_engine, init_db

    engine = get_engine(db_path)
    await init_db(engine)
    await engine.dispose()
    return engine


@pytest.mark.asyncio
async def test_home_shows_quickscan_form(tmp_path):
    db_path = str(tmp_path / "test.db")
    app = create_dashboard_app(db_path)

    async with await _client(app) as client:
        response = await client.get("/")

    assert response.status_code == 200
    assert 'action="/scans/quick-start"' in response.text
    assert 'name="target_input"' in response.text
    assert 'name="authorized"' in response.text
    assert 'name="mode"' in response.text


@pytest.mark.asyncio
async def test_scan_overview_shows_counts_and_links(tmp_path):
    db_path = str(tmp_path / "test.db")
    scan_id = await _seed_scan(db_path)
    app = create_dashboard_app(db_path)

    async with await _client(app) as client:
        response = await client.get(f"/scans/{scan_id}")

    assert response.status_code == 200
    assert "dashboard-test-target" in response.text
    assert "complete" in response.text
    assert f"/scans/{scan_id}/attack-surface" in response.text
    assert f"/scans/{scan_id}/findings" in response.text
    assert f"/scans/{scan_id}/classifications" in response.text


@pytest.mark.asyncio
async def test_scan_overview_404_for_unknown_scan(tmp_path):
    db_path = str(tmp_path / "test.db")
    await _seed_scan(db_path)
    app = create_dashboard_app(db_path)

    async with await _client(app) as client:
        response = await client.get("/scans/nonexistent-scan-id")

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_findings_page_reuses_report_renderer(tmp_path):
    db_path = str(tmp_path / "test.db")
    scan_id = await _seed_scan(db_path)
    app = create_dashboard_app(db_path)

    async with await _client(app) as client:
        response = await client.get(f"/scans/{scan_id}/findings")

    assert response.status_code == 200
    assert "<!DOCTYPE html>" in response.text
    assert "Unescaped reflection" in response.text
    assert "Likely" in response.text  # verified + high confidence


@pytest.mark.asyncio
async def test_attack_surface_page_shows_hosts_endpoints_and_technologies(tmp_path):
    db_path = str(tmp_path / "test.db")
    scan_id = await _seed_scan(db_path)
    app = create_dashboard_app(db_path)

    async with await _client(app) as client:
        response = await client.get(f"/scans/{scan_id}/attack-surface")

    assert response.status_code == 200
    assert "app.example.com" in response.text
    assert "/search" in response.text
    assert "nginx" in response.text


@pytest.mark.asyncio
async def test_attack_surface_escapes_hostile_endpoint_path(tmp_path):
    db_path = str(tmp_path / "hostile.db")
    engine = get_engine(db_path)
    await init_db(engine)
    session_factory = make_session_factory(engine)

    async with session_scope(session_factory) as session:
        targets = TargetRepository(session)
        scans = ScanRepository(session)
        attack_surface = AttackSurfaceRepository(session)

        target = await targets.create("hostile-target", {"allow": ["app.example.com"], "deny": []})
        scan = await scans.create(target.id, "safe", {})
        host = await attack_surface.get_or_create_host(target.id, "app.example.com", scan.id)
        # a hostile/malformed path a real crawl could pick up from a crafted link
        await attack_surface.get_or_create_endpoint(
            host.id, "/<script>alert(1)</script>", "GET", scan.id, source="crawl"
        )
        scan_id = scan.id

    await engine.dispose()

    app = create_dashboard_app(db_path)
    async with await _client(app) as client:
        response = await client.get(f"/scans/{scan_id}/attack-surface")

    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;" in response.text


@pytest.mark.asyncio
async def test_classifications_page_shows_ai_reasoning(tmp_path):
    db_path = str(tmp_path / "test.db")
    scan_id = await _seed_scan(db_path)
    app = create_dashboard_app(db_path)

    async with await _client(app) as client:
        response = await client.get(f"/scans/{scan_id}/classifications")

    assert response.status_code == 200
    assert "search" in response.text
    assert "search-like parameter" in response.text
    assert "ai" in response.text


@pytest.mark.asyncio
async def test_classifications_page_handles_empty_state(tmp_path):
    db_path = str(tmp_path / "test.db")
    engine = get_engine(db_path)
    await init_db(engine)
    session_factory = make_session_factory(engine)

    async with session_scope(session_factory) as session:
        targets = TargetRepository(session)
        scans = ScanRepository(session)
        target = await targets.create("empty-target", {"allow": ["app.example.com"], "deny": []})
        scan = await scans.create(target.id, "safe", {})
        scan_id = scan.id

    await engine.dispose()

    app = create_dashboard_app(db_path)
    async with await _client(app) as client:
        response = await client.get(f"/scans/{scan_id}/classifications")

    assert response.status_code == 200
    assert "No AI classifications recorded yet" in response.text


# --- quick-start route tests -------------------------------------------------


@pytest.mark.asyncio
async def test_quick_start_rejects_missing_authorization_checkbox(tmp_path):
    db_path = str(tmp_path / "test.db")
    app = create_dashboard_app(db_path)

    async with await _client(app) as client:
        response = await client.post(
            "/scans/quick-start",
            data={"target_input": "example.com", "mode": "safe"},  # no "authorized"
        )

    assert response.status_code == 400
    assert "authorized" in response.text.lower()


@pytest.mark.asyncio
async def test_quick_start_rejects_empty_target_input(tmp_path):
    db_path = str(tmp_path / "test.db")
    app = create_dashboard_app(db_path)

    async with await _client(app) as client:
        response = await client.post(
            "/scans/quick-start",
            data={"target_input": "   ", "mode": "safe", "authorized": "yes"},
        )

    assert response.status_code == 400


@pytest.mark.asyncio
async def test_quick_start_creates_scan_and_redirects(tmp_path, monkeypatch):
    """Patches out the actual CLI subprocess calls so this test doesn't spawn a
    real Python process or touch the network — it verifies the route's own logic
    (auth check, config building, redirect, background task scheduling) using a
    fake ProcessRunner, the same injection pattern used throughout the rest of
    this codebase for tool adapters and scanners."""
    db_path = str(tmp_path / "test.db")

    async def fake_runner(args, timeout):
        return 0, "Created scan 22222222-2222-2222-2222-222222222222\n", ""

    import app.dashboard.quickscan as quickscan_module

    monkeypatch.setattr(quickscan_module, "default_process_runner", fake_runner)

    app = create_dashboard_app(db_path)

    async with await _client(app) as client:
        response = await client.post(
            "/scans/quick-start",
            data={"target_input": "example.com", "mode": "safe", "authorized": "yes"},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/scans/22222222-2222-2222-2222-222222222222"
