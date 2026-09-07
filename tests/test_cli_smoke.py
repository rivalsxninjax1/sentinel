"""End-to-end smoke test: create a scan via the CLI's underlying logic against a
temporary SQLite DB and confirm it lands in SCOPE_VALIDATED, and separately verify
`scan classify` degrades gracefully to fallback when Ollama is unreachable."""

import textwrap
from pathlib import Path

import asyncio
import pytest
from typer.testing import CliRunner

from app.cli.main import app
from app.core.lifecycle import ScanState
from app.storage.db import get_engine, init_db, make_session_factory, session_scope
from app.storage.repository import AttackSurfaceRepository, ScanRepository, TargetRepository

runner = CliRunner()


@pytest.fixture()
def tmp_config(tmp_path: Path) -> Path:
    db_path = tmp_path / "sentinel_test.db"
    config_path = tmp_path / "test_config.yaml"
    config_path.write_text(
        textwrap.dedent(
            f"""
            target:
              name: "smoke-test-target"
              scope:
                allow:
                  - "app.smoke-test.local"
                deny: []
            scan:
              mode: passive
            storage_path: "{db_path}"
            log_level: "WARNING"
            """
        )
    )
    return config_path


def test_init_db_creates_sqlite_file(tmp_config: Path, tmp_path: Path):
    result = runner.invoke(app, ["init-db", "--config", str(tmp_config)])
    assert result.exit_code == 0, result.output
    db_files = list(tmp_path.glob("*.db"))
    assert len(db_files) == 1


def test_scan_create_and_status_roundtrip(tmp_config: Path):
    create_result = runner.invoke(app, ["scan", "create", "--config", str(tmp_config)])
    assert create_result.exit_code == 0, create_result.output
    scan_id = create_result.output.strip().split()[-1]

    status_result = runner.invoke(
        app, ["scan", "status", scan_id, "--config", str(tmp_config)]
    )
    assert status_result.exit_code == 0, status_result.output
    assert "status=scope_validated" in status_result.output


@pytest.fixture()
def tmp_config_unreachable_llm(tmp_path: Path) -> Path:
    """Config pointing at a port nothing is listening on, so OllamaProvider's
    availability check fails fast and deterministically — this exercises the
    graceful-fallback path without needing a real Ollama instance."""
    db_path = tmp_path / "sentinel_test.db"
    config_path = tmp_path / "test_config_llm.yaml"
    config_path.write_text(
        textwrap.dedent(
            f"""
            target:
              name: "classify-test-target"
              scope:
                allow:
                  - "app.classify-test.local"
                deny: []
            scan:
              mode: passive
            storage_path: "{db_path}"
            log_level: "WARNING"
            llm:
              provider: ollama
              model: "unused-in-test"
              base_url: "http://127.0.0.1:1"
              temperature: 0
            """
        )
    )
    return config_path


def test_scan_classify_falls_back_and_advances_lifecycle(tmp_config_unreachable_llm: Path):
    cfg_path = tmp_config_unreachable_llm
    from app.config.settings import SentinelConfig

    cfg = SentinelConfig.from_yaml(str(cfg_path))

    async def _seed() -> str:
        db_engine = get_engine(cfg.storage_path)
        await init_db(db_engine)
        session_factory = make_session_factory(db_engine)

        async with session_scope(session_factory) as session:
            targets = TargetRepository(session)
            scans = ScanRepository(session)
            attack_surface = AttackSurfaceRepository(session)

            target = await targets.create(
                cfg.target.name, {"allow": cfg.target.scope.allow, "deny": cfg.target.scope.deny}
            )
            scan = await scans.create(target.id, "passive", {})
            host = await attack_surface.get_or_create_host(
                target.id, "app.classify-test.local", scan.id
            )
            endpoint = await attack_surface.get_or_create_endpoint(
                host.id, "/api/users/1", "GET", scan.id, source="crawl"
            )
            await attack_surface.add_parameter(endpoint.id, "id", "query", "1")
            await scans.update_status(scan.id, ScanState.DISCOVERY.value)
            scan_id = scan.id

        await db_engine.dispose()
        return scan_id

    scan_id = asyncio.run(_seed())

    result = runner.invoke(app, ["scan", "classify", scan_id, "--config", str(cfg_path)])
    assert result.exit_code == 0, result.output
    assert "fallback" in result.output

    status_result = runner.invoke(app, ["scan", "status", scan_id, "--config", str(cfg_path)])
    assert "status=intelligence" in status_result.output


def test_scan_test_runs_scanners_and_advances_to_testing(tmp_path: Path):
    """End-to-end: seed a scan directly at INTELLIGENCE with one host/endpoint/
    parameter, point 'scan test' at a mocked target via a config whose seed_urls
    scheme matches, and confirm it produces findings and reaches TESTING.

    Since `scan test` uses a real SentinelHTTPClient (not mockable via config), this
    test targets 127.0.0.1 on a port nothing listens on — every request will fail
    with a connection error, which every scanner already handles gracefully (catches
    httpx.HTTPError and returns no findings). This proves the full orchestration
    pipeline (mode gating, persistence, lifecycle transition) works even when the
    network layer is fully unavailable — the same fail-safe pattern already proven
    for the classify command's LLM fallback path."""
    db_path = tmp_path / "sentinel_test.db"
    config_path = tmp_path / "test_config_scan_test.yaml"
    config_path.write_text(
        textwrap.dedent(
            f"""
            target:
              name: "scan-test-target"
              scope:
                allow:
                  - "127.0.0.1"
                deny: []
              seed_urls:
                - "http://127.0.0.1:1/"
            scan:
              mode: safe
            storage_path: "{db_path}"
            log_level: "WARNING"
            """
        )
    )

    from app.config.settings import SentinelConfig

    cfg = SentinelConfig.from_yaml(str(config_path))

    async def _seed() -> str:
        db_engine = get_engine(cfg.storage_path)
        await init_db(db_engine)
        session_factory = make_session_factory(db_engine)

        async with session_scope(session_factory) as session:
            targets = TargetRepository(session)
            scans = ScanRepository(session)
            attack_surface = AttackSurfaceRepository(session)

            target = await targets.create(
                cfg.target.name, {"allow": cfg.target.scope.allow, "deny": cfg.target.scope.deny}
            )
            scan = await scans.create(target.id, "safe", {})
            host = await attack_surface.get_or_create_host(target.id, "127.0.0.1", scan.id)
            endpoint = await attack_surface.get_or_create_endpoint(
                host.id, "/search", "GET", scan.id, source="crawl"
            )
            await attack_surface.add_parameter(endpoint.id, "q", "query", "")
            await attack_surface.add_form(
                endpoint.id, "POST", "http://127.0.0.1:1/search", [{"name": "q"}]
            )
            await scans.update_status(scan.id, ScanState.INTELLIGENCE.value)
            scan_id = scan.id

        await db_engine.dispose()
        return scan_id

    scan_id = asyncio.run(_seed())

    result = runner.invoke(app, ["scan", "test", scan_id, "--config", str(config_path)])
    assert result.exit_code == 0, result.output
    assert "Testing complete" in result.output

    status_result = runner.invoke(app, ["scan", "status", scan_id, "--config", str(config_path)])
    assert "status=testing" in status_result.output


def test_scan_verify_processes_findings_and_advances_to_correlating(tmp_path: Path):
    """End-to-end: seed a scan directly at TESTING with one pre-existing Finding
    (as if `scan test` had already produced it), point 'scan verify' at the same
    unreachable target used by the scan-test smoke test above, and confirm it
    completes and reaches CORRELATING.

    The baseline fetch will fail (connection refused), so this specific finding
    ends up "needs_manual_review" rather than verified/false_positive — that's the
    correct, expected behavior for an unreachable baseline (see
    test_verification_engine.py's test_baseline_fetch_failure_falls_back_to_manual_review),
    and proves the full verify-then-correlate-then-advance pipeline works even when
    the network layer is fully unavailable, same fail-safe pattern as scan_test."""
    db_path = tmp_path / "sentinel_test.db"
    config_path = tmp_path / "test_config_scan_verify.yaml"
    config_path.write_text(
        textwrap.dedent(
            f"""
            target:
              name: "scan-verify-target"
              scope:
                allow:
                  - "127.0.0.1"
                deny: []
              seed_urls:
                - "http://127.0.0.1:1/"
            scan:
              mode: safe
            storage_path: "{db_path}"
            log_level: "WARNING"
            """
        )
    )

    from app.config.settings import SentinelConfig
    from app.storage.repository import FindingsRepository
    from app.tools.models import NormalizedFinding

    cfg = SentinelConfig.from_yaml(str(config_path))

    async def _seed() -> str:
        db_engine = get_engine(cfg.storage_path)
        await init_db(db_engine)
        session_factory = make_session_factory(db_engine)

        async with session_scope(session_factory) as session:
            targets = TargetRepository(session)
            scans = ScanRepository(session)
            attack_surface = AttackSurfaceRepository(session)
            findings_repo = FindingsRepository(session)

            target = await targets.create(
                cfg.target.name, {"allow": cfg.target.scope.allow, "deny": cfg.target.scope.deny}
            )
            scan = await scans.create(target.id, "safe", {})
            host = await attack_surface.get_or_create_host(target.id, "127.0.0.1", scan.id)
            endpoint = await attack_surface.get_or_create_endpoint(
                host.id, "/search", "GET", scan.id, source="crawl"
            )
            test_record = await findings_repo.create_test(
                scan_id=scan.id,
                endpoint_id=endpoint.id,
                vulnerability_class="xss",
                scanner_name="reflected_xss",
            )
            normalized = NormalizedFinding(
                tool_name="reflected_xss",
                tool_version=None,
                title="Unescaped reflection via parameter 'q'",
                severity="medium",
                matched_endpoint="http://127.0.0.1:1/search?q=%3Csentinel9f2a%3E",
                raw_output="injected marker reflected unescaped in response body",
                metadata={"parameter": "q", "vulnerability_class": "xss", "confidence": "low"},
            )
            await findings_repo.create_finding_from_normalized(scan.id, test_record.id, normalized)

            await scans.update_status(scan.id, ScanState.TESTING.value)
            scan_id = scan.id

        await db_engine.dispose()
        return scan_id

    scan_id = asyncio.run(_seed())

    result = runner.invoke(app, ["scan", "verify", scan_id, "--config", str(config_path)])
    assert result.exit_code == 0, result.output
    assert "Verification complete" in result.output
    assert "1 need manual review" in result.output

    status_result = runner.invoke(app, ["scan", "status", scan_id, "--config", str(config_path)])
    assert "status=correlating" in status_result.output


def test_scan_report_writes_files_and_reaches_complete(tmp_path: Path):
    """End-to-end: seed a scan directly at CORRELATING with one verified finding,
    run `scan report`, and confirm real JSON/Markdown/HTML files land on disk with
    the expected content, and the scan reaches the final COMPLETE state."""
    db_path = tmp_path / "sentinel_test.db"
    config_path = tmp_path / "test_config_scan_report.yaml"
    config_path.write_text(
        textwrap.dedent(
            f"""
            target:
              name: "scan-report-target"
              scope:
                allow:
                  - "127.0.0.1"
                deny: []
              seed_urls:
                - "http://127.0.0.1:1/"
            scan:
              mode: safe
            storage_path: "{db_path}"
            log_level: "WARNING"
            """
        )
    )

    from app.config.settings import SentinelConfig
    from app.storage.repository import FindingsRepository
    from app.tools.models import NormalizedFinding

    cfg = SentinelConfig.from_yaml(str(config_path))
    output_dir = tmp_path / "reports"

    async def _seed() -> str:
        db_engine = get_engine(cfg.storage_path)
        await init_db(db_engine)
        session_factory = make_session_factory(db_engine)

        async with session_scope(session_factory) as session:
            targets = TargetRepository(session)
            scans = ScanRepository(session)
            attack_surface = AttackSurfaceRepository(session)
            findings_repo = FindingsRepository(session)

            target = await targets.create(
                cfg.target.name, {"allow": cfg.target.scope.allow, "deny": cfg.target.scope.deny}
            )
            scan = await scans.create(target.id, "safe", {})
            host = await attack_surface.get_or_create_host(target.id, "127.0.0.1", scan.id)
            endpoint = await attack_surface.get_or_create_endpoint(
                host.id, "/search", "GET", scan.id, source="crawl"
            )
            test_record = await findings_repo.create_test(
                scan_id=scan.id,
                endpoint_id=endpoint.id,
                vulnerability_class="xss",
                scanner_name="reflected_xss",
            )
            normalized = NormalizedFinding(
                tool_name="reflected_xss",
                tool_version=None,
                title="Unescaped reflection via parameter 'q'",
                severity="medium",
                matched_endpoint="http://127.0.0.1:1/search?q=x",
                raw_output="injected marker reflected unescaped in response body",
                metadata={"parameter": "q", "vulnerability_class": "xss", "confidence": "high"},
            )
            f = await findings_repo.create_finding_from_normalized(scan.id, test_record.id, normalized)
            await findings_repo.update_verification(f.id, "verified", "high")

            await scans.update_status(scan.id, ScanState.CORRELATING.value)
            scan_id = scan.id

        await db_engine.dispose()
        return scan_id

    scan_id = asyncio.run(_seed())

    result = runner.invoke(
        app,
        ["scan", "report", scan_id, "--config", str(config_path), "--output-dir", str(output_dir)],
    )
    assert result.exit_code == 0, result.output
    assert "Report generated: 1 findings" in result.output
    assert "Scan COMPLETE" in result.output

    json_path = output_dir / scan_id / "report.json"
    md_path = output_dir / scan_id / "report.md"
    html_path = output_dir / scan_id / "report.html"
    assert json_path.exists()
    assert md_path.exists()
    assert html_path.exists()

    assert "Unescaped reflection" in md_path.read_text()
    assert "Likely" in md_path.read_text()  # high confidence + verified -> Likely
    assert "<!DOCTYPE html>" in html_path.read_text()

    import json as json_module

    data = json_module.loads(json_path.read_text())
    assert data["findings"][0]["disposition"] == "Likely"
    assert data["findings"][0]["cwe_id"] == "CWE-79"

    status_result = runner.invoke(app, ["scan", "status", scan_id, "--config", str(config_path)])
    assert "status=complete" in status_result.output
