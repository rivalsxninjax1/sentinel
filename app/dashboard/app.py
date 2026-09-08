"""Local read-only dashboard over the scan database.

Per docs/architecture.md §11 (Dashboard): shows scan status, attack surface,
endpoints, parameters, technologies, findings, severity, confidence, evidence,
tool results, and AI reasoning. This is a READ-ONLY view — no route here creates,
modifies, or deletes anything; every mutation still happens exclusively through the
CLI's `scan ...` commands, which is the only place scope/mode/lifecycle rules are
enforced. The dashboard is a viewer, not a second orchestrator.

`fastapi`/`uvicorn`/`jinja2` are optional dependencies (`pip install -e
".[dashboard]"`) — the same graceful-unavailable pattern used for Playwright
(Phase 3) and `websockets` (Phase 8). `create_dashboard_app()` raises a clear
`DashboardUnavailable` if FastAPI isn't installed, rather than the CLI command
crashing with an unhelpful ImportError.

SECURITY NOTE: this server binds to 127.0.0.1 by default (see
app/cli/main.py's `dashboard` command) and has NO AUTHENTICATION — anyone who can
reach the bound host/port can view every scan's findings, including reflected
target content. Do not bind this to 0.0.0.0 or expose it beyond localhost without
adding authentication first; that is explicitly out of scope for this phase (see
docs/dashboard.md).
"""

from __future__ import annotations

from app.dashboard import templates
from app.reporting.builder import ReportBuilder
from app.reporting.renderers import html_renderer
from app.storage.db import get_engine, make_session_factory, session_scope
from app.storage.repository import (
    AttackSurfaceRepository,
    FindingsRepository,
    IntelligenceRepository,
    ScanRepository,
    TargetRepository,
)

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import HTMLResponse

    _FASTAPI_AVAILABLE = True
except Exception as exc:  # pragma: no cover - exercised only when fastapi is absent
    FastAPI = None  # type: ignore[assignment]
    HTTPException = None  # type: ignore[assignment]
    HTMLResponse = None  # type: ignore[assignment]
    _FASTAPI_AVAILABLE = False
    _FASTAPI_IMPORT_ERROR: Exception | None = exc
else:
    _FASTAPI_IMPORT_ERROR = None


class DashboardUnavailable(Exception):
    """Raised by create_dashboard_app() when FastAPI/uvicorn/jinja2 aren't
    installed. Callers (the CLI) should catch this and print a clear
    pip-install hint rather than let an ImportError propagate."""


def is_available() -> bool:
    return _FASTAPI_AVAILABLE


_STATUS_CLASS = {"complete": "complete", "stopped": "stopped"}


def _status_class(status: str) -> str:
    return _STATUS_CLASS.get(status, "default")


def create_dashboard_app(storage_path: str):
    if not _FASTAPI_AVAILABLE:
        raise DashboardUnavailable(
            f"FastAPI is not available: {_FASTAPI_IMPORT_ERROR}. "
            'Install with `pip install -e ".[dashboard]"`.'
        )

    app = FastAPI(title="SENTINEL Dashboard")
    engine = get_engine(storage_path)
    session_factory = make_session_factory(engine)

    @app.get("/", response_class=HTMLResponse)
    async def home() -> str:
        async with session_scope(session_factory) as session:
            scans_repo = ScanRepository(session)
            rows = await scans_repo.list_all_with_target()
            scans = [
                {
                    "id": scan.id,
                    "target_name": target.name,
                    "mode": scan.mode,
                    "status": scan.status,
                    "status_class": _status_class(scan.status),
                    "started_at": scan.started_at.isoformat() if scan.started_at else "",
                }
                for scan, target in rows
            ]
        return templates.render_home(scans)

    @app.get("/scans/{scan_id}", response_class=HTMLResponse)
    async def scan_overview(scan_id: str) -> str:
        async with session_scope(session_factory) as session:
            scans_repo = ScanRepository(session)
            scan = await scans_repo.get(scan_id)
            if scan is None:
                raise HTTPException(status_code=404, detail="Scan not found")

            targets_repo = TargetRepository(session)
            target = await targets_repo.get(scan.target_id)

            attack_surface = AttackSurfaceRepository(session)
            hosts = await attack_surface.list_hosts_for_target(scan.target_id)
            endpoint_count = 0
            parameter_count = 0
            technology_count = 0
            js_asset_count = 0
            for host in hosts:
                endpoints = await attack_surface.list_endpoints_for_host(host.id)
                endpoint_count += len(endpoints)
                parameter_count += sum(len(e.parameters) for e in endpoints)
                technology_count += len(await attack_surface.list_technologies_for_host(host.id))
                # JS asset count: no dedicated list method exists yet (Phase 3 only
                # added add_javascript_asset with get-or-create dedup) — omitted
                # from the count rather than adding an unused new query just for a
                # dashboard number; shown as "-" if not orchestrated separately.

            findings_repo = FindingsRepository(session)
            builder = ReportBuilder(scans_repo, targets_repo, findings_repo)
            try:
                report = await builder.build(scan_id)
                disposition_counts = report.summary_by_disposition
            except ValueError:
                disposition_counts = {}

            intelligence_repo = IntelligenceRepository(session)
            classifications = await intelligence_repo.list_for_scan(scan_id)
            ai_count = sum(1 for c in classifications if c.source == "ai")
            fallback_count = sum(1 for c in classifications if c.source == "fallback")

        return templates.render_scan_overview(
            scan_id=scan_id,
            target_name=target.name if target else "unknown",
            mode=scan.mode,
            status=scan.status,
            status_class=_status_class(scan.status),
            stopped_reason=scan.stopped_reason,
            started_at=scan.started_at.isoformat() if scan.started_at else "",
            counts={
                "hosts": len(hosts),
                "endpoints": endpoint_count,
                "parameters": parameter_count,
                "technologies": technology_count,
                "js_assets": js_asset_count,
            },
            disposition_counts=disposition_counts,
            classification_count=len(classifications),
            ai_count=ai_count,
            fallback_count=fallback_count,
        )

    @app.get("/scans/{scan_id}/findings", response_class=HTMLResponse)
    async def scan_findings(scan_id: str) -> str:
        async with session_scope(session_factory) as session:
            scans_repo = ScanRepository(session)
            scan = await scans_repo.get(scan_id)
            if scan is None:
                raise HTTPException(status_code=404, detail="Scan not found")

            builder = ReportBuilder(
                scans_repo, TargetRepository(session), FindingsRepository(session)
            )
            report = await builder.build(scan_id)
        # Reuses Phase 10's already-escaped, already-tested HTML renderer directly
        # rather than re-implementing findings display in a dashboard template.
        return html_renderer.render(report)

    @app.get("/scans/{scan_id}/attack-surface", response_class=HTMLResponse)
    async def scan_attack_surface(scan_id: str) -> str:
        async with session_scope(session_factory) as session:
            scans_repo = ScanRepository(session)
            scan = await scans_repo.get(scan_id)
            if scan is None:
                raise HTTPException(status_code=404, detail="Scan not found")

            attack_surface = AttackSurfaceRepository(session)
            host_rows = await attack_surface.list_hosts_for_target(scan.target_id)

            hosts = []
            for host in host_rows:
                endpoints = await attack_surface.list_endpoints_for_host(host.id)
                technologies = await attack_surface.list_technologies_for_host(host.id)
                hosts.append(
                    {
                        "hostname": host.hostname,
                        "technologies": [{"name": t.name, "version": t.version} for t in technologies],
                        "endpoints": [
                            {
                                "method": e.method,
                                "path": e.path,
                                "source": e.source,
                                "parameters": [p.name for p in e.parameters],
                            }
                            for e in endpoints
                        ],
                    }
                )

        return templates.render_attack_surface(scan_id, hosts)

    @app.get("/scans/{scan_id}/classifications", response_class=HTMLResponse)
    async def scan_classifications(scan_id: str) -> str:
        async with session_scope(session_factory) as session:
            scans_repo = ScanRepository(session)
            scan = await scans_repo.get(scan_id)
            if scan is None:
                raise HTTPException(status_code=404, detail="Scan not found")

            intelligence_repo = IntelligenceRepository(session)
            classifications = await intelligence_repo.list_for_scan_with_context(scan_id)

        return templates.render_classifications(scan_id, classifications)

    return app
