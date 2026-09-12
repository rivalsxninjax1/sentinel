"""SENTINEL CLI.

Commands implemented so far:
  sentinel init-db --config configs/example.yaml
  sentinel scan create --config configs/example.yaml
  sentinel scan crawl <scan_id> --config configs/example.yaml
  sentinel scan discover-js <scan_id> --config configs/example.yaml
  sentinel scan classify <scan_id> --config configs/example.yaml
  sentinel scan test <scan_id> --config configs/example.yaml
  sentinel scan verify <scan_id> --config configs/example.yaml
  sentinel scan report <scan_id> --config configs/example.yaml
  sentinel scan status <scan_id> --config configs/example.yaml
  sentinel tools list

Later phases attach real dashboard/research behavior beyond this scaffolding.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from urllib.parse import urljoin

import httpx
import typer

from app.config.settings import SentinelConfig
from app.core.auth_context import AuthContextConfig, build_contexts
from app.core.http_client import SentinelHTTPClient
from app.core.lifecycle import ScanLifecycle, ScanState
from app.core.logging import configure_logging, get_logger
from app.core.rate_limiter import RateLimiter
from app.core.test_orchestrator import TestOrchestrator
from app.crawler.browser import BrowserDiscovery, BrowserEngine, BrowserUnavailable
from app.crawler.crawler import Crawler
from app.intelligence.javascript import JSExtractionResult, extract_from_js
from app.intelligence.reasoning import SecurityReasoningEngine
from app.llm.ollama_provider import OllamaProvider
from app.reporting.builder import ReportBuilder
from app.reporting.renderers import html_renderer, json_renderer, markdown_renderer
from app.scanners.registry import build_default_scanners
from app.scope.engine import ScopeEngine, ScopeViolation
from app.storage.db import get_engine, init_db, make_session_factory, session_scope
from app.storage.repository import (
    AttackSurfaceRepository,
    FindingsRepository,
    IntelligenceRepository,
    ScanRepository,
    TargetRepository,
)
from app.tools.registry import build_default_registry
from app.verification.correlation import CorrelationEngine
from app.verification.engine import VerificationEngine

app = typer.Typer(help="SENTINEL — authorized web application security testing platform.")
scan_app = typer.Typer(help="Scan lifecycle commands.")
tools_app = typer.Typer(help="Tool adapter commands.")
app.add_typer(scan_app, name="scan")
app.add_typer(tools_app, name="tools")

logger = get_logger(__name__)


def _load_config(config_path: str) -> SentinelConfig:
    return SentinelConfig.from_yaml(config_path)


@app.command("init-db")
def init_db_command(config: str = typer.Option(..., "--config", "-c")) -> None:
    """Create the SQLite database and tables."""
    cfg = _load_config(config)
    configure_logging(cfg.log_level)

    async def _run() -> None:
        engine = get_engine(cfg.storage_path)
        await init_db(engine)
        await engine.dispose()

    asyncio.run(_run())
    typer.echo(f"Initialized database at {cfg.storage_path}")


@scan_app.command("create")
def scan_create(config: str = typer.Option(..., "--config", "-c")) -> None:
    """Create a scan: persists the target (if new), validates scope, and advances the
    scan to SCOPE_VALIDATED. Does not perform recon yet — that's Phase 2."""
    cfg = _load_config(config)
    configure_logging(cfg.log_level)

    scope = ScopeEngine(allow=cfg.target.scope.allow, deny=cfg.target.scope.deny)

    async def _run() -> str:
        engine = get_engine(cfg.storage_path)
        await init_db(engine)
        session_factory = make_session_factory(engine)

        async with session_scope(session_factory) as session:
            targets = TargetRepository(session)
            scans = ScanRepository(session)

            target = await targets.get_by_name(cfg.target.name)
            if target is None:
                target = await targets.create(
                    name=cfg.target.name,
                    scope_definition={"allow": cfg.target.scope.allow, "deny": cfg.target.scope.deny},
                )

            scan_record = await scans.create(
                target_id=target.id,
                mode=cfg.scan.mode.value,
                config_snapshot=cfg.model_dump(mode="json"),
            )

            lifecycle = ScanLifecycle(ScanState.CREATED)
            try:
                # Scope "validation" at scan-creation time means: the configured
                # scope itself is well-formed and non-empty (enforced by
                # SentinelConfig at load time already). Per-request enforcement
                # happens later, at every actual HTTP call, via ScopeEngine.enforce().
                if not scope.allow_rules:
                    raise ScopeViolation("no allow rules configured")
                lifecycle.advance()  # CREATED -> SCOPE_VALIDATED
                await scans.update_status(scan_record.id, lifecycle.state.value)
            except ScopeViolation as exc:
                lifecycle.stop(str(exc))
                await scans.update_status(
                    scan_record.id, lifecycle.state.value, stopped_reason=str(exc)
                )

        await engine.dispose()
        return scan_record.id

    scan_id = asyncio.run(_run())
    typer.echo(f"Created scan {scan_id}")


@scan_app.command("crawl")
def scan_crawl(
    scan_id: str,
    config: str = typer.Option(..., "--config", "-c"),
) -> None:
    """Phase 2 — Recon: crawl the target's seed URLs, extract endpoints/forms/
    parameters, fingerprint technologies, and persist everything to the attack-surface
    store. Advances the scan RECON -> DISCOVERY on success."""
    cfg = _load_config(config)
    configure_logging(cfg.log_level)

    if not cfg.target.seed_urls:
        typer.echo("target.seed_urls is empty in config — nothing to crawl.", err=True)
        raise typer.Exit(code=1)

    scope = ScopeEngine(allow=cfg.target.scope.allow, deny=cfg.target.scope.deny)
    rate_limiter = RateLimiter(
        requests_per_second=cfg.limits.requests_per_second,
        concurrency=cfg.limits.concurrency,
        max_requests=cfg.limits.max_requests,
    )

    async def _run() -> None:
        engine = get_engine(cfg.storage_path)
        await init_db(engine)
        session_factory = make_session_factory(engine)

        async with session_scope(session_factory) as session:
            scans = ScanRepository(session)
            scan_record = await scans.get(scan_id)
            if scan_record is None:
                typer.echo(f"No such scan: {scan_id}", err=True)
                raise typer.Exit(code=1)

            try:
                lifecycle = ScanLifecycle(ScanState(scan_record.status))
            except ValueError:
                typer.echo(f"Scan {scan_id} is in a terminal or unknown state: {scan_record.status}", err=True)
                raise typer.Exit(code=1)

            if lifecycle.state != ScanState.SCOPE_VALIDATED:
                typer.echo(
                    f"Scan {scan_id} must be in SCOPE_VALIDATED to crawl "
                    f"(currently: {lifecycle.state.value}).",
                    err=True,
                )
                raise typer.Exit(code=1)

            lifecycle.advance()  # SCOPE_VALIDATED -> RECON
            await scans.update_status(scan_record.id, lifecycle.state.value)

        try:
            async with SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter) as http_client:
                crawler = Crawler(
                    http_client=http_client,
                    max_depth=cfg.limits.max_crawl_depth,
                )
                summary = await crawler.crawl(cfg.target.seed_urls)
        except Exception as exc:
            async with session_scope(session_factory) as session:
                scans = ScanRepository(session)
                lifecycle = ScanLifecycle(ScanState.RECON)
                lifecycle.stop(f"crawl failed: {exc}")
                await scans.update_status(
                    scan_id, lifecycle.state.value, stopped_reason=lifecycle.stopped_reason
                )
            typer.echo(f"Crawl failed, scan stopped: {exc}", err=True)
            raise typer.Exit(code=1)

        async with session_scope(session_factory) as session:
            scans = ScanRepository(session)
            targets = TargetRepository(session)
            attack_surface = AttackSurfaceRepository(session)

            scan_record = await scans.get(scan_id)
            target = await targets.get(scan_record.target_id)

            for page in summary.pages:
                hostname = httpx.URL(page.url).host
                host = await attack_surface.get_or_create_host(target.id, hostname, scan_id)

                path = httpx.URL(page.url).path or "/"
                endpoint = await attack_surface.get_or_create_endpoint(
                    host.id, path, "GET", scan_id, source="crawl", status_code=page.status_code
                )
                for qp in page.query_parameters:
                    await attack_surface.add_parameter(
                        endpoint.id, qp.name, qp.location, qp.observed_value
                    )
                for form in page.forms:
                    form_path = httpx.URL(form.action).path or "/"
                    form_endpoint = await attack_surface.get_or_create_endpoint(
                        host.id, form_path, form.method, scan_id, source="crawl"
                    )
                    await attack_surface.add_form(
                        form_endpoint.id,
                        form.method,
                        form.action,
                        [
                            {"name": p.name, "location": p.location, "observed_value": p.observed_value}
                            for p in form.parameters
                        ],
                    )
                    for p in form.parameters:
                        await attack_surface.add_parameter(
                            form_endpoint.id, p.name, p.location, p.observed_value
                        )

            for hostname, detections in summary.technologies_by_host.items():
                host = await attack_surface.get_or_create_host(target.id, hostname, scan_id)
                for d in detections:
                    await attack_surface.add_technology(
                        host.id, d.name, d.version, d.confidence, d.source
                    )

            lifecycle = ScanLifecycle(ScanState.RECON)
            lifecycle.advance()  # RECON -> DISCOVERY
            await scans.update_status(scan_id, lifecycle.state.value)

        typer.echo(
            f"Crawled {summary.visited_count} pages "
            f"({summary.skipped_out_of_scope} skipped out-of-scope, "
            f"{len(summary.errors)} errors). Scan advanced to DISCOVERY."
        )

    asyncio.run(_run())


@scan_app.command("discover-js")
def scan_discover_js(
    scan_id: str,
    config: str = typer.Option(..., "--config", "-c"),
) -> None:
    """Phase 3 — JavaScript Intelligence: re-crawl seed URLs to collect script
    assets (external + inline), extract API/GraphQL/WebSocket routes and source-map
    references via regex analysis, and — if Playwright is installed — run
    browser-based dynamic discovery to catch requests that only fire after
    client-side JS executes.

    Scan must be in DISCOVERY. This command does NOT advance the lifecycle: JS and
    browser discovery are additional discovery substeps feeding the same
    attack-surface store as `scan crawl`, not a new stage. Advancing to INTELLIGENCE
    is Phase 4's job (Ollama classification)."""
    cfg = _load_config(config)
    configure_logging(cfg.log_level)

    if not cfg.target.seed_urls:
        typer.echo("target.seed_urls is empty in config — nothing to analyze.", err=True)
        raise typer.Exit(code=1)

    scope = ScopeEngine(allow=cfg.target.scope.allow, deny=cfg.target.scope.deny)
    rate_limiter = RateLimiter(
        requests_per_second=cfg.limits.requests_per_second,
        concurrency=cfg.limits.concurrency,
        max_requests=cfg.limits.max_requests,
    )

    async def _run() -> None:
        engine = get_engine(cfg.storage_path)
        await init_db(engine)
        session_factory = make_session_factory(engine)

        async with session_scope(session_factory) as session:
            scans = ScanRepository(session)
            scan_record = await scans.get(scan_id)
            if scan_record is None:
                typer.echo(f"No such scan: {scan_id}", err=True)
                raise typer.Exit(code=1)
            if scan_record.status != ScanState.DISCOVERY.value:
                typer.echo(
                    f"Scan {scan_id} must be in DISCOVERY to run JS discovery "
                    f"(currently: {scan_record.status}).",
                    err=True,
                )
                raise typer.Exit(code=1)
            target_id = scan_record.target_id

        js_routes_found = 0
        graphql_found = 0
        websocket_found = 0
        scripts_found = 0
        source_maps_found = 0
        browser_requests_found = 0
        browser_used = False

        js_results: list[tuple[str, JSExtractionResult]] = []  # (source_url, result)
        script_urls: set[str] = set()
        browser_discoveries: list[tuple[str, BrowserDiscovery]] = []

        async with SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter) as http_client:
            crawler = Crawler(http_client=http_client, max_depth=cfg.limits.max_crawl_depth)
            summary = await crawler.crawl(cfg.target.seed_urls)

            for page in summary.pages:
                for text in page.inline_scripts:
                    js_results.append((page.url, extract_from_js(text)))
                script_urls.update(page.script_urls)

            for script_url in script_urls:
                if not scope.check(script_url).allowed:
                    continue
                try:
                    response = await http_client.get(script_url)
                except (httpx.HTTPError, ScopeViolation):
                    continue
                scripts_found += 1
                result = extract_from_js(response.text)
                if result.source_map_url:
                    source_maps_found += 1
                js_results.append((script_url, result))

            if BrowserEngine.is_available():
                browser_used = True
                browser = BrowserEngine()
                for seed_url in cfg.target.seed_urls:
                    try:
                        discovery = await browser.discover(seed_url, scope)
                        browser_discoveries.append((seed_url, discovery))
                        browser_requests_found += len(discovery.requests_in_scope)
                    except BrowserUnavailable:
                        browser_used = False
                    except Exception as exc:
                        logger.warning("browser_discovery_failed", url=seed_url, error=str(exc))

        async with session_scope(session_factory) as session:
            attack_surface = AttackSurfaceRepository(session)

            for source_url, result in js_results:
                hostname = httpx.URL(source_url).host
                host = await attack_surface.get_or_create_host(target_id, hostname, scan_id)

                for route in result.routes:
                    await attack_surface.get_or_create_endpoint(
                        host.id, route, "GET", scan_id, source="javascript"
                    )
                    js_routes_found += 1
                for gql in result.graphql_endpoints:
                    await attack_surface.get_or_create_endpoint(
                        host.id, gql, "POST", scan_id, source="javascript"
                    )
                    graphql_found += 1
                for ws in result.websocket_endpoints:
                    await attack_surface.get_or_create_endpoint(
                        host.id, ws, "GET", scan_id, source="javascript"
                    )
                    websocket_found += 1

            for script_url in script_urls:
                matching = next((r for u, r in js_results if u == script_url), None)
                if matching is None:
                    continue  # not actually fetched (e.g. out of scope, or fetch failed)
                hostname = httpx.URL(script_url).host
                host = await attack_surface.get_or_create_host(target_id, hostname, scan_id)
                has_map = bool(matching.source_map_url)
                map_url = urljoin(script_url, matching.source_map_url) if has_map else None
                await attack_surface.add_javascript_asset(
                    host.id, script_url, has_map, map_url, scan_id
                )

            for seed_url, discovery in browser_discoveries:
                hostname = httpx.URL(seed_url).host
                host = await attack_surface.get_or_create_host(target_id, hostname, scan_id)
                for req_url in discovery.requests_in_scope:
                    req_path = httpx.URL(req_url).path or "/"
                    await attack_surface.get_or_create_endpoint(
                        host.id, req_path, "GET", scan_id, source="browser"
                    )

        browser_summary = (
            f"used, {browser_requests_found} in-scope requests"
            if browser_used
            else "skipped (Playwright unavailable)"
        )
        typer.echo(
            f"JS discovery complete: {scripts_found} scripts fetched, "
            f"{js_routes_found} routes / {graphql_found} graphql / {websocket_found} websocket "
            f"endpoints found, {source_maps_found} source maps detected. "
            f"Browser discovery: {browser_summary}."
        )

    asyncio.run(_run())


@scan_app.command("classify")
def scan_classify(
    scan_id: str,
    config: str = typer.Option(..., "--config", "-c"),
    max_items: int = typer.Option(200, help="Cap on how many endpoint/parameter pairs to classify."),
) -> None:
    """Phase 4 — Ollama Intelligence: classify every discovered endpoint/parameter
    using the configured LLM provider (advisory only — see
    app/intelligence/reasoning.py), persist the results, and advance the scan
    DISCOVERY -> INTELLIGENCE.

    If the configured LLM is unreachable or misconfigured, this command does NOT
    fail the scan: it records `source="fallback"` for everything and still advances
    the lifecycle. AI reasoning is an enhancement, never a dependency."""
    cfg = _load_config(config)
    configure_logging(cfg.log_level)

    async def _run() -> None:
        engine = get_engine(cfg.storage_path)
        await init_db(engine)
        session_factory = make_session_factory(engine)

        async with session_scope(session_factory) as session:
            scans = ScanRepository(session)
            scan_record = await scans.get(scan_id)
            if scan_record is None:
                typer.echo(f"No such scan: {scan_id}", err=True)
                raise typer.Exit(code=1)
            if scan_record.status != ScanState.DISCOVERY.value:
                typer.echo(
                    f"Scan {scan_id} must be in DISCOVERY to classify "
                    f"(currently: {scan_record.status}).",
                    err=True,
                )
                raise typer.Exit(code=1)
            target_id = scan_record.target_id

        provider = OllamaProvider(
            base_url=cfg.llm.base_url, model=cfg.llm.model, temperature=cfg.llm.temperature
        )
        ai_available = False
        try:
            ai_available = await provider.check_availability()
        except Exception as exc:
            logger.info("llm_availability_check_failed", error=str(exc))

        reasoning_engine = SecurityReasoningEngine(provider if ai_available else None)

        classified_count = 0
        ai_count = 0
        fallback_count = 0

        async with session_scope(session_factory) as session:
            attack_surface = AttackSurfaceRepository(session)
            intelligence = IntelligenceRepository(session)

            hosts = await attack_surface.list_hosts_for_target(target_id)
            for host in hosts:
                technologies = [t.name for t in await attack_surface.list_technologies_for_host(host.id)]
                endpoints = await attack_surface.list_endpoints_for_host(host.id)

                for endpoint in endpoints:
                    if classified_count >= max_items:
                        break

                    targets_to_classify: list[tuple[str | None, str | None, str | None]] = []
                    if endpoint.parameters:
                        for param in endpoint.parameters:
                            targets_to_classify.append((param.id, param.name, param.location))
                    else:
                        targets_to_classify.append((None, None, None))

                    for param_id, param_name, param_location in targets_to_classify:
                        if classified_count >= max_items:
                            break

                        outcome = await reasoning_engine.classify_endpoint_parameter(
                            endpoint.path,
                            endpoint.method,
                            param_name,
                            param_location,
                            technologies,
                        )
                        classified_count += 1
                        if outcome.source == "ai":
                            ai_count += 1
                        else:
                            fallback_count += 1

                        if outcome.classification is not None:
                            c = outcome.classification
                            await intelligence.add_classification(
                                scan_id=scan_id,
                                endpoint_id=endpoint.id,
                                parameter_id=param_id,
                                classification=c.classification.value,
                                risk_score=c.risk_score,
                                recommended_tests=[t.value for t in c.recommended_tests],
                                reason=c.reason,
                                source="ai",
                            )
                        else:
                            await intelligence.add_classification(
                                scan_id=scan_id,
                                endpoint_id=endpoint.id,
                                parameter_id=param_id,
                                classification="unknown",
                                risk_score=0,
                                recommended_tests=[],
                                reason="AI unavailable or produced no valid classification.",
                                source="fallback",
                            )

            scans = ScanRepository(session)
            lifecycle = ScanLifecycle(ScanState.DISCOVERY)
            lifecycle.advance()  # DISCOVERY -> INTELLIGENCE
            await scans.update_status(scan_id, lifecycle.state.value)

        await provider.aclose()

        typer.echo(
            f"Classified {classified_count} endpoint/parameter pairs "
            f"({ai_count} via AI, {fallback_count} fallback"
            f"{' — LLM unreachable' if not ai_available else ''}). "
            f"Scan advanced to INTELLIGENCE."
        )

    asyncio.run(_run())


@scan_app.command("test")
def scan_test(
    scan_id: str,
    config: str = typer.Option(..., "--config", "-c"),
    max_parameters: int = typer.Option(200, help="Cap on how many parameters get parameter-level scanners."),
) -> None:
    """Phase 6 — Detection: run deterministic scanners (security headers,
    information exposure, open redirect, reflected XSS, path traversal,
    error-based SQLi) against every discovered host/endpoint/parameter, subject to
    scan mode (docs/architecture.md §29 — PASSIVE/SAFE/ACTIVE gate which scanners
    run at all). Persists Test/Finding/Evidence records.

    Every finding this produces is a CANDIDATE, never a confirmed vulnerability —
    confidence is always "low" or "info"/"high" (for objective facts like a missing
    header), never "confirmed". Verification and correlation are Phase 9.

    Scan must be in INTELLIGENCE. Advances INTELLIGENCE -> PRIORITIZED -> TESTING."""
    cfg = _load_config(config)
    configure_logging(cfg.log_level)

    scope = ScopeEngine(allow=cfg.target.scope.allow, deny=cfg.target.scope.deny)
    rate_limiter = RateLimiter(
        requests_per_second=cfg.limits.requests_per_second,
        concurrency=cfg.limits.concurrency,
        max_requests=cfg.limits.max_requests,
    )

    async def _run() -> None:
        engine = get_engine(cfg.storage_path)
        await init_db(engine)
        session_factory = make_session_factory(engine)

        async with session_scope(session_factory) as session:
            scans = ScanRepository(session)
            scan_record = await scans.get(scan_id)
            if scan_record is None:
                typer.echo(f"No such scan: {scan_id}", err=True)
                raise typer.Exit(code=1)
            if scan_record.status != ScanState.INTELLIGENCE.value:
                typer.echo(
                    f"Scan {scan_id} must be in INTELLIGENCE to test "
                    f"(currently: {scan_record.status}).",
                    err=True,
                )
                raise typer.Exit(code=1)
            target_id = scan_record.target_id
            mode = scan_record.mode

            lifecycle = ScanLifecycle(ScanState.INTELLIGENCE)
            lifecycle.advance()  # INTELLIGENCE -> PRIORITIZED
            await scans.update_status(scan_id, lifecycle.state.value)

        # Best-effort scheme reconstruction: reuse the scheme from configured seed
        # URLs (same limitation already documented for discover-js in Phase 3 —
        # stored endpoints only have a path, not a full scheme+host URL).
        default_scheme = "https"
        if cfg.target.seed_urls:
            default_scheme = httpx.URL(cfg.target.seed_urls[0]).scheme

        auth_contexts = build_contexts(
            [
                AuthContextConfig(kind=a.kind, label=a.label, name=a.name, env_var=a.env_var)
                for a in cfg.target.auth_contexts
            ]
        )
        orchestrator = TestOrchestrator(
            scanners=build_default_scanners(), mode=mode, auth_contexts=auth_contexts
        )

        findings_to_persist: list[tuple[str, str | None, object]] = []  # (endpoint_id, parameter_id, NormalizedFinding)
        total_scanners_run = 0
        total_scanners_skipped = 0
        errors: list[str] = []
        parameters_tested = 0

        async with SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter) as http_client:
            async with session_scope(session_factory) as session:
                attack_surface = AttackSurfaceRepository(session)
                hosts = await attack_surface.list_hosts_for_target(target_id)

                for host in hosts:
                    host_root = f"{default_scheme}://{host.hostname}/"
                    host_result = await orchestrator.run_host_level(host_root, http_client)
                    total_scanners_run += host_result.scanners_run
                    total_scanners_skipped += host_result.scanners_skipped_mode
                    errors.extend(host_result.errors)
                    for finding in host_result.findings:
                        # Host-level findings aren't tied to one endpoint; attach to
                        # None here and handle at persistence time via a synthetic
                        # root endpoint below.
                        findings_to_persist.append((None, None, finding, host))

                    endpoints = await attack_surface.list_endpoints_for_host(host.id)
                    for endpoint in endpoints:
                        # Endpoints discovered via JS intelligence (Phase 3) for
                        # WebSocket/absolute-URL routes store the FULL URL in
                        # `path`, not a relative path — see
                        # app/intelligence/javascript.py's websocket_endpoints and
                        # the discover-js CLI command. Detect and use as-is rather
                        # than double-prefixing with scheme+host.
                        if endpoint.path.startswith(("http://", "https://", "ws://", "wss://")):
                            endpoint_url = endpoint.path
                        else:
                            endpoint_url = f"{default_scheme}://{host.hostname}{endpoint.path}"

                        endpoint_result = await orchestrator.run_endpoint_level(
                            endpoint_url, endpoint.method, http_client
                        )
                        total_scanners_run += endpoint_result.scanners_run
                        total_scanners_skipped += endpoint_result.scanners_skipped_mode
                        errors.extend(endpoint_result.errors)
                        for finding in endpoint_result.findings:
                            findings_to_persist.append((endpoint.id, None, finding, None))

                        for param in endpoint.parameters:
                            if parameters_tested >= max_parameters:
                                break
                            parameters_tested += 1
                            param_result = await orchestrator.run_parameter_level(
                                endpoint_url, endpoint.method, param.name, param.location, http_client
                            )
                            total_scanners_run += param_result.scanners_run
                            total_scanners_skipped += param_result.scanners_skipped_mode
                            errors.extend(param_result.errors)
                            for finding in param_result.findings:
                                findings_to_persist.append((endpoint.id, param.id, finding, None))
                        if parameters_tested >= max_parameters:
                            break

                        for form in endpoint.forms:
                            form_fields = [
                                {"name": f.get("name", "")} for f in (form.fields_json or [])
                            ]
                            form_result = await orchestrator.run_form_level(
                                endpoint_url, form.method, form_fields, http_client
                            )
                            total_scanners_run += form_result.scanners_run
                            total_scanners_skipped += form_result.scanners_skipped_mode
                            errors.extend(form_result.errors)
                            for finding in form_result.findings:
                                findings_to_persist.append((endpoint.id, None, finding, None))

        findings_created = 0
        async with session_scope(session_factory) as session:
            attack_surface = AttackSurfaceRepository(session)
            findings_repo = FindingsRepository(session)

            for endpoint_id, parameter_id, finding, host_for_root in findings_to_persist:
                if endpoint_id is None:
                    # Host-level finding: attach to a synthetic "/" GET endpoint so
                    # it still has a valid endpoint_id (Test/Finding both require one).
                    root_endpoint = await attack_surface.get_or_create_endpoint(
                        host_for_root.id, "/", "GET", scan_id, source="scanner"
                    )
                    endpoint_id = root_endpoint.id

                test_record = await findings_repo.create_test(
                    scan_id=scan_id,
                    endpoint_id=endpoint_id,
                    vulnerability_class=finding.metadata.get("vulnerability_class", "unknown"),
                    scanner_name=finding.tool_name,
                    parameter_id=parameter_id,
                )
                await findings_repo.create_finding_from_normalized(scan_id, test_record.id, finding)
                findings_created += 1

            scans = ScanRepository(session)
            lifecycle = ScanLifecycle(ScanState.PRIORITIZED)
            lifecycle.advance()  # PRIORITIZED -> TESTING
            await scans.update_status(scan_id, lifecycle.state.value)

        typer.echo(
            f"Testing complete: {parameters_tested} parameters tested, "
            f"{total_scanners_run} scanner runs ({total_scanners_skipped} skipped due to "
            f"scan mode), {findings_created} candidate findings recorded"
            f"{f', {len(errors)} scanner errors' if errors else ''}. "
            f"Scan advanced to TESTING."
        )

    asyncio.run(_run())


@scan_app.command("verify")
def scan_verify(
    scan_id: str,
    config: str = typer.Option(..., "--config", "-c"),
) -> None:
    """Phase 9 — Verification & Correlation: for every Finding from `scan test`,
    runs a baseline/differential comparison (reflection/injection classes) or marks
    objective findings verified / candidate-only findings needs_manual_review, then
    groups findings by (endpoint, vulnerability_class) across independent sources
    and records agreement/conflict as Correlation rows.

    NEVER sets confidence to "confirmed" — the maximum automated confidence is
    "high" (see app/verification/engine.py's module docstring for why). Advances
    TESTING -> VERIFYING -> CORRELATING."""
    cfg = _load_config(config)
    configure_logging(cfg.log_level)

    scope = ScopeEngine(allow=cfg.target.scope.allow, deny=cfg.target.scope.deny)
    rate_limiter = RateLimiter(
        requests_per_second=cfg.limits.requests_per_second,
        concurrency=cfg.limits.concurrency,
        max_requests=cfg.limits.max_requests,
    )

    async def _run() -> None:
        engine = get_engine(cfg.storage_path)
        await init_db(engine)
        session_factory = make_session_factory(engine)

        async with session_scope(session_factory) as session:
            scans = ScanRepository(session)
            scan_record = await scans.get(scan_id)
            if scan_record is None:
                typer.echo(f"No such scan: {scan_id}", err=True)
                raise typer.Exit(code=1)
            if scan_record.status != ScanState.TESTING.value:
                typer.echo(
                    f"Scan {scan_id} must be in TESTING to verify "
                    f"(currently: {scan_record.status}).",
                    err=True,
                )
                raise typer.Exit(code=1)

            lifecycle = ScanLifecycle(ScanState.TESTING)
            lifecycle.advance()  # TESTING -> VERIFYING
            await scans.update_status(scan_id, lifecycle.state.value)

        verified_count = 0
        false_positive_count = 0
        manual_review_count = 0

        async with SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter) as http_client:
            verification_engine = VerificationEngine(http_client)

            async with session_scope(session_factory) as session:
                findings_repo = FindingsRepository(session)
                findings = await findings_repo.list_findings_for_scan(scan_id)

                for finding in findings:
                    outcome = await verification_engine.verify(
                        finding.vulnerability_class,
                        finding.matched_endpoint,
                        finding.confidence,
                        finding.metadata_json or {},
                    )
                    await findings_repo.update_verification(
                        finding.id, outcome.verification_status, outcome.confidence
                    )
                    if outcome.verification_status == "verified":
                        verified_count += 1
                    elif outcome.verification_status == "false_positive":
                        false_positive_count += 1
                    else:
                        manual_review_count += 1

        correlation_groups_created = 0
        agreement_count = 0
        conflict_count = 0

        async with session_scope(session_factory) as session:
            findings_repo = FindingsRepository(session)
            findings_with_source = await findings_repo.list_findings_with_source_for_scan(scan_id)

            correlation_engine = CorrelationEngine()
            groups = correlation_engine.correlate(findings_with_source)

            for group in groups:
                await findings_repo.create_correlation(
                    scan_id=scan_id,
                    endpoint_id=group.endpoint_id,
                    vulnerability_class=group.vulnerability_class,
                    finding_ids=group.finding_ids,
                    tool_names=group.tool_names,
                    combined_confidence=group.combined_confidence,
                    status=group.status,
                    rationale=group.rationale,
                )
                correlation_groups_created += 1
                if group.status == "agreement":
                    agreement_count += 1
                elif group.status == "conflicting_evidence":
                    conflict_count += 1

            scans = ScanRepository(session)
            lifecycle = ScanLifecycle(ScanState.VERIFYING)
            lifecycle.advance()  # VERIFYING -> CORRELATING
            await scans.update_status(scan_id, lifecycle.state.value)

        typer.echo(
            f"Verification complete: {verified_count} verified, "
            f"{false_positive_count} false positives, {manual_review_count} need manual review. "
            f"Correlation: {correlation_groups_created} groups "
            f"({agreement_count} agreement, {conflict_count} conflicting evidence). "
            f"Scan advanced to CORRELATING."
        )

    asyncio.run(_run())


@scan_app.command("report")
def scan_report(
    scan_id: str,
    config: str = typer.Option(..., "--config", "-c"),
    output_format: str = typer.Option(
        "all", "--format", help="One of: json, markdown, html, all"
    ),
    output_dir: str = typer.Option("reports", help="Directory to write report file(s) into"),
) -> None:
    """Phase 10 — Reporting: assembles every Finding into a report, distinguishing
    Confirmed/Likely/Potential/Informational/Requires Manual Verification (never
    "Confirmed" in practice — see app/reporting/disposition.py), excludes false
    positives from the main report (listed separately for audit-trail
    transparency), and writes JSON/Markdown/HTML output.

    Scan must be in CORRELATING. Advances CORRELATING -> REPORTING -> COMPLETE —
    this is the final lifecycle stage."""
    cfg = _load_config(config)
    configure_logging(cfg.log_level)

    if output_format not in ("json", "markdown", "html", "all"):
        typer.echo(f"Invalid --format {output_format!r}; must be json, markdown, html, or all", err=True)
        raise typer.Exit(code=1)

    async def _run() -> None:
        engine = get_engine(cfg.storage_path)
        await init_db(engine)
        session_factory = make_session_factory(engine)

        async with session_scope(session_factory) as session:
            scans = ScanRepository(session)
            scan_record = await scans.get(scan_id)
            if scan_record is None:
                typer.echo(f"No such scan: {scan_id}", err=True)
                raise typer.Exit(code=1)
            if scan_record.status != ScanState.CORRELATING.value:
                typer.echo(
                    f"Scan {scan_id} must be in CORRELATING to report "
                    f"(currently: {scan_record.status}).",
                    err=True,
                )
                raise typer.Exit(code=1)

            lifecycle = ScanLifecycle(ScanState.CORRELATING)
            lifecycle.advance()  # CORRELATING -> REPORTING
            await scans.update_status(scan_id, lifecycle.state.value)

        async with session_scope(session_factory) as session:
            builder = ReportBuilder(
                ScanRepository(session), TargetRepository(session), FindingsRepository(session)
            )
            report = await builder.build(scan_id)

            scan_dir = Path(output_dir) / scan_id
            scan_dir.mkdir(parents=True, exist_ok=True)

            written_files = []
            if output_format in ("json", "all"):
                path = scan_dir / "report.json"
                path.write_text(json_renderer.render(report))
                written_files.append(str(path))
            if output_format in ("markdown", "all"):
                path = scan_dir / "report.md"
                path.write_text(markdown_renderer.render(report))
                written_files.append(str(path))
            if output_format in ("html", "all"):
                path = scan_dir / "report.html"
                path.write_text(html_renderer.render(report))
                written_files.append(str(path))

            scans = ScanRepository(session)
            lifecycle = ScanLifecycle(ScanState.REPORTING)
            lifecycle.advance()  # REPORTING -> COMPLETE
            await scans.update_status(scan_id, lifecycle.state.value)

        typer.echo(
            f"Report generated: {len(report.findings)} findings "
            f"({len(report.excluded_false_positives)} false positives excluded). "
            f"Wrote: {', '.join(written_files)}. Scan COMPLETE."
        )

    asyncio.run(_run())


@scan_app.command("status")
def scan_status(
    scan_id: str,
    config: str = typer.Option(..., "--config", "-c"),
) -> None:
    cfg = _load_config(config)
    configure_logging(cfg.log_level)

    async def _run() -> None:
        engine = get_engine(cfg.storage_path)
        session_factory = make_session_factory(engine)
        async with session_scope(session_factory) as session:
            scans = ScanRepository(session)
            scan_record = await scans.get(scan_id)
            if scan_record is None:
                typer.echo(f"No such scan: {scan_id}", err=True)
                raise typer.Exit(code=1)
            typer.echo(
                f"scan={scan_record.id} mode={scan_record.mode} "
                f"status={scan_record.status} stopped_reason={scan_record.stopped_reason}"
            )
        await engine.dispose()

    asyncio.run(_run())


@tools_app.command("list")
def tools_list() -> None:
    """Phase 5 — Tool Orchestration: show every registered external tool adapter,
    whether its binary is currently available on PATH, and its detected version.
    Does not run any tool — purely an availability/version report (see
    docs/architecture.md §48, tool version tracking)."""

    async def _run() -> None:
        registry = build_default_registry()
        report = await registry.availability_report()
        for tool_name, info in report.items():
            status = "available" if info["available"] else "NOT FOUND on PATH"
            version = info["version"] or "-"
            line = f"{tool_name:12s} {status:20s} version={version}"
            if tool_name == "httpx" and info["available"] and info["version"] is None:
                line += (
                    "  [!] found an 'httpx' binary but couldn't read its version — "
                    "this is often the Python httpx package's own CLI shadowing "
                    "ProjectDiscovery's httpx on PATH. See docs/tools.md."
                )
            typer.echo(line)

    asyncio.run(_run())


@app.command("dashboard")
def dashboard(
    config: str = typer.Option(..., "--config", "-c"),
    host: str = typer.Option(
        "127.0.0.1", help="Bind address. Do NOT use 0.0.0.0 — this server has no authentication."
    ),
    port: int = typer.Option(8000, help="Port to listen on."),
) -> None:
    """Phase 11 — Dashboard: launches a local, read-only web UI over the scan
    database (scan status, attack surface, findings, AI reasoning). Every mutation
    still happens exclusively through `scan ...` CLI commands — this only ever
    reads.

    SECURITY: no authentication. Binds to 127.0.0.1 by default; do not change this
    to 0.0.0.0 or otherwise expose it beyond localhost without adding
    authentication first (see docs/dashboard.md)."""
    cfg = _load_config(config)
    configure_logging(cfg.log_level)

    from app.dashboard.app import DashboardUnavailable, create_dashboard_app

    try:
        dashboard_app = create_dashboard_app(cfg.storage_path)
    except DashboardUnavailable as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1)

    if host not in ("127.0.0.1", "localhost"):
        typer.echo(
            f"[!] Binding to {host!r} — this dashboard has NO AUTHENTICATION. "
            "Only do this if you understand the exposure.",
            err=True,
        )

    import uvicorn

    typer.echo(f"SENTINEL dashboard running at http://{host}:{port}")
    uvicorn.run(dashboard_app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    app()
