import httpx
import pytest

from app.core.http_client import SentinelHTTPClient
from app.core.rate_limiter import RateLimiter
from app.core.test_orchestrator import TestOrchestrator
from app.scanners.registry import build_default_scanners
from app.scope.engine import ScopeEngine


def _client(handler):
    scope = ScopeEngine(allow=["app.example.com"])
    rate_limiter = RateLimiter(requests_per_second=1000, concurrency=5, max_requests=1000)
    return SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter, transport=httpx.MockTransport(handler))


# Registered host-level scanners: security_headers(passive), information_exposure(safe),
# cors(safe), jwt_weakness(safe) = 4 total.
# Registered parameter-level scanners: open_redirect(safe, gated), reflected_xss(safe),
# path_traversal(active), sqli_error_based(active), ssrf(active, gated), ssti(active),
# idor_candidate(safe, self-gated internally), identity_authorization(active, self-gated
# internally on auth_contexts count) = 8 total, 2 of which have orchestrator-level name
# gating (open_redirect, ssrf).
# Registered form-level scanners: csrf(safe), file_upload(active), xxe(active),
# mass_assignment_candidate(active) = 4 total.
# Registered endpoint-level scanners: graphql_introspection(safe, self-gated on URL),
# websocket_auth(safe, self-gated on URL scheme), http_method_enum(safe) = 3 total.


@pytest.mark.asyncio
async def test_passive_mode_only_runs_security_headers():
    def handler(request):
        return httpx.Response(200, headers={}, content=b"ok")

    async with _client(handler) as client:
        orchestrator = TestOrchestrator(scanners=build_default_scanners(), mode="passive")
        result = await orchestrator.run_host_level("https://app.example.com/", client)

    assert result.scanners_run == 1
    assert result.scanners_skipped_mode == 3


@pytest.mark.asyncio
async def test_safe_mode_runs_all_four_host_level_scanners():
    def handler(request):
        return httpx.Response(404, content=b"not found")

    async with _client(handler) as client:
        orchestrator = TestOrchestrator(scanners=build_default_scanners(), mode="safe")
        result = await orchestrator.run_host_level("https://app.example.com/", client)

    assert result.scanners_run == 4
    assert result.scanners_skipped_mode == 0


@pytest.mark.asyncio
async def test_parameter_level_safe_mode_skips_active_only_scanners():
    def handler(request):
        return httpx.Response(200, content=b"ok")

    async with _client(handler) as client:
        orchestrator = TestOrchestrator(scanners=build_default_scanners(), mode="safe")
        result = await orchestrator.run_parameter_level(
            "https://app.example.com/search", "GET", "q", "query", client
        )

    # reflected_xss + idor_candidate run (both safe); path_traversal/sqli_error_based/
    # ssti/identity_authorization require active -> skipped (counted, 4 total);
    # open_redirect and ssrf are gated out entirely by name heuristic before the mode
    # check even happens, so they contribute to neither counter
    assert result.scanners_run == 2
    assert result.scanners_skipped_mode == 4


@pytest.mark.asyncio
async def test_parameter_level_active_mode_runs_everything_relevant():
    def handler(request):
        return httpx.Response(200, content=b"ok")

    async with _client(handler) as client:
        orchestrator = TestOrchestrator(scanners=build_default_scanners(), mode="active")
        result = await orchestrator.run_parameter_level(
            "https://app.example.com/go", "GET", "redirect_url", "query", client
        )

    # "redirect_url" matches both the redirect-hint heuristic (open_redirect) and the
    # SSRF hint heuristic (contains "url"): open_redirect, reflected_xss,
    # path_traversal, sqli_error_based, ssrf, ssti, idor_candidate,
    # identity_authorization (no auth_contexts configured -> returns [] but still runs) = 8
    assert result.scanners_run == 8
    assert result.scanners_skipped_mode == 0


@pytest.mark.asyncio
async def test_parameter_level_never_runs_host_form_or_endpoint_scanners():
    def handler(request):
        return httpx.Response(200, content=b"ok")

    async with _client(handler) as client:
        orchestrator = TestOrchestrator(scanners=build_default_scanners(), mode="active")
        result = await orchestrator.run_parameter_level(
            "https://app.example.com/x", "GET", "id", "query", client
        )

    # a plain "id" param at active mode with no redirect/ssrf hint match runs:
    # reflected_xss, path_traversal, sqli_error_based, ssti, idor_candidate,
    # identity_authorization = 6
    assert result.scanners_run == 6
    run_names = {f.tool_name for f in result.findings}
    assert run_names.isdisjoint(
        {
            "security_headers", "information_exposure", "cors", "jwt_weakness",
            "csrf", "file_upload", "xxe", "mass_assignment_candidate",
            "graphql_introspection", "websocket_auth", "http_method_enum",
        }
    )


@pytest.mark.asyncio
async def test_run_form_level_dispatches_only_form_scanners():
    def handler(request):
        return httpx.Response(200, content=b"ok")

    async with _client(handler) as client:
        orchestrator = TestOrchestrator(scanners=build_default_scanners(), mode="active")
        result = await orchestrator.run_form_level(
            "https://app.example.com/submit",
            "POST",
            [{"name": "comment"}],
            client,
        )

    # csrf(safe), file_upload(active, no upload hint -> []), xxe(active),
    # mass_assignment_candidate(active) = 4 scanners actually invoked
    assert result.scanners_run == 4


@pytest.mark.asyncio
async def test_run_form_level_respects_mode():
    def handler(request):
        return httpx.Response(200, content=b"ok")

    async with _client(handler) as client:
        orchestrator = TestOrchestrator(scanners=build_default_scanners(), mode="safe")
        result = await orchestrator.run_form_level(
            "https://app.example.com/submit",
            "POST",
            [{"name": "comment"}],
            client,
        )

    # only csrf is safe; file_upload/xxe/mass_assignment_candidate require active
    assert result.scanners_run == 1
    assert result.scanners_skipped_mode == 3


@pytest.mark.asyncio
async def test_run_endpoint_level_dispatches_only_endpoint_scanners():
    def handler(request):
        return httpx.Response(200, headers={"Allow": "GET, POST"}, content=b"ok")

    async with _client(handler) as client:
        orchestrator = TestOrchestrator(scanners=build_default_scanners(), mode="safe")
        result = await orchestrator.run_endpoint_level(
            "https://app.example.com/api/resource", "GET", client
        )

    # graphql_introspection (no "graphql" in URL -> []), websocket_auth (not ws:// ->
    # []), http_method_enum (runs, Allow header has no notable methods -> []) = 3 run
    assert result.scanners_run == 3
    assert result.findings == []


@pytest.mark.asyncio
async def test_scanner_exception_is_isolated_and_recorded():
    class _BoomScanner:
        name = "boom"
        vulnerability_class = "boom"
        required_mode = "passive"

        async def scan(self, target, http_client):
            raise RuntimeError("simulated scanner bug")

    def handler(request):
        return httpx.Response(200, content=b"ok")

    async with _client(handler) as client:
        orchestrator = TestOrchestrator(scanners=[_BoomScanner()], mode="active")
        result = await orchestrator.run_parameter_level(
            "https://app.example.com/x", "GET", "id", "query", client
        )

    assert result.scanners_run == 0
    assert len(result.errors) == 1
    assert "boom" in result.errors[0]
