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


# Registered host-level scanners (Phase 6+7): security_headers(passive),
# information_exposure(safe), cors(safe), jwt_weakness(safe) = 4 total.


@pytest.mark.asyncio
async def test_passive_mode_only_runs_security_headers():
    def handler(request):
        return httpx.Response(200, headers={}, content=b"ok")

    async with _client(handler) as client:
        orchestrator = TestOrchestrator(scanners=build_default_scanners(), mode="passive")
        result = await orchestrator.run_host_level("https://app.example.com/", client)

    # only security_headers is passive; information_exposure/cors/jwt_weakness need safe
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

    # reflected_xss + idor_candidate run (both safe, idor_candidate just finds nothing
    # for "q"); path_traversal/sqli_error_based/ssti require active -> skipped (counted);
    # open_redirect and ssrf are gated out entirely by name heuristic before the mode
    # check even happens, so they contribute to neither counter
    assert result.scanners_run == 2
    assert result.scanners_skipped_mode == 3


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
    # path_traversal, sqli_error_based, ssrf, ssti, idor_candidate = 7
    assert result.scanners_run == 7
    assert result.scanners_skipped_mode == 0


@pytest.mark.asyncio
async def test_parameter_level_never_runs_host_or_form_scanners():
    def handler(request):
        return httpx.Response(200, content=b"ok")

    async with _client(handler) as client:
        orchestrator = TestOrchestrator(scanners=build_default_scanners(), mode="active")
        result = await orchestrator.run_parameter_level(
            "https://app.example.com/x", "GET", "id", "query", client
        )

    # a plain "id" param at active mode with no redirect/ssrf hint match runs:
    # reflected_xss, path_traversal, sqli_error_based, ssti, idor_candidate = 5.
    # None of security_headers/information_exposure/cors/jwt_weakness (host-level) or
    # csrf/file_upload/xxe (form-level) should ever be dispatched here.
    assert result.scanners_run == 5
    run_scanner_names = {f.tool_name for f in result.findings} | {
        "reflected_xss", "path_traversal", "sqli_error_based", "ssti", "idor_candidate"
    }
    assert run_scanner_names.isdisjoint(
        {"security_headers", "information_exposure", "cors", "jwt_weakness", "csrf", "file_upload", "xxe"}
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

    # csrf(safe), file_upload(active, but no upload hint in url/fields -> returns []
    # but still counted as "run"), xxe(active) = 3 scanners actually invoked
    assert result.scanners_run == 3


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

    # only csrf is safe; file_upload and xxe require active -> skipped
    assert result.scanners_run == 1
    assert result.scanners_skipped_mode == 2


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
        # run_parameter_level skips host-level/form-level scanners only; boom isn't
        # in either set so it runs
        result = await orchestrator.run_parameter_level(
            "https://app.example.com/x", "GET", "id", "query", client
        )

    assert result.scanners_run == 0
    assert len(result.errors) == 1
    assert "boom" in result.errors[0]
