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


@pytest.mark.asyncio
async def test_passive_mode_only_runs_security_headers():
    def handler(request):
        return httpx.Response(200, headers={}, content=b"ok")

    async with _client(handler) as client:
        orchestrator = TestOrchestrator(scanners=build_default_scanners(), mode="passive")
        result = await orchestrator.run_host_level("https://app.example.com/", client)

    # security_headers is passive; information_exposure requires safe -> skipped
    assert result.scanners_run == 1
    assert result.scanners_skipped_mode == 1


@pytest.mark.asyncio
async def test_safe_mode_runs_both_host_level_scanners():
    def handler(request):
        return httpx.Response(404, content=b"not found")

    async with _client(handler) as client:
        orchestrator = TestOrchestrator(scanners=build_default_scanners(), mode="safe")
        result = await orchestrator.run_host_level("https://app.example.com/", client)

    assert result.scanners_run == 2
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

    # reflected_xss runs (safe); path_traversal + sqli_error_based require active -> skipped;
    # open_redirect only runs for redirect-hinting param names, "q" doesn't match -> not counted at all
    assert result.scanners_run == 1
    assert result.scanners_skipped_mode == 2


@pytest.mark.asyncio
async def test_parameter_level_active_mode_runs_everything_relevant():
    def handler(request):
        return httpx.Response(200, content=b"ok")

    async with _client(handler) as client:
        orchestrator = TestOrchestrator(scanners=build_default_scanners(), mode="active")
        result = await orchestrator.run_parameter_level(
            "https://app.example.com/go", "GET", "redirect_url", "query", client
        )

    # "redirect_url" matches the redirect-hint heuristic, so open_redirect also runs
    assert result.scanners_run == 4  # open_redirect, reflected_xss, path_traversal, sqli_error_based
    assert result.scanners_skipped_mode == 0


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
        # run_parameter_level skips host-level scanners only; boom isn't host-level so it runs
        result = await orchestrator.run_parameter_level(
            "https://app.example.com/x", "GET", "id", "query", client
        )

    assert result.scanners_run == 0
    assert len(result.errors) == 1
    assert "boom" in result.errors[0]
