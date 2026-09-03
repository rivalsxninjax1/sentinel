import httpx
import pytest

from app.core.http_client import SentinelHTTPClient
from app.core.rate_limiter import RateLimiter
from app.scanners.base import ScanTarget
from app.scanners.sqli_error_based import SqliErrorBasedScanner
from app.scope.engine import ScopeEngine


def _client(handler):
    scope = ScopeEngine(allow=["app.example.com"])
    rate_limiter = RateLimiter(requests_per_second=1000, concurrency=5, max_requests=1000)
    return SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter, transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_flags_mysql_error_signature():
    def handler(request):
        return httpx.Response(
            500,
            content=b"Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given",
        )

    async with _client(handler) as client:
        scanner = SqliErrorBasedScanner()
        target = ScanTarget(url="https://app.example.com/product", parameter_name="id")
        findings = await scanner.scan(target, client)

    assert len(findings) == 1
    assert "id" in findings[0].title
    assert findings[0].severity == "high"


@pytest.mark.asyncio
async def test_flags_postgres_error_signature():
    def handler(request):
        return httpx.Response(500, content=b"pg_query(): query failed: ERROR syntax error")

    async with _client(handler) as client:
        scanner = SqliErrorBasedScanner()
        target = ScanTarget(url="https://app.example.com/product", parameter_name="id")
        findings = await scanner.scan(target, client)

    assert len(findings) == 1


@pytest.mark.asyncio
async def test_no_finding_on_normal_response():
    def handler(request):
        return httpx.Response(200, content=b"Product not found")

    async with _client(handler) as client:
        scanner = SqliErrorBasedScanner()
        target = ScanTarget(url="https://app.example.com/product", parameter_name="id")
        findings = await scanner.scan(target, client)

    assert findings == []
