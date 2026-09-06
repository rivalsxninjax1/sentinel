import httpx
import pytest

from app.core.http_client import SentinelHTTPClient
from app.core.rate_limiter import RateLimiter
from app.scanners.base import ScanTarget
from app.scanners.http_method_enum import HTTPMethodEnumScanner
from app.scope.engine import ScopeEngine


def _client(handler):
    scope = ScopeEngine(allow=["app.example.com"])
    rate_limiter = RateLimiter(requests_per_second=1000, concurrency=5, max_requests=1000)
    return SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter, transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_flags_notable_methods_in_allow_header():
    def handler(request):
        return httpx.Response(200, headers={"Allow": "GET, POST, PUT, DELETE"})

    async with _client(handler) as client:
        scanner = HTTPMethodEnumScanner()
        target = ScanTarget(url="https://app.example.com/api/resource/1")
        findings = await scanner.scan(target, client)

    assert len(findings) == 1
    assert "PUT" in findings[0].title
    assert "DELETE" in findings[0].title


@pytest.mark.asyncio
async def test_no_finding_for_benign_methods_only():
    def handler(request):
        return httpx.Response(200, headers={"Allow": "GET, HEAD, POST"})

    async with _client(handler) as client:
        scanner = HTTPMethodEnumScanner()
        target = ScanTarget(url="https://app.example.com/api/resource/1")
        findings = await scanner.scan(target, client)

    assert findings == []


@pytest.mark.asyncio
async def test_no_finding_when_no_allow_header():
    def handler(request):
        return httpx.Response(200)

    async with _client(handler) as client:
        scanner = HTTPMethodEnumScanner()
        target = ScanTarget(url="https://app.example.com/api/resource/1")
        findings = await scanner.scan(target, client)

    assert findings == []


@pytest.mark.asyncio
async def test_never_sends_mutating_requests():
    """Ensures this scanner only ever sends OPTIONS — never PUT/DELETE/PATCH."""
    methods_seen = []

    def handler(request):
        methods_seen.append(request.method)
        return httpx.Response(200, headers={"Allow": "GET, PUT, DELETE"})

    async with _client(handler) as client:
        scanner = HTTPMethodEnumScanner()
        target = ScanTarget(url="https://app.example.com/api/resource/1")
        await scanner.scan(target, client)

    assert methods_seen == ["OPTIONS"]
