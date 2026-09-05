import httpx
import pytest

from app.core.http_client import SentinelHTTPClient
from app.core.rate_limiter import RateLimiter
from app.scanners.base import ScanTarget
from app.scanners.cors import CORSScanner
from app.scope.engine import ScopeEngine


def _client(handler):
    scope = ScopeEngine(allow=["app.example.com"])
    rate_limiter = RateLimiter(requests_per_second=1000, concurrency=5, max_requests=1000)
    return SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter, transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_flags_reflected_origin_with_credentials_as_high():
    def handler(request):
        origin = request.headers.get("origin", "")
        return httpx.Response(
            200,
            headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            },
        )

    async with _client(handler) as client:
        scanner = CORSScanner()
        target = ScanTarget(url="https://app.example.com/api/data")
        findings = await scanner.scan(target, client)

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].metadata["credentials_allowed"] is True


@pytest.mark.asyncio
async def test_flags_reflected_origin_without_credentials_as_medium():
    def handler(request):
        origin = request.headers.get("origin", "")
        return httpx.Response(200, headers={"Access-Control-Allow-Origin": origin})

    async with _client(handler) as client:
        scanner = CORSScanner()
        target = ScanTarget(url="https://app.example.com/api/data")
        findings = await scanner.scan(target, client)

    assert len(findings) == 1
    assert findings[0].severity == "medium"


@pytest.mark.asyncio
async def test_flags_wildcard_without_credentials_as_low():
    def handler(request):
        return httpx.Response(200, headers={"Access-Control-Allow-Origin": "*"})

    async with _client(handler) as client:
        scanner = CORSScanner()
        target = ScanTarget(url="https://app.example.com/api/data")
        findings = await scanner.scan(target, client)

    assert len(findings) == 1
    assert findings[0].severity == "low"


@pytest.mark.asyncio
async def test_no_finding_when_origin_not_reflected():
    def handler(request):
        return httpx.Response(200, headers={"Access-Control-Allow-Origin": "https://trusted.example.com"})

    async with _client(handler) as client:
        scanner = CORSScanner()
        target = ScanTarget(url="https://app.example.com/api/data")
        findings = await scanner.scan(target, client)

    assert findings == []


@pytest.mark.asyncio
async def test_no_finding_when_no_cors_headers_present():
    def handler(request):
        return httpx.Response(200)

    async with _client(handler) as client:
        scanner = CORSScanner()
        target = ScanTarget(url="https://app.example.com/api/data")
        findings = await scanner.scan(target, client)

    assert findings == []
