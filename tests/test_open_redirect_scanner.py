import httpx
import pytest

from app.core.http_client import SentinelHTTPClient
from app.core.rate_limiter import RateLimiter
from app.scanners.base import ScanTarget
from app.scanners.open_redirect import OpenRedirectScanner
from app.scope.engine import ScopeEngine


def _client(handler):
    scope = ScopeEngine(allow=["app.example.com"])
    rate_limiter = RateLimiter(requests_per_second=1000, concurrency=5, max_requests=1000)
    return SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter, transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_flags_reflected_external_redirect():
    def handler(request):
        return httpx.Response(302, headers={"Location": "https://sentinel-redirect-test.invalid/"})

    async with _client(handler) as client:
        scanner = OpenRedirectScanner()
        target = ScanTarget(url="https://app.example.com/go", parameter_name="next")
        findings = await scanner.scan(target, client)

    assert len(findings) == 1
    assert "next" in findings[0].title


@pytest.mark.asyncio
async def test_no_finding_when_redirect_stays_internal():
    def handler(request):
        return httpx.Response(302, headers={"Location": "https://app.example.com/home"})

    async with _client(handler) as client:
        scanner = OpenRedirectScanner()
        target = ScanTarget(url="https://app.example.com/go", parameter_name="next")
        findings = await scanner.scan(target, client)

    assert findings == []


@pytest.mark.asyncio
async def test_no_finding_when_no_parameter_given():
    def handler(request):
        return httpx.Response(200)

    async with _client(handler) as client:
        scanner = OpenRedirectScanner()
        target = ScanTarget(url="https://app.example.com/go")  # no parameter_name
        findings = await scanner.scan(target, client)

    assert findings == []


@pytest.mark.asyncio
async def test_no_finding_on_200_response():
    def handler(request):
        return httpx.Response(200, content=b"no redirect here")

    async with _client(handler) as client:
        scanner = OpenRedirectScanner()
        target = ScanTarget(url="https://app.example.com/go", parameter_name="next")
        findings = await scanner.scan(target, client)

    assert findings == []
