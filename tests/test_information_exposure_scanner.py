import httpx
import pytest

from app.core.http_client import SentinelHTTPClient
from app.core.rate_limiter import RateLimiter
from app.scanners.base import ScanTarget
from app.scanners.information_exposure import InformationExposureScanner
from app.scope.engine import ScopeEngine


def _client(handler):
    scope = ScopeEngine(allow=["app.example.com"])
    rate_limiter = RateLimiter(requests_per_second=1000, concurrency=5, max_requests=1000)
    return SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter, transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_flags_exposed_sensitive_file():
    def handler(request):
        if str(request.url).endswith(".env"):
            return httpx.Response(200, content=b"DB_PASSWORD=secret")
        return httpx.Response(404, content=b"not found")

    async with _client(handler) as client:
        scanner = InformationExposureScanner()
        target = ScanTarget(url="https://app.example.com/")
        findings = await scanner.scan(target, client)

    assert len(findings) == 1
    assert ".env" in findings[0].title
    assert findings[0].severity == "medium"


@pytest.mark.asyncio
async def test_no_findings_when_everything_404s():
    def handler(request):
        return httpx.Response(404, content=b"not found")

    async with _client(handler) as client:
        scanner = InformationExposureScanner()
        target = ScanTarget(url="https://app.example.com/")
        findings = await scanner.scan(target, client)

    assert findings == []


@pytest.mark.asyncio
async def test_ignores_empty_200_response():
    def handler(request):
        return httpx.Response(200, content=b"")

    async with _client(handler) as client:
        scanner = InformationExposureScanner()
        target = ScanTarget(url="https://app.example.com/")
        findings = await scanner.scan(target, client)

    assert findings == []


@pytest.mark.asyncio
async def test_never_flags_benign_wellknown_security_txt():
    def handler(request):
        if "security.txt" in str(request.url):
            return httpx.Response(200, content=b"Contact: security@example.com")
        return httpx.Response(404, content=b"not found")

    async with _client(handler) as client:
        scanner = InformationExposureScanner()
        target = ScanTarget(url="https://app.example.com/")
        findings = await scanner.scan(target, client)

    assert findings == []
