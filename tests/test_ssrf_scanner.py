import httpx
import pytest

from app.core.http_client import SentinelHTTPClient
from app.core.rate_limiter import RateLimiter
from app.scanners.base import ScanTarget
from app.scanners.ssrf import SSRFScanner
from app.scope.engine import ScopeEngine


def _client(handler):
    scope = ScopeEngine(allow=["app.example.com"])
    rate_limiter = RateLimiter(requests_per_second=1000, concurrency=5, max_requests=1000)
    return SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter, transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_flags_reflected_cloud_metadata_response():
    def handler(request):
        return httpx.Response(200, content=b'{"instance-id": "i-0123456789", "ami-id": "ami-abc"}')

    async with _client(handler) as client:
        scanner = SSRFScanner()
        target = ScanTarget(url="https://app.example.com/fetch", parameter_name="url")
        findings = await scanner.scan(target, client)

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "known_gap" in findings[0].metadata


@pytest.mark.asyncio
async def test_no_finding_on_normal_response():
    def handler(request):
        return httpx.Response(200, content=b"nothing interesting here")

    async with _client(handler) as client:
        scanner = SSRFScanner()
        target = ScanTarget(url="https://app.example.com/fetch", parameter_name="url")
        findings = await scanner.scan(target, client)

    assert findings == []


@pytest.mark.asyncio
async def test_no_finding_without_parameter():
    def handler(request):
        return httpx.Response(200, content=b"ami-id")

    async with _client(handler) as client:
        scanner = SSRFScanner()
        target = ScanTarget(url="https://app.example.com/fetch")
        findings = await scanner.scan(target, client)

    assert findings == []
