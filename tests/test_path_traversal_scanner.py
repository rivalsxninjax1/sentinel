import httpx
import pytest

from app.core.http_client import SentinelHTTPClient
from app.core.rate_limiter import RateLimiter
from app.scanners.base import ScanTarget
from app.scanners.path_traversal import PathTraversalScanner
from app.scope.engine import ScopeEngine


def _client(handler):
    scope = ScopeEngine(allow=["app.example.com"])
    rate_limiter = RateLimiter(requests_per_second=1000, concurrency=5, max_requests=1000)
    return SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter, transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_flags_traversal_indicator_in_response():
    def handler(request):
        return httpx.Response(
            200, content=b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        )

    async with _client(handler) as client:
        scanner = PathTraversalScanner()
        target = ScanTarget(url="https://app.example.com/download", parameter_name="file")
        findings = await scanner.scan(target, client)

    assert len(findings) == 1
    assert "file" in findings[0].title
    assert findings[0].severity == "high"


@pytest.mark.asyncio
async def test_no_finding_on_normal_response():
    def handler(request):
        return httpx.Response(200, content=b"file not found")

    async with _client(handler) as client:
        scanner = PathTraversalScanner()
        target = ScanTarget(url="https://app.example.com/download", parameter_name="file")
        findings = await scanner.scan(target, client)

    assert findings == []


@pytest.mark.asyncio
async def test_no_finding_without_parameter():
    def handler(request):
        return httpx.Response(200, content=b"root:x:0:0")  # even if body matches, no param to test

    async with _client(handler) as client:
        scanner = PathTraversalScanner()
        target = ScanTarget(url="https://app.example.com/download")
        findings = await scanner.scan(target, client)

    assert findings == []
