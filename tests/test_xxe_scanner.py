import httpx
import pytest

from app.core.http_client import SentinelHTTPClient
from app.core.rate_limiter import RateLimiter
from app.scanners.base import ScanTarget
from app.scanners.xxe import XXEScanner
from app.scope.engine import ScopeEngine


def _client(handler):
    scope = ScopeEngine(allow=["app.example.com"])
    rate_limiter = RateLimiter(requests_per_second=1000, concurrency=5, max_requests=1000)
    return SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter, transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_flags_traversal_indicator_after_xxe_payload():
    def handler(request):
        assert request.headers.get("content-type") == "application/xml"
        return httpx.Response(200, content=b"root:x:0:0:root:/root:/bin/bash\n")

    async with _client(handler) as client:
        scanner = XXEScanner()
        target = ScanTarget(
            url="https://app.example.com/api/import",
            method="POST",
            form_fields=[{"name": "data"}],
        )
        findings = await scanner.scan(target, client)

    assert len(findings) == 1
    assert findings[0].severity == "critical"


@pytest.mark.asyncio
async def test_no_finding_when_rejected():
    def handler(request):
        return httpx.Response(415, content=b"unsupported media type")

    async with _client(handler) as client:
        scanner = XXEScanner()
        target = ScanTarget(
            url="https://app.example.com/api/import",
            method="POST",
            form_fields=[{"name": "data"}],
        )
        findings = await scanner.scan(target, client)

    assert findings == []


@pytest.mark.asyncio
async def test_skips_get_endpoints():
    scanner = XXEScanner()
    target = ScanTarget(url="https://app.example.com/api/import", method="GET", form_fields=[{"name": "data"}])
    findings = await scanner.scan(target, http_client=None)

    assert findings == []


@pytest.mark.asyncio
async def test_no_findings_without_form_fields():
    scanner = XXEScanner()
    target = ScanTarget(url="https://app.example.com/api/import", method="POST", form_fields=None)
    findings = await scanner.scan(target, http_client=None)

    assert findings == []
