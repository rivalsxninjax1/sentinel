import httpx
import pytest

from app.core.http_client import SentinelHTTPClient
from app.core.rate_limiter import RateLimiter
from app.scanners.base import ScanTarget
from app.scanners.ssti import SSTIScanner
from app.scope.engine import ScopeEngine


def _client(handler):
    scope = ScopeEngine(allow=["app.example.com"])
    rate_limiter = RateLimiter(requests_per_second=1000, concurrency=5, max_requests=1000)
    return SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter, transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_flags_evaluated_expression():
    def handler(request):
        # simulate a vulnerable Jinja2-style template that evaluates {{7*7}}
        return httpx.Response(200, content=b"<html>Result: 49</html>")

    async with _client(handler) as client:
        scanner = SSTIScanner()
        target = ScanTarget(url="https://app.example.com/render", parameter_name="name")
        findings = await scanner.scan(target, client)

    assert len(findings) == 1
    assert findings[0].severity == "high"


@pytest.mark.asyncio
async def test_no_finding_when_payload_only_reflected_not_evaluated():
    def handler(request):
        return httpx.Response(200, content=b"<html>Result: {{7*7}}</html>")

    async with _client(handler) as client:
        scanner = SSTIScanner()
        target = ScanTarget(url="https://app.example.com/render", parameter_name="name")
        findings = await scanner.scan(target, client)

    assert findings == []


@pytest.mark.asyncio
async def test_no_finding_on_unrelated_response():
    def handler(request):
        return httpx.Response(200, content=b"<html>Hello, world</html>")

    async with _client(handler) as client:
        scanner = SSTIScanner()
        target = ScanTarget(url="https://app.example.com/render", parameter_name="name")
        findings = await scanner.scan(target, client)

    assert findings == []
