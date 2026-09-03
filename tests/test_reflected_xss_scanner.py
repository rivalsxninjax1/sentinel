import httpx
import pytest

from app.core.http_client import SentinelHTTPClient
from app.core.rate_limiter import RateLimiter
from app.scanners.base import ScanTarget
from app.scanners.reflected_xss import ReflectedXSSScanner
from app.scope.engine import ScopeEngine


def _client(handler):
    scope = ScopeEngine(allow=["app.example.com"])
    rate_limiter = RateLimiter(requests_per_second=1000, concurrency=5, max_requests=1000)
    return SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter, transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_flags_unescaped_reflection():
    def handler(request):
        # simulate a naive search page: read the (auto-decoded) query param and
        # echo it back into the page verbatim, unescaped
        q = request.url.params.get("q", "")
        return httpx.Response(200, content=f"<html>Results for: {q}</html>".encode())

    async with _client(handler) as client:
        scanner = ReflectedXSSScanner()
        target = ScanTarget(url="https://app.example.com/search", parameter_name="q")
        findings = await scanner.scan(target, client)

    assert len(findings) == 1
    assert "q" in findings[0].title


@pytest.mark.asyncio
async def test_no_finding_when_payload_is_encoded():
    def handler(request):
        # simulate proper HTML-encoding: the raw payload never appears verbatim
        return httpx.Response(200, content=b"<html>Results for: &lt;sentinel9f2a&gt;</html>")

    async with _client(handler) as client:
        scanner = ReflectedXSSScanner()
        target = ScanTarget(url="https://app.example.com/search", parameter_name="q")
        findings = await scanner.scan(target, client)

    assert findings == []


@pytest.mark.asyncio
async def test_no_finding_without_parameter():
    def handler(request):
        return httpx.Response(200, content=b"<html>ok</html>")

    async with _client(handler) as client:
        scanner = ReflectedXSSScanner()
        target = ScanTarget(url="https://app.example.com/search")
        findings = await scanner.scan(target, client)

    assert findings == []
