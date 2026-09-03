import httpx
import pytest

from app.core.http_client import SentinelHTTPClient
from app.core.rate_limiter import RateLimiter
from app.scanners.base import ScanTarget
from app.scanners.security_headers import SecurityHeadersScanner
from app.scope.engine import ScopeEngine


def _client(handler):
    scope = ScopeEngine(allow=["app.example.com"])
    rate_limiter = RateLimiter(requests_per_second=1000, concurrency=5, max_requests=1000)
    return SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter, transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_flags_all_missing_headers():
    def handler(request):
        return httpx.Response(200, headers={}, content=b"ok")

    async with _client(handler) as client:
        scanner = SecurityHeadersScanner()
        target = ScanTarget(url="https://app.example.com/")
        findings = await scanner.scan(target, client)

    titles = {f.title for f in findings}
    assert any("Content-Security-Policy" in t for t in titles)
    assert any("X-Frame-Options" in t for t in titles)
    assert any("Strict-Transport-Security" in t for t in titles)


@pytest.mark.asyncio
async def test_does_not_flag_present_headers():
    def handler(request):
        return httpx.Response(
            200,
            headers={
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Strict-Transport-Security": "max-age=31536000",
                "Referrer-Policy": "no-referrer",
            },
            content=b"ok",
        )

    async with _client(handler) as client:
        scanner = SecurityHeadersScanner()
        target = ScanTarget(url="https://app.example.com/")
        findings = await scanner.scan(target, client)

    assert findings == []


@pytest.mark.asyncio
async def test_flags_server_banner_disclosure():
    def handler(request):
        return httpx.Response(
            200,
            headers={
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Strict-Transport-Security": "max-age=31536000",
                "Referrer-Policy": "no-referrer",
                "Server": "Apache/2.4.41 (Ubuntu)",
            },
            content=b"ok",
        )

    async with _client(handler) as client:
        scanner = SecurityHeadersScanner()
        target = ScanTarget(url="https://app.example.com/")
        findings = await scanner.scan(target, client)

    assert len(findings) == 1
    assert "Apache/2.4.41" in findings[0].title
    assert findings[0].severity == "info"
