import httpx
import pytest

from app.core.http_client import SentinelHTTPClient
from app.core.rate_limiter import RateLimiter
from app.scanners.base import ScanTarget
from app.scanners.csrf import CSRFScanner
from app.scope.engine import ScopeEngine


def _client(handler):
    scope = ScopeEngine(allow=["app.example.com"])
    rate_limiter = RateLimiter(requests_per_second=1000, concurrency=5, max_requests=1000)
    return SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter, transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_flags_post_form_without_csrf_token():
    def handler(request):
        return httpx.Response(200, headers={"Set-Cookie": "session=abc123; Path=/; SameSite=Lax"})

    async with _client(handler) as client:
        scanner = CSRFScanner()
        target = ScanTarget(
            url="https://app.example.com/transfer",
            method="POST",
            form_fields=[{"name": "amount"}, {"name": "to_account"}],
        )
        findings = await scanner.scan(target, client)

    assert any("no anti-CSRF token" in f.title for f in findings)


@pytest.mark.asyncio
async def test_no_missing_token_finding_when_csrf_field_present():
    def handler(request):
        return httpx.Response(200, headers={"Set-Cookie": "session=abc123; Path=/; SameSite=Lax"})

    async with _client(handler) as client:
        scanner = CSRFScanner()
        target = ScanTarget(
            url="https://app.example.com/transfer",
            method="POST",
            form_fields=[{"name": "amount"}, {"name": "csrf_token"}],
        )
        findings = await scanner.scan(target, client)

    assert not any("no anti-CSRF token" in f.title for f in findings)


@pytest.mark.asyncio
async def test_flags_cookie_without_samesite():
    def handler(request):
        return httpx.Response(200, headers={"Set-Cookie": "session=abc123; Path=/"})

    async with _client(handler) as client:
        scanner = CSRFScanner()
        target = ScanTarget(
            url="https://app.example.com/transfer",
            method="POST",
            form_fields=[{"name": "csrf_token"}],
        )
        findings = await scanner.scan(target, client)

    assert any("without a SameSite" in f.title for f in findings)


@pytest.mark.asyncio
async def test_skips_get_forms():
    def handler(request):
        return httpx.Response(200)

    async with _client(handler) as client:
        scanner = CSRFScanner()
        target = ScanTarget(url="https://app.example.com/search", method="GET", form_fields=[{"name": "q"}])
        findings = await scanner.scan(target, client)

    assert findings == []


@pytest.mark.asyncio
async def test_no_findings_without_form_fields():
    scanner = CSRFScanner()
    target = ScanTarget(url="https://app.example.com/transfer", method="POST", form_fields=None)
    findings = await scanner.scan(target, http_client=None)

    assert findings == []
