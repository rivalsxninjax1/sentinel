import httpx
import pytest

from app.core.http_client import SentinelHTTPClient
from app.core.rate_limiter import RateLimiter
from app.scanners.base import ScanTarget
from app.scanners.mass_assignment_candidate import MassAssignmentCandidateScanner
from app.scope.engine import ScopeEngine


def _client(handler):
    scope = ScopeEngine(allow=["app.example.com"])
    rate_limiter = RateLimiter(requests_per_second=1000, concurrency=5, max_requests=1000)
    return SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter, transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_flags_reflected_injected_field():
    def handler(request):
        return httpx.Response(200, content=b'{"name": "sentinel_test_value", "role": "admin"}')

    async with _client(handler) as client:
        scanner = MassAssignmentCandidateScanner()
        target = ScanTarget(
            url="https://app.example.com/profile",
            method="POST",
            form_fields=[{"name": "name"}],
        )
        findings = await scanner.scan(target, client)

    assert len(findings) == 1
    assert findings[0].severity == "medium"


@pytest.mark.asyncio
async def test_no_finding_when_field_not_reflected():
    def handler(request):
        return httpx.Response(200, content=b'{"name": "sentinel_test_value"}')

    async with _client(handler) as client:
        scanner = MassAssignmentCandidateScanner()
        target = ScanTarget(
            url="https://app.example.com/profile",
            method="POST",
            form_fields=[{"name": "name"}],
        )
        findings = await scanner.scan(target, client)

    assert findings == []


@pytest.mark.asyncio
async def test_skips_when_role_already_a_legitimate_field():
    scanner = MassAssignmentCandidateScanner()
    target = ScanTarget(
        url="https://app.example.com/profile",
        method="POST",
        form_fields=[{"name": "name"}, {"name": "role"}],
    )
    findings = await scanner.scan(target, http_client=None)
    assert findings == []


@pytest.mark.asyncio
async def test_skips_get_forms():
    scanner = MassAssignmentCandidateScanner()
    target = ScanTarget(url="https://app.example.com/profile", method="GET", form_fields=[{"name": "name"}])
    findings = await scanner.scan(target, http_client=None)
    assert findings == []


@pytest.mark.asyncio
async def test_no_finding_on_rejected_request():
    def handler(request):
        return httpx.Response(422, content=b"validation error")

    async with _client(handler) as client:
        scanner = MassAssignmentCandidateScanner()
        target = ScanTarget(
            url="https://app.example.com/profile",
            method="POST",
            form_fields=[{"name": "name"}],
        )
        findings = await scanner.scan(target, client)

    assert findings == []
