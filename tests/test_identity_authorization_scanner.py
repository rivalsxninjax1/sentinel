import httpx
import pytest

from app.core.auth_context import AuthenticationContext
from app.core.http_client import SentinelHTTPClient
from app.core.rate_limiter import RateLimiter
from app.scanners.base import ScanTarget
from app.scanners.identity_authorization import IdentityAuthorizationScanner
from app.scope.engine import ScopeEngine


def _client(handler):
    scope = ScopeEngine(allow=["app.example.com"])
    rate_limiter = RateLimiter(requests_per_second=1000, concurrency=5, max_requests=1000)
    return SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter, transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_no_findings_without_two_identities():
    scanner = IdentityAuthorizationScanner()
    target = ScanTarget(url="https://app.example.com/orders/1", parameter_name="id", auth_contexts=[])
    findings = await scanner.scan(target, http_client=None)
    assert findings == []


@pytest.mark.asyncio
async def test_no_findings_without_parameter():
    ctx_a = AuthenticationContext("user_a", "header", "Authorization", "SENTINEL_TEST_A")
    ctx_b = AuthenticationContext("user_b", "header", "Authorization", "SENTINEL_TEST_B")
    scanner = IdentityAuthorizationScanner()
    target = ScanTarget(url="https://app.example.com/orders/1", auth_contexts=[ctx_a, ctx_b])
    findings = await scanner.scan(target, http_client=None)
    assert findings == []


@pytest.mark.asyncio
async def test_flags_identical_access_across_identities(monkeypatch):
    monkeypatch.setenv("SENTINEL_TEST_A", "token-a")
    monkeypatch.setenv("SENTINEL_TEST_B", "token-b")

    def handler(request):
        auth = request.headers.get("authorization", "")
        if not auth:
            return httpx.Response(401, content=b"unauthorized")
        # Both distinct identities get the exact same object back — the anomaly.
        return httpx.Response(200, content=b'{"order_id": 1, "amount": 500}')

    ctx_a = AuthenticationContext("user_a", "header", "Authorization", "SENTINEL_TEST_A")
    ctx_b = AuthenticationContext("user_b", "header", "Authorization", "SENTINEL_TEST_B")

    async with _client(handler) as client:
        scanner = IdentityAuthorizationScanner()
        target = ScanTarget(
            url="https://app.example.com/orders/1", parameter_name="id", auth_contexts=[ctx_a, ctx_b]
        )
        findings = await scanner.scan(target, client)

    assert len(findings) == 1
    assert findings[0].metadata["identities_tested"] == ["user_a", "user_b"]
    assert findings[0].metadata["anonymous_denied"] is True
    assert "caveat" in findings[0].metadata


@pytest.mark.asyncio
async def test_no_finding_when_one_identity_denied(monkeypatch):
    monkeypatch.setenv("SENTINEL_TEST_A", "token-a")
    monkeypatch.setenv("SENTINEL_TEST_B", "token-b")

    def handler(request):
        auth = request.headers.get("authorization", "")
        if auth == "token-a":
            return httpx.Response(200, content=b'{"order_id": 1}')
        if auth == "token-b":
            return httpx.Response(403, content=b"forbidden")
        return httpx.Response(401)

    ctx_a = AuthenticationContext("user_a", "header", "Authorization", "SENTINEL_TEST_A")
    ctx_b = AuthenticationContext("user_b", "header", "Authorization", "SENTINEL_TEST_B")

    async with _client(handler) as client:
        scanner = IdentityAuthorizationScanner()
        target = ScanTarget(
            url="https://app.example.com/orders/1", parameter_name="id", auth_contexts=[ctx_a, ctx_b]
        )
        findings = await scanner.scan(target, client)

    assert findings == []  # this is the NORMAL, expected pattern — no anomaly


@pytest.mark.asyncio
async def test_no_finding_when_missing_credential_leaves_fewer_than_two_identities(monkeypatch):
    monkeypatch.setenv("SENTINEL_TEST_A", "token-a")
    monkeypatch.delenv("SENTINEL_TEST_B", raising=False)

    def handler(request):
        return httpx.Response(200, content=b"ok")

    ctx_a = AuthenticationContext("user_a", "header", "Authorization", "SENTINEL_TEST_A")
    ctx_b = AuthenticationContext("user_b", "header", "Authorization", "SENTINEL_TEST_B")

    async with _client(handler) as client:
        scanner = IdentityAuthorizationScanner()
        target = ScanTarget(
            url="https://app.example.com/orders/1", parameter_name="id", auth_contexts=[ctx_a, ctx_b]
        )
        findings = await scanner.scan(target, client)

    assert findings == []


@pytest.mark.asyncio
async def test_no_finding_when_response_bodies_differ_substantially(monkeypatch):
    monkeypatch.setenv("SENTINEL_TEST_A", "token-a")
    monkeypatch.setenv("SENTINEL_TEST_B", "token-b")

    def handler(request):
        auth = request.headers.get("authorization", "")
        if auth == "token-a":
            return httpx.Response(200, content=b'{"order_id": 1, "owner": "alice", "amount": 500}')
        if auth == "token-b":
            return httpx.Response(200, content=b'{"error": "different shape entirely", "code": 42}')
        return httpx.Response(401)

    ctx_a = AuthenticationContext("user_a", "header", "Authorization", "SENTINEL_TEST_A")
    ctx_b = AuthenticationContext("user_b", "header", "Authorization", "SENTINEL_TEST_B")

    async with _client(handler) as client:
        scanner = IdentityAuthorizationScanner()
        target = ScanTarget(
            url="https://app.example.com/orders/1", parameter_name="id", auth_contexts=[ctx_a, ctx_b]
        )
        findings = await scanner.scan(target, client)

    assert findings == []
