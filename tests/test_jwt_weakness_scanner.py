import base64
import hashlib
import hmac
import json

import httpx
import pytest

from app.core.http_client import SentinelHTTPClient
from app.core.rate_limiter import RateLimiter
from app.scanners.base import ScanTarget
from app.scanners.jwt_weakness import JWTWeaknessScanner
from app.scope.engine import ScopeEngine


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_jwt(header: dict, payload: dict, secret: str | None = None) -> str:
    header_b64 = _b64url(json.dumps(header).encode())
    payload_b64 = _b64url(json.dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    if header.get("alg", "").lower() == "none":
        sig_b64 = ""
    elif secret is not None:
        sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        sig_b64 = _b64url(sig)
    else:
        sig_b64 = _b64url(b"not-a-real-signature")
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def _client(handler):
    scope = ScopeEngine(allow=["app.example.com"])
    rate_limiter = RateLimiter(requests_per_second=1000, concurrency=5, max_requests=1000)
    return SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter, transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_flags_alg_none():
    token = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "1", "exp": 9999999999})

    def handler(request):
        return httpx.Response(200, content=f"token: {token}".encode())

    async with _client(handler) as client:
        scanner = JWTWeaknessScanner()
        target = ScanTarget(url="https://app.example.com/")
        findings = await scanner.scan(target, client)

    assert any("alg: none" in f.title for f in findings)


@pytest.mark.asyncio
async def test_flags_weak_hs256_secret():
    token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "exp": 9999999999}, secret="secret")

    def handler(request):
        return httpx.Response(200, content=f"token: {token}".encode())

    async with _client(handler) as client:
        scanner = JWTWeaknessScanner()
        target = ScanTarget(url="https://app.example.com/")
        findings = await scanner.scan(target, client)

    weak_secret_findings = [f for f in findings if "weak" in f.title.lower()]
    assert len(weak_secret_findings) == 1
    assert weak_secret_findings[0].metadata["matched_secret"] == "secret"
    assert weak_secret_findings[0].severity == "critical"


@pytest.mark.asyncio
async def test_does_not_flag_strong_secret():
    token = _make_jwt(
        {"alg": "HS256", "typ": "JWT"}, {"sub": "1", "exp": 9999999999}, secret="a-genuinely-long-random-secret-key"
    )

    def handler(request):
        return httpx.Response(200, content=f"token: {token}".encode())

    async with _client(handler) as client:
        scanner = JWTWeaknessScanner()
        target = ScanTarget(url="https://app.example.com/")
        findings = await scanner.scan(target, client)

    assert not any("weak" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_flags_missing_exp_claim():
    token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1"}, secret="a-genuinely-long-random-secret-key")

    def handler(request):
        return httpx.Response(200, content=f"token: {token}".encode())

    async with _client(handler) as client:
        scanner = JWTWeaknessScanner()
        target = ScanTarget(url="https://app.example.com/")
        findings = await scanner.scan(target, client)

    assert any("no expiration" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_finds_jwt_in_set_cookie_header():
    token = _make_jwt({"alg": "none"}, {"sub": "1", "exp": 9999999999})

    def handler(request):
        return httpx.Response(200, headers={"Set-Cookie": f"session={token}; Path=/; HttpOnly"})

    async with _client(handler) as client:
        scanner = JWTWeaknessScanner()
        target = ScanTarget(url="https://app.example.com/")
        findings = await scanner.scan(target, client)

    assert any("alg: none" in f.title for f in findings)


@pytest.mark.asyncio
async def test_no_findings_when_no_jwt_present():
    def handler(request):
        return httpx.Response(200, content=b"<html>no tokens here</html>")

    async with _client(handler) as client:
        scanner = JWTWeaknessScanner()
        target = ScanTarget(url="https://app.example.com/")
        findings = await scanner.scan(target, client)

    assert findings == []
