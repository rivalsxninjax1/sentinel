import json

import httpx
import pytest

from app.core.http_client import SentinelHTTPClient
from app.core.rate_limiter import RateLimiter
from app.scanners.base import ScanTarget
from app.scanners.graphql_introspection import GraphQLIntrospectionScanner
from app.scope.engine import ScopeEngine


def _client(handler):
    scope = ScopeEngine(allow=["app.example.com"])
    rate_limiter = RateLimiter(requests_per_second=1000, concurrency=5, max_requests=1000)
    return SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter, transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_flags_enabled_introspection():
    def handler(request):
        return httpx.Response(
            200, json={"data": {"__schema": {"queryType": {"name": "Query"}}}}
        )

    async with _client(handler) as client:
        scanner = GraphQLIntrospectionScanner()
        target = ScanTarget(url="https://app.example.com/graphql")
        findings = await scanner.scan(target, client)

    assert len(findings) == 1
    assert findings[0].severity == "medium"


@pytest.mark.asyncio
async def test_no_finding_when_introspection_disabled():
    def handler(request):
        return httpx.Response(
            200, json={"errors": [{"message": "introspection is disabled"}]}
        )

    async with _client(handler) as client:
        scanner = GraphQLIntrospectionScanner()
        target = ScanTarget(url="https://app.example.com/graphql")
        findings = await scanner.scan(target, client)

    assert findings == []


@pytest.mark.asyncio
async def test_skips_non_graphql_urls():
    scanner = GraphQLIntrospectionScanner()
    target = ScanTarget(url="https://app.example.com/api/users")
    findings = await scanner.scan(target, http_client=None)

    assert findings == []


@pytest.mark.asyncio
async def test_no_finding_on_non_json_response():
    def handler(request):
        return httpx.Response(200, content=b"<html>not json</html>")

    async with _client(handler) as client:
        scanner = GraphQLIntrospectionScanner()
        target = ScanTarget(url="https://app.example.com/graphql")
        findings = await scanner.scan(target, client)

    assert findings == []
