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


class _StubOOBClient:
    def __init__(self, will_confirm: bool):
        self._will_confirm = will_confirm
        self.registered_calls: list[dict] = []

    @staticmethod
    def generate_correlation_id() -> str:
        return "sentinel-stub-correlation-id"

    def build_callback_url(self, correlation_id: str) -> str:
        return f"http://oob.test.invalid/oob/{correlation_id}"

    async def register_and_wait(self, **kwargs) -> bool:
        self.registered_calls.append(kwargs)
        return self._will_confirm


@pytest.mark.asyncio
async def test_no_oob_client_only_runs_file_read_check():
    def handler(request):
        return httpx.Response(200, content=b"nothing interesting")

    async with _client(handler) as client:
        scanner = XXEScanner()
        target = ScanTarget(
            url="https://app.example.com/api/import", method="POST",
            form_fields=[{"name": "data"}], oob_client=None,
        )
        findings = await scanner.scan(target, client)

    assert findings == []  # unchanged from Phase 7 behavior


@pytest.mark.asyncio
async def test_oob_confirmed_produces_critical_high_confidence_finding():
    def handler(request):
        return httpx.Response(200, content=b"ok")

    stub_oob = _StubOOBClient(will_confirm=True)

    async with _client(handler) as client:
        scanner = XXEScanner()
        target = ScanTarget(
            url="https://app.example.com/api/import", method="POST",
            form_fields=[{"name": "data"}], oob_client=stub_oob, oob_scan_id="scan-123",
        )
        findings = await scanner.scan(target, client)

    oob_findings = [f for f in findings if f.metadata.get("detection_method") == "oob_confirmed"]
    assert len(oob_findings) == 1
    assert oob_findings[0].severity == "critical"
    assert oob_findings[0].metadata["confidence"] == "high"
    assert stub_oob.registered_calls[0]["scan_id"] == "scan-123"


@pytest.mark.asyncio
async def test_oob_not_confirmed_still_runs_file_read_check():
    def handler(request):
        return httpx.Response(200, content=b"root:x:0:0:root:/root:/bin/bash\n")

    stub_oob = _StubOOBClient(will_confirm=False)

    async with _client(handler) as client:
        scanner = XXEScanner()
        target = ScanTarget(
            url="https://app.example.com/api/import", method="POST",
            form_fields=[{"name": "data"}], oob_client=stub_oob,
        )
        findings = await scanner.scan(target, client)

    assert not any(f.metadata.get("detection_method") == "oob_confirmed" for f in findings)
    assert any(f.metadata.get("detection_method") == "file_read_reflection" for f in findings)


@pytest.mark.asyncio
async def test_skips_get_endpoints_even_with_oob_configured():
    stub_oob = _StubOOBClient(will_confirm=True)
    scanner = XXEScanner()
    target = ScanTarget(
        url="https://app.example.com/api/import", method="GET",
        form_fields=[{"name": "data"}], oob_client=stub_oob,
    )
    findings = await scanner.scan(target, http_client=None)
    assert findings == []
    assert stub_oob.registered_calls == []


@pytest.mark.asyncio
async def test_no_findings_without_form_fields_even_with_oob_configured():
    stub_oob = _StubOOBClient(will_confirm=True)
    scanner = XXEScanner()
    target = ScanTarget(
        url="https://app.example.com/api/import", method="POST",
        form_fields=None, oob_client=stub_oob,
    )
    findings = await scanner.scan(target, http_client=None)
    assert findings == []
