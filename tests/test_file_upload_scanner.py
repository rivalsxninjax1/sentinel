import httpx
import pytest

from app.core.http_client import SentinelHTTPClient
from app.core.rate_limiter import RateLimiter
from app.scanners.base import ScanTarget
from app.scanners.file_upload import FileUploadScanner
from app.scope.engine import ScopeEngine


def _client(handler):
    scope = ScopeEngine(allow=["app.example.com"])
    rate_limiter = RateLimiter(requests_per_second=1000, concurrency=5, max_requests=1000)
    return SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter, transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_flags_executable_content_type_on_fetch_back():
    def handler(request):
        if request.method == "POST":
            return httpx.Response(200, content=b"Uploaded to /uploads/sentinel_test.jpg.php")
        return httpx.Response(200, headers={"Content-Type": "text/html"}, content=b"<?php ?>")

    async with _client(handler) as client:
        scanner = FileUploadScanner()
        target = ScanTarget(
            url="https://app.example.com/upload",
            method="POST",
            form_fields=[{"name": "file"}],
        )
        findings = await scanner.scan(target, client)

    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].metadata["cleanup_required"]


@pytest.mark.asyncio
async def test_low_severity_when_served_as_static_content():
    def handler(request):
        if request.method == "POST":
            return httpx.Response(200, content=b"Uploaded to /uploads/sentinel_test.jpg.php")
        return httpx.Response(200, headers={"Content-Type": "image/jpeg"}, content=b"not really an image")

    async with _client(handler) as client:
        scanner = FileUploadScanner()
        target = ScanTarget(
            url="https://app.example.com/upload",
            method="POST",
            form_fields=[{"name": "file"}],
        )
        findings = await scanner.scan(target, client)

    assert len(findings) == 1
    assert findings[0].severity == "low"


@pytest.mark.asyncio
async def test_skips_forms_without_upload_hint():
    def handler(request):
        return httpx.Response(200, content=b"ok")

    async with _client(handler) as client:
        scanner = FileUploadScanner()
        target = ScanTarget(
            url="https://app.example.com/comment",
            method="POST",
            form_fields=[{"name": "text"}],
        )
        findings = await scanner.scan(target, client)

    assert findings == []


@pytest.mark.asyncio
async def test_no_findings_without_form_fields():
    scanner = FileUploadScanner()
    target = ScanTarget(url="https://app.example.com/upload", method="POST", form_fields=None)
    findings = await scanner.scan(target, http_client=None)

    assert findings == []


@pytest.mark.asyncio
async def test_rejected_upload_produces_no_finding():
    def handler(request):
        return httpx.Response(415, content=b"unsupported media type")

    async with _client(handler) as client:
        scanner = FileUploadScanner()
        target = ScanTarget(
            url="https://app.example.com/upload",
            method="POST",
            form_fields=[{"name": "file"}],
        )
        findings = await scanner.scan(target, client)

    assert findings == []
