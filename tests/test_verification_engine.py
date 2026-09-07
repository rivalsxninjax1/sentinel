import httpx
import pytest

from app.core.http_client import SentinelHTTPClient
from app.core.rate_limiter import RateLimiter
from app.scope.engine import ScopeEngine
from app.verification.engine import VerificationEngine


def _client(handler):
    scope = ScopeEngine(allow=["app.example.com"])
    rate_limiter = RateLimiter(requests_per_second=1000, concurrency=5, max_requests=1000)
    return SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter, transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_objective_class_is_verified_without_baseline_request():
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200)

    async with _client(handler) as client:
        engine = VerificationEngine(client)
        outcome = await engine.verify("security_headers", "https://app.example.com/", "high", {})

    assert outcome.verification_status == "verified"
    assert outcome.confidence == "high"
    assert calls == []  # no baseline request needed for objective classes


@pytest.mark.asyncio
async def test_unknown_class_needs_manual_review():
    async with _client(lambda r: httpx.Response(200)) as client:
        engine = VerificationEngine(client)
        outcome = await engine.verify("mass_assignment", "https://app.example.com/x", "low", {})

    assert outcome.verification_status == "needs_manual_review"
    assert outcome.confidence == "low"  # unchanged


@pytest.mark.asyncio
async def test_xss_false_positive_when_baseline_also_reflects_marker():
    def handler(request):
        # baseline (no payload) ALSO contains the exact marker — app always echoes
        # it, unrelated to any injected payload
        return httpx.Response(200, content=b"<html><sentinel9f2a> always here</html>")

    async with _client(handler) as client:
        engine = VerificationEngine(client)
        outcome = await engine.verify(
            "xss",
            "https://app.example.com/search?q=%3Csentinel9f2a%3E",
            "low",
            {"parameter": "q"},
        )

    assert outcome.verification_status == "false_positive"
    assert outcome.confidence == "low"  # not upgraded


@pytest.mark.asyncio
async def test_xss_verified_and_upgraded_when_baseline_is_clean():
    def handler(request):
        return httpx.Response(200, content=b"<html>no marker here</html>")

    async with _client(handler) as client:
        engine = VerificationEngine(client)
        outcome = await engine.verify(
            "xss",
            "https://app.example.com/search?q=%3Csentinel9f2a%3E",
            "low",
            {"parameter": "q"},
        )

    assert outcome.verification_status == "verified"
    assert outcome.confidence == "medium"  # low -> medium, one step


@pytest.mark.asyncio
async def test_confidence_upgrade_is_capped_at_high():
    def handler(request):
        return httpx.Response(200, content=b"<html>clean</html>")

    async with _client(handler) as client:
        engine = VerificationEngine(client)
        outcome = await engine.verify(
            "xss",
            "https://app.example.com/search?q=%3Csentinel9f2a%3E",
            "high",
            {"parameter": "q"},
        )

    assert outcome.confidence == "high"  # already at cap, never becomes "confirmed"


@pytest.mark.asyncio
async def test_ssti_baseline_check():
    def handler(request):
        return httpx.Response(200, content=b"<html>Result: 49</html>")

    async with _client(handler) as client:
        engine = VerificationEngine(client)
        outcome = await engine.verify(
            "ssti", "https://app.example.com/render?name=%7B%7B7*7%7D%7D", "low", {"parameter": "name"}
        )

    assert outcome.verification_status == "false_positive"


@pytest.mark.asyncio
async def test_sqli_baseline_check():
    def handler(request):
        return httpx.Response(200, content=b"clean response, no errors")

    async with _client(handler) as client:
        engine = VerificationEngine(client)
        outcome = await engine.verify(
            "sqli", "https://app.example.com/product?id=%27", "low", {"parameter": "id"}
        )

    assert outcome.verification_status == "verified"
    assert outcome.confidence == "medium"


@pytest.mark.asyncio
async def test_path_traversal_baseline_check():
    def handler(request):
        return httpx.Response(200, content=b"file not found")

    async with _client(handler) as client:
        engine = VerificationEngine(client)
        outcome = await engine.verify(
            "path_traversal",
            "https://app.example.com/download?file=..%2F..%2Fetc%2Fpasswd",
            "low",
            {"parameter": "file"},
        )

    assert outcome.verification_status == "verified"


@pytest.mark.asyncio
async def test_ssrf_baseline_check():
    def handler(request):
        return httpx.Response(200, content=b"nothing interesting")

    async with _client(handler) as client:
        engine = VerificationEngine(client)
        outcome = await engine.verify(
            "ssrf",
            "https://app.example.com/fetch?url=http%3A%2F%2F169.254.169.254%2F",
            "low",
            {"parameter": "url"},
        )

    assert outcome.verification_status == "verified"


@pytest.mark.asyncio
async def test_xxe_baseline_uses_clean_url_directly():
    def handler(request):
        assert request.method == "GET"  # baseline always GETs, never resends XXE payload
        return httpx.Response(200, content=b"no traversal indicators here")

    async with _client(handler) as client:
        engine = VerificationEngine(client)
        outcome = await engine.verify(
            "xxe", "https://app.example.com/api/import", "low", {}
        )

    assert outcome.verification_status == "verified"


@pytest.mark.asyncio
async def test_missing_parameter_metadata_falls_back_to_endpoint_as_is():
    def handler(request):
        return httpx.Response(200, content=b"clean")

    async with _client(handler) as client:
        engine = VerificationEngine(client)
        # no "parameter" key in metadata at all
        outcome = await engine.verify("xss", "https://app.example.com/x", "low", {})

    assert outcome.verification_status == "verified"


@pytest.mark.asyncio
async def test_baseline_fetch_failure_falls_back_to_manual_review():
    scope = ScopeEngine(allow=["app.example.com"])
    rate_limiter = RateLimiter(requests_per_second=1000, concurrency=5, max_requests=1000)
    # target the wrong host so the scope check itself raises ScopeViolation
    async with SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter) as client:
        engine = VerificationEngine(client)
        outcome = await engine.verify(
            "xss", "https://evil.com/x?q=%3Csentinel9f2a%3E", "low", {"parameter": "q"}
        )

    assert outcome.verification_status == "needs_manual_review"
    assert outcome.confidence == "low"
