import httpx
import pytest

from app.core.http_client import SentinelHTTPClient
from app.core.rate_limiter import RateLimiter
from app.crawler.crawler import Crawler
from app.scope.engine import ScopeEngine

_PAGES = {
    "https://app.example.com/": """
        <html><body>
            <a href="/about">About</a>
            <a href="/login">Login</a>
            <a href="https://evil.com/x">Out of scope</a>
        </body></html>
    """,
    "https://app.example.com/about": """
        <html><body><a href="/">Home</a></body></html>
    """,
    "https://app.example.com/login": """
        <html><body>
            <form method="post" action="/login">
                <input name="username">
                <input name="password" type="password">
            </form>
        </body></html>
    """,
}


def _handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if url in _PAGES:
        return httpx.Response(
            200,
            headers={"Content-Type": "text/html", "Server": "nginx/1.20.0"},
            content=_PAGES[url].encode(),
        )
    return httpx.Response(404, headers={"Content-Type": "text/html"}, content=b"<html>not found</html>")


@pytest.mark.asyncio
async def test_crawls_within_scope_and_follows_links():
    scope = ScopeEngine(allow=["app.example.com"])
    rate_limiter = RateLimiter(requests_per_second=1000, concurrency=5, max_requests=1000)
    transport = httpx.MockTransport(_handler)

    async with SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter, transport=transport) as client:
        crawler = Crawler(http_client=client, max_depth=3)
        summary = await crawler.crawl(["https://app.example.com/"])

    visited_urls = {p.url for p in summary.pages}
    assert "https://app.example.com/" in visited_urls
    assert "https://app.example.com/about" in visited_urls
    assert "https://app.example.com/login" in visited_urls
    assert summary.skipped_out_of_scope == 1  # https://evil.com/x


@pytest.mark.asyncio
async def test_extracts_forms_during_crawl():
    scope = ScopeEngine(allow=["app.example.com"])
    rate_limiter = RateLimiter(requests_per_second=1000, concurrency=5, max_requests=1000)
    transport = httpx.MockTransport(_handler)

    async with SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter, transport=transport) as client:
        crawler = Crawler(http_client=client, max_depth=3)
        summary = await crawler.crawl(["https://app.example.com/"])

    login_page = next(p for p in summary.pages if p.url == "https://app.example.com/login")
    assert len(login_page.forms) == 1
    assert {p.name for p in login_page.forms[0].parameters} == {"username", "password"}


@pytest.mark.asyncio
async def test_detects_technology_during_crawl():
    scope = ScopeEngine(allow=["app.example.com"])
    rate_limiter = RateLimiter(requests_per_second=1000, concurrency=5, max_requests=1000)
    transport = httpx.MockTransport(_handler)

    async with SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter, transport=transport) as client:
        crawler = Crawler(http_client=client, max_depth=3)
        summary = await crawler.crawl(["https://app.example.com/"])

    detections = summary.technologies_by_host["app.example.com"]
    assert any(d.name == "Nginx" for d in detections)


@pytest.mark.asyncio
async def test_respects_max_depth():
    scope = ScopeEngine(allow=["app.example.com"])
    rate_limiter = RateLimiter(requests_per_second=1000, concurrency=5, max_requests=1000)
    transport = httpx.MockTransport(_handler)

    async with SentinelHTTPClient(scope=scope, rate_limiter=rate_limiter, transport=transport) as client:
        crawler = Crawler(http_client=client, max_depth=0)
        summary = await crawler.crawl(["https://app.example.com/"])

    # depth 0 means only the seed page itself is fetched, no links followed
    assert summary.visited_count == 1
