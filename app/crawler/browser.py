"""BrowserEngine — Playwright-based dynamic discovery.

Used only when HTTP-based analysis (HTML crawling, JS regex extraction) is
insufficient — e.g. SPA routes that only appear after client-side JS builds the DOM,
or API calls issued by frontend code a static regex pass can't fully resolve. Per
docs/architecture.md §28 ("HTTP first, browser when necessary"), this is an explicit,
separate discovery step, not run for every page.

Playwright is an optional runtime dependency. If the package isn't installed, or its
browser binaries haven't been downloaded, `is_available()` returns False and callers
should skip browser-based discovery rather than crash the scan — see
docs/architecture.md §49 for the same "detect and degrade, don't silently fail"
principle applied to external tool binaries.

IMPORTANT LIMITATION: Playwright issues its own network requests at the browser/OS
level — they do NOT go through SentinelHTTPClient, so SENTINEL's RateLimiter does not
pace them. Every request the page fires is still classified against ScopeEngine before
being reported (out-of-scope requests are counted but never returned by URL), but the
browser can and will make requests to whatever the page's JS tells it to before
SENTINEL can intervene. Keep `discover()` calls few and deliberate; this is not a
substitute for the scope-and-rate-limited HTTP crawl.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.core.logging import get_logger
from app.scope.engine import ScopeEngine

logger = get_logger(__name__)

try:
    from playwright.async_api import async_playwright

    _PLAYWRIGHT_IMPORT_ERROR: Exception | None = None
except Exception as exc:  # pragma: no cover - exercised only when playwright is absent
    async_playwright = None  # type: ignore[assignment]
    _PLAYWRIGHT_IMPORT_ERROR = exc


@dataclass
class BrowserDiscovery:
    url: str
    requests_observed: list[str] = field(default_factory=list)
    requests_in_scope: list[str] = field(default_factory=list)
    requests_out_of_scope_count: int = 0


class BrowserUnavailable(Exception):
    """Raised by discover() when Playwright (or its browser binaries) aren't
    available. Callers should catch this and skip browser-based discovery rather
    than fail the whole scan."""


class BrowserEngine:
    @staticmethod
    def is_available() -> bool:
        return async_playwright is not None

    async def discover(
        self, url: str, scope: ScopeEngine, timeout_ms: int = 15_000
    ) -> BrowserDiscovery:
        """Navigate to `url` in headless Chromium and record every network request the
        page issues while it loads and runs its JS."""
        if not self.is_available():
            raise BrowserUnavailable(
                f"Playwright is not available: {_PLAYWRIGHT_IMPORT_ERROR}. "
                "Install with `pip install playwright` and `playwright install chromium`."
            )

        discovery = BrowserDiscovery(url=url)

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            try:
                page = await browser.new_page()

                def _on_request(request: object) -> None:
                    request_url = getattr(request, "url", None)
                    if not request_url:
                        return
                    discovery.requests_observed.append(request_url)
                    if scope.check(request_url).allowed:
                        discovery.requests_in_scope.append(request_url)
                    else:
                        discovery.requests_out_of_scope_count += 1

                page.on("request", _on_request)
                await page.goto(url, timeout=timeout_ms, wait_until="networkidle")
            except Exception as exc:
                logger.warning("browser_navigation_failed", url=url, error=str(exc))
                raise
            finally:
                await browser.close()

        return discovery
