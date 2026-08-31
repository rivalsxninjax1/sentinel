import pytest

import app.crawler.browser as browser_module
from app.crawler.browser import BrowserEngine, BrowserUnavailable
from app.scope.engine import ScopeEngine


def test_is_available_reflects_playwright_import():
    # In this environment the playwright *package* is installed, so import succeeds.
    # (Whether browser binaries are downloaded is a separate, runtime-only concern —
    # see docs/setup.md.)
    assert BrowserEngine.is_available() == (browser_module.async_playwright is not None)


@pytest.mark.asyncio
async def test_discover_raises_when_playwright_unavailable(monkeypatch):
    monkeypatch.setattr(browser_module, "async_playwright", None)
    engine = BrowserEngine()
    scope = ScopeEngine(allow=["app.example.com"])
    with pytest.raises(BrowserUnavailable):
        await engine.discover("https://app.example.com/", scope)
