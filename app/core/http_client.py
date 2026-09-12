"""SentinelHTTPClient — the only supported way SENTINEL's own code issues HTTP
requests. Wraps httpx.AsyncClient and forces every request through the ScopeEngine
and RateLimiter first. Tool adapters (Phase 5) that shell out to external binaries
enforce scope separately at their own layer, but anything using this client gets it
for free.
"""

from __future__ import annotations

from types import TracebackType
from typing import Any

import httpx

from app.core.logging import get_logger
from app.core.rate_limiter import RateLimiter
from app.scope.engine import ScopeEngine, ScopeViolation

logger = get_logger(__name__)


class SentinelHTTPClient:
    def __init__(
        self,
        scope: ScopeEngine,
        rate_limiter: RateLimiter,
        timeout: float = 15.0,
        follow_redirects: bool = False,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        """`transport` is exposed only so tests can inject an `httpx.MockTransport`
        instead of hitting the network. Scope and rate-limit enforcement in
        `_request()` apply regardless of transport — a mock transport does not bypass
        them."""
        self._scope = scope
        self._rate_limiter = rate_limiter
        self._client = httpx.AsyncClient(
            timeout=timeout, follow_redirects=follow_redirects, transport=transport
        )

    async def __aenter__(self) -> SentinelHTTPClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request("POST", url, **kwargs)

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request(method, url, **kwargs)

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        # Enforced here, at the lowest layer of SENTINEL's own HTTP path — not just
        # by callers remembering to check first. See docs/architecture.md §2/§11.
        try:
            self._scope.enforce(url)
        except ScopeViolation:
            logger.warning("scope_violation_blocked", method=method, url=url)
            raise

        async with self._rate_limiter.throttle():
            logger.debug("http_request", method=method, url=url)
            response = await self._client.request(method, url, **kwargs)
            logger.debug("http_response", method=method, url=url, status=response.status_code)
            return response
