"""Async token-bucket rate limiter + request budget + concurrency cap.

Every outbound request (internal HTTP client now; every tool adapter later) must go
through `RateLimiter.throttle()` before it's allowed to fire. That single call site
enforces: requests-per-second pacing, max concurrency, and the global max_requests
budget for the scan.
"""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator


class RequestBudgetExceeded(Exception):
    """Raised when the scan's max_requests budget has been exhausted."""


class RateLimiter:
    def __init__(
        self,
        requests_per_second: float = 5.0,
        concurrency: int = 3,
        max_requests: int = 10_000,
    ) -> None:
        if requests_per_second <= 0:
            raise ValueError("requests_per_second must be > 0")
        if concurrency <= 0:
            raise ValueError("concurrency must be > 0")
        if max_requests <= 0:
            raise ValueError("max_requests must be > 0")

        self._interval = 1.0 / requests_per_second
        self._max_requests = max_requests
        self._semaphore = asyncio.Semaphore(concurrency)
        self._pace_lock = asyncio.Lock()
        self._last_request_at: float | None = None
        self._requests_made = 0

    @property
    def requests_made(self) -> int:
        return self._requests_made

    @property
    def budget_remaining(self) -> int:
        return max(0, self._max_requests - self._requests_made)

    @asynccontextmanager
    async def throttle(self) -> AsyncIterator[None]:
        """Usage:

            async with rate_limiter.throttle():
                response = await http_client.get(url)

        Raises RequestBudgetExceeded before making any request once the budget is
        exhausted.
        """
        async with self._pace_lock:
            if self._requests_made >= self._max_requests:
                raise RequestBudgetExceeded(
                    f"max_requests budget of {self._max_requests} exhausted"
                )
            now = time.monotonic()
            if self._last_request_at is not None:
                elapsed = now - self._last_request_at
                wait = self._interval - elapsed
                if wait > 0:
                    await asyncio.sleep(wait)
            self._last_request_at = time.monotonic()
            self._requests_made += 1

        async with self._semaphore:
            yield
