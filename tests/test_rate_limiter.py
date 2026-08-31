import asyncio
import time

import pytest

from app.core.rate_limiter import RateLimiter, RequestBudgetExceeded


@pytest.mark.asyncio
async def test_paces_requests_to_configured_rate():
    limiter = RateLimiter(requests_per_second=10, concurrency=5, max_requests=100)
    start = time.monotonic()
    for _ in range(3):
        async with limiter.throttle():
            pass
    elapsed = time.monotonic() - start
    # 3 requests at 10/s should take at least ~0.2s (2 gaps of 0.1s)
    assert elapsed >= 0.15


@pytest.mark.asyncio
async def test_enforces_max_requests_budget():
    limiter = RateLimiter(requests_per_second=1000, concurrency=5, max_requests=2)
    async with limiter.throttle():
        pass
    async with limiter.throttle():
        pass
    with pytest.raises(RequestBudgetExceeded):
        async with limiter.throttle():
            pass


@pytest.mark.asyncio
async def test_concurrency_cap_limits_parallel_slots():
    limiter = RateLimiter(requests_per_second=1000, concurrency=2, max_requests=100)
    in_flight = 0
    max_in_flight = 0
    lock = asyncio.Lock()

    async def worker():
        nonlocal in_flight, max_in_flight
        async with limiter.throttle():
            async with lock:
                in_flight += 1
                max_in_flight = max(max_in_flight, in_flight)
            await asyncio.sleep(0.05)
            async with lock:
                in_flight -= 1

    await asyncio.gather(*(worker() for _ in range(6)))
    assert max_in_flight <= 2


def test_rejects_invalid_construction_args():
    with pytest.raises(ValueError):
        RateLimiter(requests_per_second=0)
    with pytest.raises(ValueError):
        RateLimiter(concurrency=0)
    with pytest.raises(ValueError):
        RateLimiter(max_requests=0)
