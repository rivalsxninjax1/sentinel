"""Subprocess execution helper shared by every tool adapter.

`ProcessRunner` is injectable so adapters are fully unit-testable without the real
external binary installed — the same "inject the thing that talks to the outside
world" pattern used for httpx transports (Phase 2/4), applied to subprocess
execution.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

ProcessRunner = Callable[[list[str], float], Awaitable[tuple[int, str, str]]]


class ToolTimeoutError(Exception):
    pass


async def default_process_runner(args: list[str], timeout_seconds: float) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout_seconds
        )
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise ToolTimeoutError(f"{' '.join(args)} exceeded {timeout_seconds}s timeout")

    return (
        proc.returncode if proc.returncode is not None else -1,
        stdout_bytes.decode(errors="replace"),
        stderr_bytes.decode(errors="replace"),
    )
