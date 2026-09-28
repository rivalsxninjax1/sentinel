"""OOBClient — lets a scanner register a unique correlation ID, embed it in a
payload sent to the target, and later check whether the target actually made an
out-of-band request back to a SENTINEL-controlled listener using that ID.

Per docs/architecture.md §27 ("Safe OOB System"): unique correlation IDs, tracked
timestamp/correlation-ID/protocol/source/finding, and the system must be
EXPLICITLY enabled (never on by default — see `target.oob` in config, which
defaults to disabled).

WHY THIS MATTERS: every reflection-based SSRF/XXE check elsewhere in SENTINEL
(app/scanners/ssrf.py, app/scanners/xxe.py, app/verification/engine.py) can only
catch cases where the target's response somehow reflects evidence back. A target
that genuinely fetches an internal-only URL but shows the caller nothing (the
common, realistic case — "blind" SSRF/XXE) is invisible to every one of those
checks. This is the documented gap those modules explicitly call out. OOB closes
it: if the target's server actually reaches out to a URL SENTINEL controls, that
network interaction is the proof — no response content needed at all.

ARCHITECTURE, and its real limitations (see docs/oob.md for the full picture):
- `OOBClient` opens its own short-lived database connection per call
  (register_and_wait) rather than being threaded through the existing
  session-per-request pattern used elsewhere — scanners don't otherwise have
  database access, and giving every scanner a live session just for this one
  feature would be a bigger, riskier change than a scanner-local SQLite engine.
  SQLite handles multiple connections to the same file safely for this
  low-concurrency, single-machine use case.
- `register_and_wait()` blocks for `wait_seconds` (default a few seconds) to give
  the target time to make the callback. This makes OOB testing meaningfully
  slower per parameter than every other check in SENTINEL, which is exactly why
  it must be explicitly enabled, not automatic.
- This confirms HTTP-level interactions only. A target that only performs a raw
  DNS lookup (no actual HTTP fetch) for a blind SSRF probe will NOT be caught —
  that would require an authoritative DNS listener, which is a real, documented,
  future enhancement (see docs/oob.md), not something this phase builds.
- The listener (app/oob/listener.py) must be reachable from the TARGET, not from
  SENTINEL — for a local lab this usually means the same machine/network; for a
  real remote target it means the operator's listener needs a real public
  IP/hostname. SENTINEL cannot set this up for you.
"""

from __future__ import annotations

import asyncio
import secrets

from app.core.logging import get_logger
from app.storage.db import get_engine, init_db, make_session_factory, session_scope
from app.storage.repository import OOBRepository

logger = get_logger(__name__)

_CORRELATION_PREFIX = "sentinel"


class OOBClient:
    def __init__(self, callback_base_url: str, storage_path: str, wait_seconds: float = 4.0) -> None:
        self._callback_base_url = callback_base_url.rstrip("/")
        self._storage_path = storage_path
        self._wait_seconds = wait_seconds

    @staticmethod
    def generate_correlation_id() -> str:
        # secrets.token_hex, not uuid4 — this ID appears in URLs sent to a
        # third-party target, so it should be unguessable (a correlation ID an
        # attacker could predict would let them fabricate a false-positive OOB
        # hit), not just unique.
        return f"{_CORRELATION_PREFIX}{secrets.token_hex(10)}"

    def build_callback_url(self, correlation_id: str) -> str:
        return f"{self._callback_base_url}/oob/{correlation_id}"

    async def register_and_wait(
        self,
        correlation_id: str,
        scan_id: str,
        vulnerability_class: str,
        matched_endpoint: str,
        endpoint_id: str | None = None,
        parameter_name: str | None = None,
    ) -> bool:
        """Registers the correlation (so the listener process, even if it's
        already running and receives the callback before this function's wait
        completes, can be matched later), waits `wait_seconds`, then checks for
        any recorded interaction. Returns True if at least one interaction was
        found — this is treated as strong, direct evidence (not a heuristic
        signature match), see app/scanners/ssrf.py/xxe.py's OOB-confirmed finding
        severity."""
        engine = get_engine(self._storage_path)
        await init_db(engine)
        session_factory = make_session_factory(engine)

        try:
            async with session_scope(session_factory) as session:
                repo = OOBRepository(session)
                await repo.create_correlation(
                    correlation_id=correlation_id,
                    scan_id=scan_id,
                    vulnerability_class=vulnerability_class,
                    matched_endpoint=matched_endpoint,
                    endpoint_id=endpoint_id,
                    parameter_name=parameter_name,
                )

            await asyncio.sleep(self._wait_seconds)

            async with session_scope(session_factory) as session:
                repo = OOBRepository(session)
                interactions = await repo.list_interactions_for_correlation(correlation_id)

            if interactions:
                logger.info(
                    "oob_interaction_confirmed",
                    correlation_id=correlation_id,
                    count=len(interactions),
                )
            return len(interactions) > 0
        finally:
            await engine.dispose()
