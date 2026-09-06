"""WebSocket authentication check: attempts to complete the WS opening handshake
with no credentials attached (no cookies, no auth headers) and checks whether the
server accepts the connection. Sends no frames after connecting and immediately
closes — this only tests handshake-level access control, not message-level
authorization within an established connection.

Only activates on endpoint URLs starting with `ws://` or `wss://` (the shape Phase
3's JS extractor stores WebSocket endpoints as — see
app/intelligence/javascript.py). `websockets` is an optional dependency (same
graceful-degradation pattern as Playwright in app/crawler/browser.py): if it isn't
installed, this scanner logs and returns no findings rather than raising.

SAFE mode: completing a WS handshake and immediately closing without sending any
frames is comparable in risk to a plain HTTP GET.
"""

from __future__ import annotations

from app.core.http_client import SentinelHTTPClient
from app.core.logging import get_logger
from app.scanners.base import DeterministicScanner, ScanTarget
from app.tools.models import NormalizedFinding

logger = get_logger(__name__)

try:
    import websockets

    _WEBSOCKETS_IMPORT_ERROR: Exception | None = None
except Exception as exc:  # pragma: no cover - exercised only when websockets is absent
    websockets = None  # type: ignore[assignment]
    _WEBSOCKETS_IMPORT_ERROR = exc


class WebSocketAuthScanner(DeterministicScanner):
    name = "websocket_auth"
    vulnerability_class = "websocket_authorization"
    required_mode = "safe"

    async def scan(
        self, target: ScanTarget, http_client: SentinelHTTPClient
    ) -> list[NormalizedFinding]:
        if not target.url.startswith(("ws://", "wss://")):
            return []

        if websockets is None:
            logger.info("websockets_unavailable", error=str(_WEBSOCKETS_IMPORT_ERROR))
            return []

        try:
            async with websockets.connect(target.url, open_timeout=10.0) as connection:
                await connection.close()
        except Exception:
            return []  # handshake rejected or errored — no finding, this is the expected/safe case

        return [
            NormalizedFinding(
                tool_name=self.name,
                tool_version=None,
                title="WebSocket endpoint accepts unauthenticated connections",
                severity="info",
                matched_endpoint=target.url,
                raw_output="WS handshake succeeded with no auth headers/cookies attached",
                metadata={
                    "vulnerability_class": self.vulnerability_class,
                    "confidence": "low",
                    "note": "many WebSocket endpoints are legitimately public "
                    "(e.g. public price feeds); this only flags the absence of a "
                    "handshake-level auth requirement, not that one is necessarily needed",
                },
            )
        ]
