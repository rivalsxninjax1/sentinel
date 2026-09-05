"""IDOR/BOLA candidate detection — NOT full IDOR testing.

Real IDOR/BOLA verification requires comparing access across multiple authenticated
identities (docs/architecture.md §25: anonymous / USER_A / USER_B / ADMIN) — sending
USER_B's session against an object USER_A owns and checking whether access is
wrongly allowed. SENTINEL does not yet have an AuthenticationContext system managing
multiple identities (see docs/architecture.md §26, not built in any phase so far),
so that comparison is impossible right now.

What this scanner DOES do, honestly: flag parameters whose name looks like an
object identifier (id, user_id, order_id, uuid, etc.) as candidates that deserve
manual or (once built) automated cross-identity IDOR testing. This is explicitly an
INFORMATIONAL finding, never higher — it is a todo-list entry, not a vulnerability
claim. See docs/architecture.md §13's required distinction between "automatically
detectable" and "requires authenticated context."

Passive with respect to the network — it only looks at already-known parameter
name, no additional request. Runs at SAFE mode (matches other lightweight checks;
nothing here is more intrusive than a decision based on already-known data).
"""

from __future__ import annotations

import re

from app.core.http_client import SentinelHTTPClient
from app.scanners.base import DeterministicScanner, ScanTarget
from app.tools.models import NormalizedFinding

_ID_PARAM_NAME_HINTS = (
    "id",
    "user_id",
    "account_id",
    "order_id",
    "invoice_id",
    "document_id",
    "file_id",
    "uuid",
)

_UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
_NUMERIC_ID_PATTERN = re.compile(r"^\d+$")


class IDORCandidateScanner(DeterministicScanner):
    name = "idor_candidate"
    vulnerability_class = "idor_bola"
    required_mode = "safe"

    async def scan(
        self, target: ScanTarget, http_client: SentinelHTTPClient
    ) -> list[NormalizedFinding]:
        if not target.parameter_name:
            return []

        name_lower = target.parameter_name.lower()
        if not any(hint in name_lower for hint in _ID_PARAM_NAME_HINTS):
            return []

        return [
            NormalizedFinding(
                tool_name=self.name,
                tool_version=None,
                title=(
                    f"Object-identifier-shaped parameter '{target.parameter_name}' — "
                    f"IDOR/BOLA candidate (requires multi-identity testing, not yet automated)"
                ),
                severity="info",
                matched_endpoint=target.url,
                raw_output=(
                    f"parameter name '{target.parameter_name}' matches object-identifier "
                    f"naming pattern"
                ),
                metadata={
                    "parameter": target.parameter_name,
                    "vulnerability_class": self.vulnerability_class,
                    "confidence": "info",
                    "requires": "multi-identity AuthenticationContext testing (not yet built)",
                },
            )
        ]

    @staticmethod
    def value_looks_like_identifier(value: str) -> bool:
        """Exposed for callers that do have an observed parameter value available
        (e.g. a future orchestrator revision) — not currently wired into the CLI's
        parameter-level pass, which only has the parameter name."""
        return bool(_UUID_PATTERN.match(value) or _NUMERIC_ID_PATTERN.match(value))
