"""XML External Entity injection heuristic.

Sends a minimal XXE payload (external entity resolving to a local file read) as the
raw request body with Content-Type: application/xml, and checks for a traversal-style
indicator in the response (same signature approach as path_traversal.py). Only a
meaningful test against endpoints that might actually parse XML — SENTINEL doesn't
currently track per-endpoint accepted content-types, so this runs against any POST/PUT
endpoint that has a form (a reasonable, if imperfect, proxy for "accepts a request
body"). Many targets will legitimately reject this payload outright (400/415), which
produces no finding — that's expected and correct behavior, not a scanner bug.

Requires ACTIVE mode: attempting to read local files via XXE is intrusive.
"""

from __future__ import annotations

import httpx

from app.core.http_client import SentinelHTTPClient
from app.scanners.base import DeterministicScanner, ScanTarget
from app.scanners.util import TRAVERSAL_INDICATORS as _TRAVERSAL_INDICATORS
from app.scope.engine import ScopeViolation
from app.tools.models import NormalizedFinding

_XXE_PAYLOAD = (
    '<?xml version="1.0"?>\n'
    "<!DOCTYPE data [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n"
    "<data>&xxe;</data>"
)


class XXEScanner(DeterministicScanner):
    name = "xxe"
    vulnerability_class = "xxe"
    required_mode = "active"

    async def scan(
        self, target: ScanTarget, http_client: SentinelHTTPClient
    ) -> list[NormalizedFinding]:
        if target.method.upper() not in ("POST", "PUT"):
            return []
        if target.form_fields is None:
            return []  # only run against endpoints we know accept a form body at all

        try:
            response = await http_client.request(
                target.method,
                target.url,
                content=_XXE_PAYLOAD.encode(),
                headers={"Content-Type": "application/xml"},
            )
        except (httpx.HTTPError, ScopeViolation):
            return []

        lowered = response.text.lower()
        if not any(indicator in lowered for indicator in _TRAVERSAL_INDICATORS):
            return []

        return [
            NormalizedFinding(
                tool_name=self.name,
                tool_version=None,
                title="Possible XXE: external entity resolved local file content",
                severity="critical",
                matched_endpoint=target.url,
                raw_output="response body contains a traversal indicator string after XXE payload",
                metadata={
                    "vulnerability_class": self.vulnerability_class,
                    "confidence": "low",
                },
            )
        ]
