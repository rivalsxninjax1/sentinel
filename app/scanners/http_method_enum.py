"""HTTP method enumeration via OPTIONS: sends an OPTIONS request (non-mutating per
HTTP semantics) and inspects the Allow header for methods that could indicate
missing method-based access control (PUT, DELETE, PATCH, TRACE).

Deliberately does NOT actually send PUT/DELETE/PATCH requests to check whether
they're accepted — doing so risks real data modification or deletion on the target,
which violates the non-negotiable "never perform destructive testing automatically"
rule. This scanner only reports what the server *claims* is allowed via the Allow
header; confirming whether those methods are actually reachable and dangerous is
explicitly left to manual verification.

SAFE mode: OPTIONS is defined by HTTP semantics as non-mutating.
"""

from __future__ import annotations

import httpx

from app.core.http_client import SentinelHTTPClient
from app.scanners.base import DeterministicScanner, ScanTarget
from app.scope.engine import ScopeViolation
from app.tools.models import NormalizedFinding

_NOTABLE_METHODS = {"PUT", "DELETE", "PATCH", "TRACE", "CONNECT"}


class HTTPMethodEnumScanner(DeterministicScanner):
    name = "http_method_enum"
    vulnerability_class = "http_method_enumeration"
    required_mode = "safe"

    async def scan(
        self, target: ScanTarget, http_client: SentinelHTTPClient
    ) -> list[NormalizedFinding]:
        try:
            response = await http_client.request("OPTIONS", target.url)
        except (httpx.HTTPError, ScopeViolation):
            return []

        allow_header = response.headers.get("allow", "")
        if not allow_header:
            return []

        declared_methods = {m.strip().upper() for m in allow_header.split(",") if m.strip()}
        notable = declared_methods & _NOTABLE_METHODS
        if not notable:
            return []

        return [
            NormalizedFinding(
                tool_name=self.name,
                tool_version=None,
                title=f"Endpoint declares potentially sensitive HTTP methods: {', '.join(sorted(notable))}",
                severity="low",
                matched_endpoint=target.url,
                raw_output=f"Allow: {allow_header}",
                metadata={
                    "vulnerability_class": self.vulnerability_class,
                    "confidence": "high",  # the Allow header content is a fact
                    "declared_methods": sorted(declared_methods),
                    "note": "reports what the Allow header claims only — does not attempt "
                    "PUT/DELETE/PATCH requests, which could modify or delete real data",
                },
            )
        ]
