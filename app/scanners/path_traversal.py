"""Path traversal heuristic: injects a small set of traversal payloads and checks
the response for indicators of having read a system file (e.g. /etc/passwd
contents). Requires ACTIVE mode — this attempts to make the target application read
a file it shouldn't, which is more intrusive than a passive/safe check.
"""

from __future__ import annotations

import httpx

from app.core.http_client import SentinelHTTPClient
from app.scanners.base import DeterministicScanner, ScanTarget
from app.scanners.util import TRAVERSAL_INDICATORS as _TRAVERSAL_INDICATORS
from app.scanners.util import inject_query_param
from app.scope.engine import ScopeViolation
from app.tools.models import NormalizedFinding

_TRAVERSAL_PAYLOADS = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
]


class PathTraversalScanner(DeterministicScanner):
    name = "path_traversal"
    vulnerability_class = "path_traversal"
    required_mode = "active"

    async def scan(
        self, target: ScanTarget, http_client: SentinelHTTPClient
    ) -> list[NormalizedFinding]:
        if not target.parameter_name:
            return []

        for payload in _TRAVERSAL_PAYLOADS:
            test_url = inject_query_param(target.url, target.parameter_name, payload)
            try:
                response = await http_client.get(test_url)
            except (httpx.HTTPError, ScopeViolation):
                continue

            lowered = response.text.lower()
            if any(indicator in lowered for indicator in _TRAVERSAL_INDICATORS):
                return [
                    NormalizedFinding(
                        tool_name=self.name,
                        tool_version=None,
                        title=f"Possible path traversal via parameter '{target.parameter_name}'",
                        severity="high",
                        matched_endpoint=test_url,
                        raw_output="response body contains a traversal indicator string",
                        metadata={
                            "parameter": target.parameter_name,
                            "payload": payload,
                            "vulnerability_class": self.vulnerability_class,
                            "confidence": "low",
                        },
                    )
                ]

        return []
