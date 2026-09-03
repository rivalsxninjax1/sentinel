"""Reflection-based XSS heuristic: injects a unique, HTML-syntax marker into a
parameter and checks whether it comes back unescaped in the response body.

This is deliberately simple compared to XSStrike's context-aware analysis
(app/tools/xsstrike.py) — it detects *raw reflection*, not sanitization bypass,
encoding-context awareness, or DOM sinks (see docs/architecture.md §14 for the full
XSS coverage ambition; this scanner is the "cheap first pass" that doesn't need an
external tool, not a replacement for XSStrike).

Non-destructive, single request per parameter — classified as SAFE.
"""

from __future__ import annotations

import httpx

from app.core.http_client import SentinelHTTPClient
from app.scanners.base import DeterministicScanner, ScanTarget
from app.scanners.util import inject_query_param
from app.scope.engine import ScopeViolation
from app.tools.models import NormalizedFinding

_MARKER = "sentinel9f2a"
_PAYLOAD = f"<{_MARKER}>"


class ReflectedXSSScanner(DeterministicScanner):
    name = "reflected_xss"
    vulnerability_class = "xss"
    required_mode = "safe"

    async def scan(
        self, target: ScanTarget, http_client: SentinelHTTPClient
    ) -> list[NormalizedFinding]:
        if not target.parameter_name:
            return []

        test_url = inject_query_param(target.url, target.parameter_name, _PAYLOAD)
        try:
            response = await http_client.get(test_url)
        except (httpx.HTTPError, ScopeViolation):
            return []

        if _PAYLOAD not in response.text:
            return []

        return [
            NormalizedFinding(
                tool_name=self.name,
                tool_version=None,
                title=(
                    f"Unescaped reflection of injected marker via parameter "
                    f"'{target.parameter_name}' (possible XSS)"
                ),
                severity="medium",
                matched_endpoint=test_url,
                raw_output="injected marker reflected unescaped in response body",
                metadata={
                    "parameter": target.parameter_name,
                    "vulnerability_class": self.vulnerability_class,
                    "confidence": "low",
                    "parse_method": "raw_reflection_heuristic",
                },
            )
        ]
