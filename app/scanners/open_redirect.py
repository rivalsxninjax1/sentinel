"""Tests whether a parameter controls a redirect to an attacker-supplied external
host. Sends one request with the parameter set to a domain that could never
legitimately be a same-application redirect target, and checks whether the response's
Location header echoes it back.

Non-destructive, single request — classified as SAFE, not ACTIVE.
"""

from __future__ import annotations

import httpx

from app.core.http_client import SentinelHTTPClient
from app.scanners.base import DeterministicScanner, ScanTarget
from app.scanners.util import inject_query_param
from app.scope.engine import ScopeViolation
from app.tools.models import NormalizedFinding

_EXTERNAL_TEST_HOST = "sentinel-redirect-test.invalid"
_EXTERNAL_TEST_URL = f"https://{_EXTERNAL_TEST_HOST}/"


class OpenRedirectScanner(DeterministicScanner):
    name = "open_redirect"
    vulnerability_class = "open_redirect"
    required_mode = "safe"

    async def scan(
        self, target: ScanTarget, http_client: SentinelHTTPClient
    ) -> list[NormalizedFinding]:
        if not target.parameter_name:
            return []

        test_url = inject_query_param(target.url, target.parameter_name, _EXTERNAL_TEST_URL)
        try:
            response = await http_client.get(test_url)
        except (httpx.HTTPError, ScopeViolation):
            return []

        location = response.headers.get("location", "")
        if _EXTERNAL_TEST_HOST not in location:
            return []

        return [
            NormalizedFinding(
                tool_name=self.name,
                tool_version=None,
                title=f"Possible open redirect via parameter '{target.parameter_name}'",
                severity="medium",
                matched_endpoint=test_url,
                raw_output=f"status={response.status_code}, Location: {location}",
                metadata={
                    "parameter": target.parameter_name,
                    "vulnerability_class": self.vulnerability_class,
                    "confidence": "low",
                },
            )
        ]
