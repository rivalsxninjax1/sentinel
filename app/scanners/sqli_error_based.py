"""Error-based SQL injection heuristic: injects a single quote and checks the
response for known database error-message signatures. Deliberately minimal — this
is the "cheap first pass" that doesn't need sqlmap; for real coverage (boolean-blind,
time-blind, UNION-based, etc.) see the sqlmap adapter (app/tools/sqlmap.py).

Requires ACTIVE mode: this is a genuine injection attempt against the target's data
layer, not a passive check.
"""

from __future__ import annotations

import httpx

from app.core.http_client import SentinelHTTPClient
from app.scanners.base import DeterministicScanner, ScanTarget
from app.scanners.util import inject_query_param
from app.scope.engine import ScopeViolation
from app.tools.models import NormalizedFinding

_SQLI_PAYLOAD = "'"

_SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlite3.operationalerror",
    "pg_query():",
    "ora-01756",
    "microsoft ole db provider for odbc drivers",
    "sqlstate[",
]


class SqliErrorBasedScanner(DeterministicScanner):
    name = "sqli_error_based"
    vulnerability_class = "sqli"
    required_mode = "active"

    async def scan(
        self, target: ScanTarget, http_client: SentinelHTTPClient
    ) -> list[NormalizedFinding]:
        if not target.parameter_name:
            return []

        test_url = inject_query_param(target.url, target.parameter_name, _SQLI_PAYLOAD)
        try:
            response = await http_client.get(test_url)
        except (httpx.HTTPError, ScopeViolation):
            return []

        lowered = response.text.lower()
        for signature in _SQL_ERROR_SIGNATURES:
            if signature in lowered:
                return [
                    NormalizedFinding(
                        tool_name=self.name,
                        tool_version=None,
                        title=(
                            f"Possible SQL injection via parameter "
                            f"'{target.parameter_name}' (error-based)"
                        ),
                        severity="high",
                        matched_endpoint=test_url,
                        raw_output=f"matched SQL error signature: {signature!r}",
                        metadata={
                            "parameter": target.parameter_name,
                            "vulnerability_class": self.vulnerability_class,
                            "confidence": "low",
                        },
                    )
                ]

        return []
