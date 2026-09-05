"""Server-Side Template Injection heuristic: injects arithmetic expressions in the
syntax of common template engines and checks whether the response contains the
*evaluated* result rather than the literal payload — the classic SSTI probe
technique (e.g. `{{7*7}}` -> `49` proves the template engine executed the
expression, not just reflected it).

Requires ACTIVE mode: successful exploitation of SSTI often leads to remote code
execution, so even probing for it is treated as intrusive.
"""

from __future__ import annotations

import httpx

from app.core.http_client import SentinelHTTPClient
from app.scanners.base import DeterministicScanner, ScanTarget
from app.scanners.util import inject_query_param
from app.scope.engine import ScopeViolation
from app.tools.models import NormalizedFinding

_EXPECTED_RESULT = "49"

# (payload, template engine family it targets)
_SSTI_PROBES: list[tuple[str, str]] = [
    ("{{7*7}}", "Jinja2/Twig/Nunjucks"),
    ("${7*7}", "FreeMarker/Velocity/JSP EL"),
    ("<%= 7*7 %>", "ERB/JSP scriptlet"),
    ("#{7*7}", "Ruby/JSF EL"),
    ("*{7*7}", "Thymeleaf"),
]


class SSTIScanner(DeterministicScanner):
    name = "ssti"
    vulnerability_class = "ssti"
    required_mode = "active"

    async def scan(
        self, target: ScanTarget, http_client: SentinelHTTPClient
    ) -> list[NormalizedFinding]:
        if not target.parameter_name:
            return []

        for payload, engine_family in _SSTI_PROBES:
            test_url = inject_query_param(target.url, target.parameter_name, payload)
            try:
                response = await http_client.get(test_url)
            except (httpx.HTTPError, ScopeViolation):
                continue

            # The literal payload must NOT be present (that would just be reflection,
            # not evaluation) and the computed result MUST be present.
            if payload in response.text:
                continue
            if _EXPECTED_RESULT in response.text:
                return [
                    NormalizedFinding(
                        tool_name=self.name,
                        tool_version=None,
                        title=(
                            f"Possible SSTI via parameter '{target.parameter_name}' "
                            f"(expression evaluated, likely {engine_family})"
                        ),
                        severity="high",
                        matched_endpoint=test_url,
                        raw_output=f"payload {payload!r} evaluated to {_EXPECTED_RESULT!r} in response",
                        metadata={
                            "parameter": target.parameter_name,
                            "vulnerability_class": self.vulnerability_class,
                            "confidence": "low",
                            "likely_engine_family": engine_family,
                        },
                    )
                ]

        return []
