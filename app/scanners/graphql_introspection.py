"""GraphQL introspection check: sends a minimal standard introspection query and
checks whether the server answers it. Introspection is a legitimate development
feature but is commonly recommended to be disabled in production (it hands an
attacker a full schema map of every type, field, and mutation).

Only activates on endpoints whose path/URL contains "graphql" (case-insensitive) —
this is a real limitation: SENTINEL only knows an endpoint is a GraphQL endpoint if
"graphql" literally appears in its discovered path (which Phase 3's JS extractor
does look for specifically — see app/intelligence/javascript.py's graphql
classification). A GraphQL endpoint mounted at a non-obvious path won't be tested.

Single POST request, read-only — SAFE mode.
"""

from __future__ import annotations

import httpx

from app.core.http_client import SentinelHTTPClient
from app.scanners.base import DeterministicScanner, ScanTarget
from app.scope.engine import ScopeViolation
from app.tools.models import NormalizedFinding

_INTROSPECTION_QUERY = {"query": "query IntrospectionCheck { __schema { queryType { name } } }"}


class GraphQLIntrospectionScanner(DeterministicScanner):
    name = "graphql_introspection"
    vulnerability_class = "graphql_introspection"
    required_mode = "safe"

    async def scan(
        self, target: ScanTarget, http_client: SentinelHTTPClient
    ) -> list[NormalizedFinding]:
        if "graphql" not in target.url.lower():
            return []

        try:
            response = await http_client.post(target.url, json=_INTROSPECTION_QUERY)
        except (httpx.HTTPError, ScopeViolation):
            return []

        try:
            data = response.json()
        except Exception:
            return []

        schema = data.get("data", {}).get("__schema") if isinstance(data, dict) else None
        if not schema:
            return []

        return [
            NormalizedFinding(
                tool_name=self.name,
                tool_version=None,
                title="GraphQL introspection is enabled",
                severity="medium",
                matched_endpoint=target.url,
                raw_output=f"introspection query returned: {schema}",
                metadata={
                    "vulnerability_class": self.vulnerability_class,
                    "confidence": "high",
                    "note": "introspection exposes the full schema; commonly recommended "
                    "to be disabled in production, though this varies by application",
                },
            )
        ]
