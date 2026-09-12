"""Deterministic extraction of API routes, GraphQL/WebSocket endpoints, and source-map
references from JavaScript source text.

Regex-based, not a JS parser — false negatives are expected for heavily obfuscated or
dynamically-constructed URLs (e.g. `"/api/" + id`). This complements, not replaces,
browser-based discovery (app/crawler/browser.py) for cases where the target URL isn't
visible as a literal string in a static pass. Per docs/architecture.md §11:
"HTML != complete attack surface" — this module exists because a SPA can expose most
of its API only through JavaScript.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_FETCH_CALL = re.compile(r'fetch\(\s*[`"\']([^`"\']+)[`"\']')
_AXIOS_CALL = re.compile(r'axios\.(?:get|post|put|delete|patch)\(\s*[`"\']([^`"\']+)[`"\']', re.IGNORECASE)
_XHR_OPEN = re.compile(
    r'\.open\(\s*[`"\'](?:GET|POST|PUT|DELETE|PATCH)[`"\']\s*,\s*[`"\']([^`"\']+)[`"\']', re.IGNORECASE
)
_GENERIC_API_LITERAL = re.compile(r'[`"\'](/(?:api|graphql|v[0-9]+)[^\s`"\']*)[`"\']', re.IGNORECASE)
_WEBSOCKET_LITERAL = re.compile(r'(wss?://[^\s`"\']+)')
_SOURCE_MAP_COMMENT = re.compile(r'//[#@]\s*sourceMappingURL=([^\s]+)')


@dataclass
class JSExtractionResult:
    routes: list[str] = field(default_factory=list)
    graphql_endpoints: list[str] = field(default_factory=list)
    websocket_endpoints: list[str] = field(default_factory=list)
    source_map_url: str | None = None


def extract_from_js(text: str) -> JSExtractionResult:
    routes: set[str] = set()
    graphql: set[str] = set()
    websockets: set[str] = set()

    for pattern in (_FETCH_CALL, _AXIOS_CALL, _XHR_OPEN, _GENERIC_API_LITERAL):
        for match in pattern.finditer(text):
            value = match.group(1)
            if value.startswith(("http://", "https://", "//")):
                # Absolute/protocol-relative URLs to *other* hosts aren't routes of
                # this application. (Same-host absolute URLs would need base-URL
                # context to detect reliably here; left to browser-based discovery.)
                continue
            if not value.startswith("/"):
                continue
            if "graphql" in value.lower():
                graphql.add(value)
            else:
                routes.add(value)

    for match in _WEBSOCKET_LITERAL.finditer(text):
        websockets.add(match.group(1))

    source_map_match = _SOURCE_MAP_COMMENT.search(text)
    source_map_url = source_map_match.group(1) if source_map_match else None

    return JSExtractionResult(
        routes=sorted(routes),
        graphql_endpoints=sorted(graphql),
        websocket_endpoints=sorted(websockets),
        source_map_url=source_map_url,
    )
