"""URL normalization.

Two different-looking URLs are often the same endpoint for crawling/dedup purposes:
    https://App.Example.com:443/path/?b=2&a=1#frag
    https://app.example.com/path?a=1&b=2

`normalize()` produces a canonical string so the crawler doesn't re-visit the same
logical endpoint under superficially different URLs, and so stored Endpoint records
are keyed consistently.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

_DEFAULT_PORTS = {"http": 80, "https": 443}


def normalize(url: str) -> str:
    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    port = parsed.port
    if port is not None and _DEFAULT_PORTS.get(scheme) == port:
        port = None
    netloc = hostname if port is None else f"{hostname}:{port}"

    path = parsed.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
        if path == "":
            path = "/"

    query_pairs = sorted(parse_qsl(parsed.query, keep_blank_values=True))
    query = urlencode(query_pairs)

    # Fragments are client-side only and never sent to the server — irrelevant for
    # attack-surface purposes, always dropped.
    return urlunparse((scheme, netloc, path, "", query, ""))


def endpoint_key(url: str) -> tuple[str, str]:
    """Returns (hostname, path) — used for grouping normalized URLs under a Host."""
    parsed = urlparse(normalize(url))
    return parsed.hostname or "", parsed.path or "/"
