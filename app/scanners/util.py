"""Small shared helper for building test request URLs. Kept separate from the
scanners themselves so the URL-building logic has one obviously-correct
implementation instead of six slightly-different copies."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# Shared across path_traversal.py and xxe.py (identical signature check), and
# reused by app/verification/engine.py for baseline differential comparison — one
# definition, not three copies that could silently drift apart.
TRAVERSAL_INDICATORS = ["root:x:0:0", "root:*:0:0"]


def inject_query_param(url: str, name: str, value: str) -> str:
    """Return `url` with query parameter `name` set to `value` (added if absent,
    overwritten if present). Other query parameters and the path are preserved."""
    parts = urlsplit(url)
    params = dict(parse_qsl(parts.query, keep_blank_values=True))
    params[name] = value
    new_query = urlencode(params)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


def strip_query_param(url: str, name: str) -> str:
    """Return `url` with query parameter `name` removed entirely — used to build a
    baseline ("what does this endpoint return with no payload at all") request from
    an already payload-bearing test URL. See app/verification/engine.py."""
    parts = urlsplit(url)
    params = dict(parse_qsl(parts.query, keep_blank_values=True))
    params.pop(name, None)
    new_query = urlencode(params)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))
