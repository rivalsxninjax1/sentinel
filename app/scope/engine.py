"""ScopeEngine — the single source of truth for "is this request allowed?"

Every outbound request path in SENTINEL (the internal HTTP client, and every future
tool adapter) MUST call `ScopeEngine.check()` before issuing a request. This is not
optional and not something adapters can work around — see docs/architecture.md §2/§11.

Design notes:
- `allow` entries may be exact hosts ("example.com"), wildcard subdomains
  ("*.example.com"), or full URL prefixes ("https://app.example.com/api").
- `deny` always wins over `allow`, even if a broad allow entry would otherwise match.
- An empty allow-list is refused at config-load time (see SentinelConfig), not here —
  but this engine also defensively refuses to permit anything if constructed with an
  empty allow-list, in case it's ever built outside of config loading.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str


class ScopeViolation(Exception):
    """Raised when code attempts to act on an out-of-scope target."""


def _host_matches(host: str, pattern: str) -> bool:
    host = host.lower()
    pattern = pattern.lower()
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) or host == pattern[2:]
    return fnmatch.fnmatch(host, pattern)


class ScopeEngine:
    def __init__(self, allow: list[str], deny: list[str] | None = None) -> None:
        self._allow = list(allow)
        self._deny = list(deny or [])

    @property
    def allow_rules(self) -> list[str]:
        return list(self._allow)

    @property
    def deny_rules(self) -> list[str]:
        return list(self._deny)

    def check(self, url: str) -> ScopeDecision:
        """Return a ScopeDecision for the given URL. Never raises for a normal
        out-of-scope check — callers that need hard-fail behavior should use
        `enforce()` instead."""
        if not self._allow:
            return ScopeDecision(False, "scope has no allow entries; refusing by default")

        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return ScopeDecision(False, f"not a valid absolute URL: {url!r}")

        host = parsed.hostname or ""

        for rule in self._deny:
            if self._rule_matches(rule, url, host):
                return ScopeDecision(False, f"matched deny rule: {rule!r}")

        for rule in self._allow:
            if self._rule_matches(rule, url, host):
                return ScopeDecision(True, f"matched allow rule: {rule!r}")

        return ScopeDecision(False, "no allow rule matched")

    def enforce(self, url: str) -> None:
        """Raise ScopeViolation if the URL is not in scope. Use this at every
        request-issuing call site."""
        decision = self.check(url)
        if not decision.allowed:
            raise ScopeViolation(f"Out of scope: {url!r} ({decision.reason})")

    @staticmethod
    def _rule_matches(rule: str, url: str, host: str) -> bool:
        if rule.startswith("http://") or rule.startswith("https://"):
            return url.startswith(rule)
        return _host_matches(host, rule)
