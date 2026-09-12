"""Deterministic technology fingerprinting from HTTP responses.

This is a small, explicit signature set — not a reimplementation of Wappalyzer/
retire.js. It's intentionally conservative: each signature only fires on a fairly
specific header/cookie/body marker, and every detection carries a confidence level
so downstream consumers (correlation, reporting) don't treat a guess as a fact.

Classification here is informational, not a vulnerability judgment — see
docs/architecture.md §12 ("classification must NOT equal vulnerability").
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import httpx


@dataclass(frozen=True)
class TechnologyDetection:
    name: str
    version: str | None
    confidence: str  # "low" | "medium" | "high"
    source: str  # e.g. "header:Server", "cookie:laravel_session", "body:meta-generator"


@dataclass(frozen=True)
class _HeaderSignature:
    name: str
    header: str
    pattern: re.Pattern[str]
    confidence: str
    version_group: int | None = None


@dataclass(frozen=True)
class _CookieSignature:
    name: str
    cookie_name: str
    confidence: str


@dataclass(frozen=True)
class _BodySignature:
    name: str
    pattern: re.Pattern[str]
    confidence: str
    version_group: int | None = None


_HEADER_SIGNATURES: list[_HeaderSignature] = [
    _HeaderSignature("Nginx", "server", re.compile(r"nginx(?:/([\d.]+))?", re.IGNORECASE), "high", 1),
    _HeaderSignature("Apache", "server", re.compile(r"apache(?:/([\d.]+))?", re.IGNORECASE), "high", 1),
    _HeaderSignature("Microsoft-IIS", "server", re.compile(r"microsoft-iis(?:/([\d.]+))?", re.IGNORECASE), "high", 1),
    _HeaderSignature("PHP", "x-powered-by", re.compile(r"php(?:/([\d.]+))?", re.IGNORECASE), "high", 1),
    _HeaderSignature("Express", "x-powered-by", re.compile(r"express", re.IGNORECASE), "medium"),
    _HeaderSignature("ASP.NET", "x-powered-by", re.compile(r"asp\.net", re.IGNORECASE), "high"),
    _HeaderSignature("ASP.NET", "x-aspnet-version", re.compile(r"([\d.]+)"), "high", 1),
]

_COOKIE_SIGNATURES: list[_CookieSignature] = [
    _CookieSignature("PHP", "PHPSESSID", "medium"),
    _CookieSignature("Django", "csrftoken", "medium"),
    _CookieSignature("Laravel", "laravel_session", "high"),
    _CookieSignature("Ruby on Rails", "_session_id", "low"),
    _CookieSignature("ASP.NET", "ASP.NET_SessionId", "high"),
    _CookieSignature("Express", "connect.sid", "high"),
]

_BODY_SIGNATURES: list[_BodySignature] = [
    _BodySignature("WordPress", re.compile(r"wp-content|wp-includes", re.IGNORECASE), "high"),
    _BodySignature("Drupal", re.compile(r"drupal\.settings|/sites/default/files", re.IGNORECASE), "medium"),
    _BodySignature("React", re.compile(r"data-reactroot|__NEXT_DATA__", re.IGNORECASE), "low"),
    _BodySignature(
        "Generator-meta",
        re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE),
        "medium",
        1,
    ),
]


class TechnologyFingerprinter:
    def detect(self, response: httpx.Response) -> list[TechnologyDetection]:
        detections: list[TechnologyDetection] = []
        detections.extend(self._from_headers(response))
        detections.extend(self._from_cookies(response))
        detections.extend(self._from_body(response))
        return _dedupe(detections)

    def _from_headers(self, response: httpx.Response) -> list[TechnologyDetection]:
        found: list[TechnologyDetection] = []
        for sig in _HEADER_SIGNATURES:
            value = response.headers.get(sig.header)
            if not value:
                continue
            match = sig.pattern.search(value)
            if not match:
                continue
            version = match.group(sig.version_group) if sig.version_group else None
            found.append(
                TechnologyDetection(
                    name=sig.name,
                    version=version,
                    confidence=sig.confidence,
                    source=f"header:{sig.header}",
                )
            )
        return found

    def _from_cookies(self, response: httpx.Response) -> list[TechnologyDetection]:
        found: list[TechnologyDetection] = []
        cookie_names = {c.split("=", 1)[0].strip() for c in response.headers.get_list("set-cookie")}
        for sig in _COOKIE_SIGNATURES:
            if sig.cookie_name in cookie_names:
                found.append(
                    TechnologyDetection(
                        name=sig.name,
                        version=None,
                        confidence=sig.confidence,
                        source=f"cookie:{sig.cookie_name}",
                    )
                )
        return found

    def _from_body(self, response: httpx.Response) -> list[TechnologyDetection]:
        found: list[TechnologyDetection] = []
        content_type = response.headers.get("content-type", "")
        if "html" not in content_type and content_type != "":
            return found
        try:
            body = response.text
        except Exception:
            return found
        for sig in _BODY_SIGNATURES:
            match = sig.pattern.search(body)
            if not match:
                continue
            version = match.group(sig.version_group) if sig.version_group else None
            name = sig.name
            if sig.name == "Generator-meta":
                # e.g. content="WordPress 6.4" — split into name/version heuristically
                generator_value = match.group(1)
                parts = generator_value.rsplit(" ", 1)
                if len(parts) == 2 and re.match(r"^[\d.]+$", parts[1]):
                    name, version = parts[0], parts[1]
                else:
                    name, version = generator_value, None
            found.append(
                TechnologyDetection(
                    name=name, version=version, confidence=sig.confidence, source="body:meta-generator"
                    if sig.name == "Generator-meta" else "body:marker",
                )
            )
        return found


def _dedupe(detections: list[TechnologyDetection]) -> list[TechnologyDetection]:
    seen: dict[str, TechnologyDetection] = {}
    _confidence_rank = {"low": 0, "medium": 1, "high": 2}
    for d in detections:
        existing = seen.get(d.name)
        if existing is None or _confidence_rank[d.confidence] > _confidence_rank[existing.confidence]:
            seen[d.name] = d
    return list(seen.values())
