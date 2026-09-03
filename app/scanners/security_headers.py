"""Passive check for missing security-relevant HTTP response headers and disclosed
server banners. Fully passive — reads one response that's already being fetched
anyway, sends no additional requests, injects no payloads. Safe at any scan mode.
"""

from __future__ import annotations

from app.core.http_client import SentinelHTTPClient
from app.scanners.base import DeterministicScanner, ScanTarget
from app.tools.models import NormalizedFinding

# header (lowercased) -> (display name, severity if missing)
_EXPECTED_HEADERS: dict[str, tuple[str, str]] = {
    "content-security-policy": ("Content-Security-Policy", "medium"),
    "x-frame-options": ("X-Frame-Options", "low"),
    "x-content-type-options": ("X-Content-Type-Options", "low"),
    "strict-transport-security": ("Strict-Transport-Security", "medium"),
    "referrer-policy": ("Referrer-Policy", "info"),
}

_BANNER_HEADERS = ("server", "x-powered-by")


class SecurityHeadersScanner(DeterministicScanner):
    name = "security_headers"
    vulnerability_class = "security_headers"
    required_mode = "passive"

    async def scan(
        self, target: ScanTarget, http_client: SentinelHTTPClient
    ) -> list[NormalizedFinding]:
        response = await http_client.get(target.url)
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        findings: list[NormalizedFinding] = []

        for header_key, (display_name, severity) in _EXPECTED_HEADERS.items():
            if header_key in headers_lower:
                continue
            findings.append(
                NormalizedFinding(
                    tool_name=self.name,
                    tool_version=None,
                    title=f"Missing security header: {display_name}",
                    severity=severity,
                    matched_endpoint=target.url,
                    raw_output=f"status={response.status_code}",
                    metadata={
                        "header": display_name,
                        "vulnerability_class": self.vulnerability_class,
                        "confidence": "high",  # absence of a header is a fact, not a guess
                    },
                )
            )

        for header_key in _BANNER_HEADERS:
            value = headers_lower.get(header_key)
            if value:
                findings.append(
                    NormalizedFinding(
                        tool_name=self.name,
                        tool_version=None,
                        title=f"'{header_key}' header discloses: {value}",
                        severity="info",
                        matched_endpoint=target.url,
                        raw_output=f"{header_key}: {value}",
                        metadata={
                            "header": header_key,
                            "vulnerability_class": self.vulnerability_class,
                            "confidence": "high",
                        },
                    )
                )

        return findings
