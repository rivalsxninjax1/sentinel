"""CORS misconfiguration check: sends a request with a spoofed Origin header that
could never legitimately be an allowed cross-origin caller, and checks whether the
response reflects it back in Access-Control-Allow-Origin — especially dangerous when
combined with Access-Control-Allow-Credentials: true, which would let an attacker's
page make authenticated cross-origin requests on a victim's behalf.

Single GET request, no state change — SAFE mode.
"""

from __future__ import annotations

from app.core.http_client import SentinelHTTPClient
from app.scanners.base import DeterministicScanner, ScanTarget
from app.tools.models import NormalizedFinding

_SPOOFED_ORIGIN = "https://sentinel-cors-test.invalid"


class CORSScanner(DeterministicScanner):
    name = "cors"
    vulnerability_class = "cors"
    required_mode = "safe"

    async def scan(
        self, target: ScanTarget, http_client: SentinelHTTPClient
    ) -> list[NormalizedFinding]:
        response = await http_client.get(target.url, headers={"Origin": _SPOOFED_ORIGIN})

        acao = response.headers.get("access-control-allow-origin", "")
        acac = response.headers.get("access-control-allow-credentials", "").lower() == "true"

        if acao != _SPOOFED_ORIGIN and acao != "*":
            return []

        if acao == "*" and not acac:
            # Wildcard without credentials is a common, often-intentional, low-risk
            # pattern (public APIs). Still worth surfacing, but at lower severity.
            return [
                NormalizedFinding(
                    tool_name=self.name,
                    tool_version=None,
                    title="CORS: Access-Control-Allow-Origin is '*' (any origin allowed)",
                    severity="low",
                    matched_endpoint=target.url,
                    raw_output=f"Access-Control-Allow-Origin: {acao}",
                    metadata={
                        "vulnerability_class": self.vulnerability_class,
                        "confidence": "high",
                        "credentials_allowed": False,
                    },
                )
            ]

        # Reflected our exact spoofed origin, or wildcard + credentials — high severity.
        severity = "high" if acac else "medium"
        return [
            NormalizedFinding(
                tool_name=self.name,
                tool_version=None,
                title=(
                    "CORS misconfiguration: arbitrary Origin reflected in "
                    "Access-Control-Allow-Origin"
                    + (" with Access-Control-Allow-Credentials: true" if acac else "")
                ),
                severity=severity,
                matched_endpoint=target.url,
                raw_output=(
                    f"sent Origin: {_SPOOFED_ORIGIN}, got "
                    f"Access-Control-Allow-Origin: {acao}, "
                    f"Access-Control-Allow-Credentials: {acac}"
                ),
                metadata={
                    "vulnerability_class": self.vulnerability_class,
                    "confidence": "high",
                    "credentials_allowed": acac,
                },
            )
        ]
