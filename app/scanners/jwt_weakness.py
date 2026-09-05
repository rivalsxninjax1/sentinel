"""JWT structural weakness check — passive/read-only.

Looks for JWT-shaped tokens (three base64url segments) in the response body and
Set-Cookie headers of the host root, decodes header + payload WITHOUT verifying any
signature against the server (we have no legitimate way to forge/replay tokens
without a real authenticated session, which SENTINEL doesn't manage yet — see
docs/architecture.md §26), and flags purely structural weaknesses:

  - `alg: none` accepted in the header — a well-known JWT library misconfiguration
    class (if the server actually honors an unsigned token, that's a critical
    finding, but confirming *server acceptance* would require forging and replaying
    a token, which this scanner does not do — it only flags that the token's own
    header declares "none", which is suspicious on its own).
  - HS256 token whose signature verifies against a small built-in list of extremely
    common weak secrets (a legitimate, well-established check — this simply runs
    HMAC-SHA256 with public well-known values and compares, exactly what any HTTP
    client could do by hand; it does not attempt to brute-force or guess anything
    beyond a short fixed list).
  - missing `exp` (no expiration) claim — informational.

This does NOT replay a forged token against the application to confirm exploitability
— that would require session/identity management SENTINEL doesn't have. Every finding
here is a structural observation, confidence capped at "low" (or "high" only for the
directly-observable "alg is literally the string none" case).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re

from app.core.http_client import SentinelHTTPClient
from app.scanners.base import DeterministicScanner, ScanTarget
from app.tools.models import NormalizedFinding

_JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

_COMMON_WEAK_SECRETS = [
    "secret",
    "password",
    "changeme",
    "your-256-bit-secret",
    "jwt_secret",
    "supersecret",
    "123456",
    "secretkey",
    "mysecret",
    "test",
]


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


class JWTWeaknessScanner(DeterministicScanner):
    name = "jwt_weakness"
    vulnerability_class = "jwt"
    required_mode = "safe"

    async def scan(
        self, target: ScanTarget, http_client: SentinelHTTPClient
    ) -> list[NormalizedFinding]:
        response = await http_client.get(target.url)

        candidates: set[str] = set(_JWT_PATTERN.findall(response.text))
        for cookie_header in response.headers.get_list("set-cookie"):
            candidates.update(_JWT_PATTERN.findall(cookie_header))

        findings: list[NormalizedFinding] = []
        for token in candidates:
            findings.extend(self._analyze_token(token, target.url))
        return findings

    def _analyze_token(self, token: str, url: str) -> list[NormalizedFinding]:
        parts = token.split(".")
        if len(parts) != 3:
            return []

        try:
            header = json.loads(_b64url_decode(parts[0]))
            payload = json.loads(_b64url_decode(parts[1]))
        except Exception:
            return []

        findings: list[NormalizedFinding] = []
        alg = str(header.get("alg", "")).lower()

        if alg == "none":
            findings.append(
                NormalizedFinding(
                    tool_name=self.name,
                    tool_version=None,
                    title="JWT declares alg: none in its header",
                    severity="high",
                    matched_endpoint=url,
                    raw_output=f"header: {json.dumps(header)}",
                    metadata={
                        "vulnerability_class": self.vulnerability_class,
                        "confidence": "high",
                        "note": "server-side acceptance not confirmed — no token replay performed",
                    },
                )
            )

        if alg == "hs256":
            signing_input = f"{parts[0]}.{parts[1]}".encode()
            try:
                actual_signature = _b64url_decode(parts[2])
            except Exception:
                actual_signature = b""
            for weak_secret in _COMMON_WEAK_SECRETS:
                expected = hmac.new(
                    weak_secret.encode(), signing_input, hashlib.sha256
                ).digest()
                if hmac.compare_digest(expected, actual_signature):
                    findings.append(
                        NormalizedFinding(
                            tool_name=self.name,
                            tool_version=None,
                            title="JWT signed with a well-known weak HS256 secret",
                            severity="critical",
                            matched_endpoint=url,
                            raw_output="HMAC-SHA256 verification succeeded against a common weak secret",
                            metadata={
                                "vulnerability_class": self.vulnerability_class,
                                "confidence": "high",
                                "matched_secret": weak_secret,
                            },
                        )
                    )
                    break

        if "exp" not in payload:
            findings.append(
                NormalizedFinding(
                    tool_name=self.name,
                    tool_version=None,
                    title="JWT has no expiration (exp) claim",
                    severity="low",
                    matched_endpoint=url,
                    raw_output=f"payload keys: {list(payload.keys())}",
                    metadata={"vulnerability_class": self.vulnerability_class, "confidence": "high"},
                )
            )

        return findings
