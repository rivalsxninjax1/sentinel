"""CSRF protection check: for state-changing forms (POST/PUT/DELETE — GET forms are
skipped since GET shouldn't change state in the first place), checks whether any
field name looks like an anti-CSRF token, and whether the session cookie (if any)
sets SameSite to Strict or Lax.

Purely inspects already-known form structure plus one GET response's cookies — no
payload injection. SAFE mode (matches other lightweight checks; the one HTTP request
is to read cookie attributes, not to change anything).
"""

from __future__ import annotations

from app.core.http_client import SentinelHTTPClient
from app.scanners.base import DeterministicScanner, ScanTarget
from app.tools.models import NormalizedFinding

_CSRF_TOKEN_NAME_HINTS = (
    "csrf",
    "xsrf",
    "authenticity_token",
    "_token",
    "csrfmiddlewaretoken",
    "requestverificationtoken",
)


class CSRFScanner(DeterministicScanner):
    name = "csrf"
    vulnerability_class = "csrf"
    required_mode = "safe"

    async def scan(
        self, target: ScanTarget, http_client: SentinelHTTPClient
    ) -> list[NormalizedFinding]:
        if target.method.upper() not in ("POST", "PUT", "DELETE", "PATCH"):
            return []
        if target.form_fields is None:
            return []

        field_names = [f.get("name", "").lower() for f in target.form_fields]
        has_csrf_field = any(
            any(hint in name for hint in _CSRF_TOKEN_NAME_HINTS) for name in field_names
        )

        findings: list[NormalizedFinding] = []

        if not has_csrf_field:
            findings.append(
                NormalizedFinding(
                    tool_name=self.name,
                    tool_version=None,
                    title=f"{target.method} form has no anti-CSRF token field",
                    severity="medium",
                    matched_endpoint=target.url,
                    raw_output=f"form fields: {field_names}",
                    metadata={
                        "vulnerability_class": self.vulnerability_class,
                        "confidence": "low",
                        "note": "absence of a token field name is suggestive, not proof "
                        "(token could be delivered via header or double-submit cookie instead)",
                    },
                )
            )

        response = await http_client.get(target.url)
        for cookie_header in response.headers.get_list("set-cookie"):
            lowered = cookie_header.lower()
            if "samesite" not in lowered:
                findings.append(
                    NormalizedFinding(
                        tool_name=self.name,
                        tool_version=None,
                        title="Cookie set without a SameSite attribute",
                        severity="low",
                        matched_endpoint=target.url,
                        raw_output=cookie_header,
                        metadata={"vulnerability_class": self.vulnerability_class, "confidence": "high"},
                    )
                )
            elif "samesite=none" in lowered:
                findings.append(
                    NormalizedFinding(
                        tool_name=self.name,
                        tool_version=None,
                        title="Cookie set with SameSite=None",
                        severity="low",
                        matched_endpoint=target.url,
                        raw_output=cookie_header,
                        metadata={"vulnerability_class": self.vulnerability_class, "confidence": "high"},
                    )
                )

        return findings
