"""Server-Side Request Forgery heuristic.

Without a real out-of-band (OOB) correlation server (docs/architecture.md §27 —
"Safe OOB System" — not built yet), SENTINEL cannot reliably prove a blind SSRF
where the target fetches a URL but never reflects anything back. This scanner is
limited to the subset of SSRF that IS detectable without OOB infrastructure:
requests to well-known internal/metadata endpoints whose response, if fetched and
reflected back to us, contains a recognizable signature (e.g. cloud metadata
service responses).

Blind SSRF (no reflection) will NOT be caught by this scanner — that's an explicit,
documented gap, not a silent one. A real OOB callback system is future work.

Requires ACTIVE mode: this attempts to make the target issue requests to internal/
metadata infrastructure, which is intrusive.
"""

from __future__ import annotations

import httpx

from app.core.http_client import SentinelHTTPClient
from app.scanners.base import DeterministicScanner, ScanTarget
from app.scanners.util import inject_query_param
from app.scope.engine import ScopeViolation
from app.tools.models import NormalizedFinding

# (payload, [signature substrings that would indicate the fetch succeeded and was reflected])
_SSRF_PROBES: list[tuple[str, list[str]]] = [
    ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "iam/security-credentials"]),
    ("http://metadata.google.internal/computeMetadata/v1/", ["computeMetadata", "instance/"]),
    ("http://127.0.0.1:22/", ["ssh-2.0", "openssh"]),
]


class SSRFScanner(DeterministicScanner):
    name = "ssrf"
    vulnerability_class = "ssrf"
    required_mode = "active"

    async def scan(
        self, target: ScanTarget, http_client: SentinelHTTPClient
    ) -> list[NormalizedFinding]:
        if not target.parameter_name:
            return []

        for payload, signatures in _SSRF_PROBES:
            test_url = inject_query_param(target.url, target.parameter_name, payload)
            try:
                response = await http_client.get(test_url)
            except (httpx.HTTPError, ScopeViolation):
                continue

            lowered = response.text.lower()
            for signature in signatures:
                if signature.lower() in lowered:
                    return [
                        NormalizedFinding(
                            tool_name=self.name,
                            tool_version=None,
                            title=(
                                f"Possible SSRF via parameter '{target.parameter_name}' "
                                f"(internal/metadata response reflected)"
                            ),
                            severity="high",
                            matched_endpoint=test_url,
                            raw_output=f"matched signature: {signature!r} for probe {payload!r}",
                            metadata={
                                "parameter": target.parameter_name,
                                "vulnerability_class": self.vulnerability_class,
                                "confidence": "low",
                                "probe": payload,
                                "known_gap": "blind SSRF (no reflection) is not detected without OOB infrastructure",
                            },
                        )
                    ]

        return []
