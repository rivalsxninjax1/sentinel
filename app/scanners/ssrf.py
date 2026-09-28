"""Server-Side Request Forgery detection — two independent techniques.

1. REFLECTION-BASED (original, Phase 7): inject well-known internal/metadata
   URLs and check whether the RESPONSE reflects back a signature proving the
   fetch happened. Only catches SSRF where the target shows you something.

2. OOB-BASED (this phase): when `target.oob_client` is configured (see
   app/oob/client.py, requires `target.oob` explicitly enabled in config), inject
   a URL pointing at a SENTINEL-controlled listener with a unique correlation ID
   instead of an internal target, then check whether that listener actually
   received a callback. This catches BLIND SSRF — the target fetches the URL but
   shows the caller nothing at all — which technique #1 can never detect by
   design. An OOB-confirmed finding is direct network-level proof, not a
   heuristic signature match, so it's reported at higher confidence than the
   reflection-based path.

Both techniques run when OOB is configured; only #1 runs otherwise. Requires
ACTIVE mode either way — this attempts to make the target issue requests to
internal/metadata infrastructure (or an operator-controlled listener), which is
intrusive.
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

        findings: list[NormalizedFinding] = []

        if target.oob_client is not None:
            oob_finding = await self._try_oob_confirmation(target, http_client)
            if oob_finding is not None:
                findings.append(oob_finding)

        findings.extend(await self._try_reflection_based(target, http_client))
        return findings

    async def _try_oob_confirmation(
        self, target: ScanTarget, http_client: SentinelHTTPClient
    ) -> NormalizedFinding | None:
        oob = target.oob_client
        correlation_id = oob.generate_correlation_id()
        callback_url = oob.build_callback_url(correlation_id)
        test_url = inject_query_param(target.url, target.parameter_name, callback_url)

        try:
            await http_client.get(test_url)
        except (httpx.HTTPError, ScopeViolation):
            pass  # the request may fail/hang on the target side; we only care whether the OOB hit lands

        confirmed = await oob.register_and_wait(
            correlation_id=correlation_id,
            scan_id=target.oob_scan_id or "",
            vulnerability_class=self.vulnerability_class,
            matched_endpoint=test_url,
            parameter_name=target.parameter_name,
        )
        if not confirmed:
            return None

        return NormalizedFinding(
            tool_name=self.name,
            tool_version=None,
            title=(
                f"Confirmed blind SSRF via parameter '{target.parameter_name}' "
                f"(out-of-band callback received)"
            ),
            severity="critical",
            matched_endpoint=test_url,
            raw_output=f"OOB listener received a callback for correlation ID {correlation_id}",
            metadata={
                "parameter": target.parameter_name,
                "vulnerability_class": self.vulnerability_class,
                "confidence": "high",
                "detection_method": "oob_confirmed",
                "correlation_id": correlation_id,
            },
        )

    async def _try_reflection_based(
        self, target: ScanTarget, http_client: SentinelHTTPClient
    ) -> list[NormalizedFinding]:
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
                                "detection_method": "reflection",
                                "probe": payload,
                                "known_gap": "blind SSRF (no reflection) requires OOB — enable "
                                "target.oob in config to catch this class too",
                            },
                        )
                    ]

        return []
