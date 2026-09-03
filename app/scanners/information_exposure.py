"""Checks a small, fixed list of commonly-sensitive paths relative to the host root.

Deliberately bounded and non-exhaustive — this is NOT a content-discovery brute
force (that's ffuf's job, app/tools/ffuf.py, with an operator-supplied wordlist).
Requires SAFE mode: each request is benign (a plain GET), but probing for backup/
config files is still an active reconnaissance action, not purely passive.
"""

from __future__ import annotations

import httpx

from app.core.http_client import SentinelHTTPClient
from app.scanners.base import DeterministicScanner, ScanTarget
from app.scope.engine import ScopeViolation
from app.tools.models import NormalizedFinding

_SENSITIVE_PATHS = [
    ".git/HEAD",
    ".env",
    ".DS_Store",
    "backup.zip",
    "backup.sql",
    "wp-config.php.bak",
    "config.php.bak",
    ".svn/entries",
    "web.config.bak",
    ".well-known/security.txt",  # informational only — presence is not a finding, see below
]

# Paths whose presence is normal/expected and should never be flagged even if found.
_BENIGN_PATHS = {".well-known/security.txt"}


class InformationExposureScanner(DeterministicScanner):
    name = "information_exposure"
    vulnerability_class = "information_exposure"
    required_mode = "safe"

    async def scan(
        self, target: ScanTarget, http_client: SentinelHTTPClient
    ) -> list[NormalizedFinding]:
        parsed = httpx.URL(target.url)
        root = f"{parsed.scheme}://{parsed.host}"
        findings: list[NormalizedFinding] = []

        for path in _SENSITIVE_PATHS:
            if path in _BENIGN_PATHS:
                continue
            url = f"{root}/{path}"
            try:
                response = await http_client.get(url)
            except (httpx.HTTPError, ScopeViolation):
                continue
            if response.status_code == 200 and len(response.content) > 0:
                findings.append(
                    NormalizedFinding(
                        tool_name=self.name,
                        tool_version=None,
                        title=f"Potentially exposed sensitive file: /{path}",
                        severity="medium",
                        matched_endpoint=url,
                        raw_output=f"status={response.status_code}, length={len(response.content)}",
                        metadata={
                            "path": path,
                            "vulnerability_class": self.vulnerability_class,
                            "confidence": "low",  # 200 + non-empty is suggestive, not proof
                        },
                    )
                )

        return findings
