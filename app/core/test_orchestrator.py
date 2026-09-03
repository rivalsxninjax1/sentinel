"""TestOrchestrator — the sole authority on whether a deterministic scanner actually
runs against a given endpoint/parameter.

Per docs/architecture.md §44/§5: AI recommendations (Phase 4 `Classification` rows)
may inform *which* parameters get extra scanner attention, but nothing in this class
takes instructions from the AI directly — it only ever reads scan configuration
(mode) and attack-surface facts (parameter names) that the orchestrator itself
decided were worth checking. There is no code path from app/llm/ or
app/intelligence/reasoning.py into this file.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.core.http_client import SentinelHTTPClient
from app.core.logging import get_logger
from app.scanners.base import DeterministicScanner, ScanTarget, mode_allows
from app.tools.models import NormalizedFinding

logger = get_logger(__name__)

_HOST_LEVEL_SCANNERS = {"security_headers", "information_exposure"}
_REDIRECT_PARAM_HINTS = ("url", "redirect", "next", "return", "dest", "continue", "target")


@dataclass
class OrchestrationResult:
    findings: list[NormalizedFinding] = field(default_factory=list)
    scanners_run: int = 0
    scanners_skipped_mode: int = 0
    errors: list[str] = field(default_factory=list)


class TestOrchestrator:
    def __init__(self, scanners: list[DeterministicScanner], mode: str) -> None:
        self._scanners = scanners
        self._mode = mode

    async def run_host_level(
        self, host_root_url: str, http_client: SentinelHTTPClient
    ) -> OrchestrationResult:
        """Runs scanners that operate once per host (security headers, information
        exposure) rather than per-parameter."""
        result = OrchestrationResult()
        target = ScanTarget(url=host_root_url, method="GET")

        for scanner in self._scanners:
            if scanner.name not in _HOST_LEVEL_SCANNERS:
                continue
            await self._run_one(scanner, target, http_client, result)

        return result

    async def run_parameter_level(
        self,
        endpoint_url: str,
        method: str,
        parameter_name: str,
        parameter_location: str,
        http_client: SentinelHTTPClient,
    ) -> OrchestrationResult:
        """Runs scanners that need a specific parameter to inject a payload into."""
        result = OrchestrationResult()
        target = ScanTarget(
            url=endpoint_url,
            method=method,
            parameter_name=parameter_name,
            parameter_location=parameter_location,
        )

        for scanner in self._scanners:
            if scanner.name in _HOST_LEVEL_SCANNERS:
                continue
            if scanner.name == "open_redirect" and not self._looks_like_redirect_param(parameter_name):
                continue
            await self._run_one(scanner, target, http_client, result)

        return result

    async def _run_one(
        self,
        scanner: DeterministicScanner,
        target: ScanTarget,
        http_client: SentinelHTTPClient,
        result: OrchestrationResult,
    ) -> None:
        if not mode_allows(self._mode, scanner.required_mode):
            result.scanners_skipped_mode += 1
            return
        try:
            findings = await scanner.scan(target, http_client)
            result.findings.extend(findings)
            result.scanners_run += 1
        except Exception as exc:  # a single scanner's bug must not abort the whole run
            logger.warning(
                "scanner_failed",
                scanner=scanner.name,
                url=target.url,
                parameter=target.parameter_name,
                error=str(exc),
            )
            result.errors.append(f"{scanner.name}@{target.url}:{target.parameter_name}: {exc}")

    @staticmethod
    def _looks_like_redirect_param(name: str) -> bool:
        lowered = name.lower()
        return any(hint in lowered for hint in _REDIRECT_PARAM_HINTS)
