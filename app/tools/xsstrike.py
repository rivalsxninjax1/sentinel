"""Adapter for XSStrike (context-aware XSS detection engine).

XSStrike doesn't ship a stable structured-output mode, so `parse()` here is a
line-based heuristic scan for its known "vulnerable" marker phrases in stdout. This is
intentionally weaker than the JSON-based adapters (httpx/nuclei/ffuf/katana) — every
finding this adapter produces should be treated as INFO-level / low-confidence until
Phase 9's Verification Engine and multi-tool correlation (docs/architecture.md §22-24)
weigh in. Do not surface XSStrike output as a confirmed vulnerability anywhere
upstream of that.

Requires ACTIVE mode: XSStrike performs live payload injection.

License/version: see docs/tools.md. Assumes an `xsstrike` entry point exists on PATH
(e.g. a shim/alias around `python3 xsstrike.py`) — see docs/setup.md for install
notes once written.
"""

from __future__ import annotations

from app.tools.base import SecurityToolAdapter, ToolConfigError, ToolExecutionContext
from app.tools.models import NormalizedFinding

_VULNERABLE_MARKERS = ("is vulnerable", "vulnerable webpage")


class XSStrikeAdapter(SecurityToolAdapter):
    name = "xsstrike"
    binary_name = "xsstrike"

    async def version(self) -> str | None:
        if not self.is_available():
            return None
        try:
            _, stdout, _ = await self._runner([self.binary_name, "--version"], 10.0)
            return stdout.strip() or None
        except Exception:
            return None

    def validate_config(self, context: ToolExecutionContext) -> None:
        if context.mode != "active":
            raise ToolConfigError(
                "XSStrike performs live payload injection; it requires ACTIVE mode."
            )

    def build_command(self, context: ToolExecutionContext) -> list[str]:
        return [
            self.binary_name,
            "-u",
            context.target_url,
            "--skip-dom",  # DOM XSS testing needs a browser context; left to Phase 6+
            "--timeout",
            str(int(context.timeout_seconds)),
        ]

    def parse(self, raw_output: str) -> list[dict]:
        records = []
        for line in raw_output.splitlines():
            lowered = line.lower()
            if any(marker in lowered for marker in _VULNERABLE_MARKERS):
                records.append({"line": line.strip()})
        return records

    def normalize(
        self, parsed: list[dict], context: ToolExecutionContext, tool_version: str | None
    ) -> list[NormalizedFinding]:
        findings = []
        for record in parsed:
            findings.append(
                NormalizedFinding(
                    tool_name=self.name,
                    tool_version=tool_version,
                    title="Possible XSS (XSStrike heuristic text match — unverified)",
                    severity="medium",
                    matched_endpoint=context.target_url,
                    raw_output=record["line"],
                    metadata={"parse_method": "line_heuristic", "confidence": "low"},
                )
            )
        return findings
