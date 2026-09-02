"""Adapter for `ffuf` (web fuzzer — content discovery, parameter fuzzing).

Requires an explicit wordlist path in `context.extra["wordlist"]` — SENTINEL does not
ship or auto-select a wordlist, per docs/architecture.md §19 ("the orchestrator must
... choose wordlists"); the operator provides one so scope/aggressiveness stays a
deliberate choice, not a default.

License/version: see docs/tools.md.
"""

from __future__ import annotations

import json

from app.tools.base import SecurityToolAdapter, ToolConfigError, ToolExecutionContext
from app.tools.models import NormalizedFinding


class FfufAdapter(SecurityToolAdapter):
    name = "ffuf"
    binary_name = "ffuf"

    async def version(self) -> str | None:
        if not self.is_available():
            return None
        try:
            _, stdout, _ = await self._runner([self.binary_name, "-V"], 10.0)
            return stdout.strip() or None
        except Exception:
            return None

    def validate_config(self, context: ToolExecutionContext) -> None:
        if context.mode == "passive":
            raise ToolConfigError("ffuf issues active fuzzing requests; it cannot run in PASSIVE mode.")
        if not context.extra.get("wordlist"):
            raise ToolConfigError(
                "ffuf requires context.extra['wordlist'] (a path to a wordlist file) — "
                "SENTINEL does not select one automatically."
            )

    def build_command(self, context: ToolExecutionContext) -> list[str]:
        target = context.target_url.rstrip("/")
        wordlist = context.extra["wordlist"]
        max_requests = context.extra.get("max_requests", 5000)
        return [
            self.binary_name,
            "-u",
            f"{target}/FUZZ",
            "-w",
            str(wordlist),
            "-of",
            "json",
            "-o",
            "-",
            "-rate",
            str(max(1, int(context.requests_per_second))),
            "-timeout",
            str(int(context.timeout_seconds)),
            "-maxtime",
            str(int(context.timeout_seconds)),
            "-N",
            str(int(max_requests)),
            "-mc",
            "200,204,301,302,307,401,403",
            "-s",
        ]

    def parse(self, raw_output: str) -> list[dict]:
        raw_output = raw_output.strip()
        if not raw_output:
            return []
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return []
        return data.get("results", [])

    def normalize(
        self, parsed: list[dict], context: ToolExecutionContext, tool_version: str | None
    ) -> list[NormalizedFinding]:
        findings = []
        for record in parsed:
            status = record.get("status")
            findings.append(
                NormalizedFinding(
                    tool_name=self.name,
                    tool_version=tool_version,
                    title=f"Discovered path (status {status})",
                    severity="info",
                    matched_endpoint=record.get("url", context.target_url),
                    raw_output=json.dumps(record),
                    metadata={
                        "status": status,
                        "length": record.get("length"),
                        "words": record.get("words"),
                        "lines": record.get("lines"),
                    },
                )
            )
        return findings
