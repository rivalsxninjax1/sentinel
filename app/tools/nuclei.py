"""Adapter for ProjectDiscovery's `nuclei` (template-based vulnerability scanner).

Per docs/architecture.md §16: template selection is bounded by scan mode, not "run
every template." In SAFE mode this restricts to info/low severity templates only
(fingerprinting, exposed-panel/misconfiguration checks) — anything that could be
considered an active exploitation attempt requires ACTIVE mode. This is enforced in
`validate_config()`/`build_command()`, not left to the operator to remember.

License/version: see docs/tools.md.
"""

from __future__ import annotations

import json

from app.tools.base import SecurityToolAdapter, ToolConfigError, ToolExecutionContext
from app.tools.models import NormalizedFinding


class NucleiAdapter(SecurityToolAdapter):
    name = "nuclei"
    binary_name = "nuclei"

    async def version(self) -> str | None:
        if not self.is_available():
            return None
        try:
            _, stdout, _ = await self._runner([self.binary_name, "-version"], 10.0)
            return stdout.strip() or None
        except Exception:
            return None

    def validate_config(self, context: ToolExecutionContext) -> None:
        if context.mode == "passive":
            raise ToolConfigError(
                "Nuclei sends active HTTP requests to match templates; it cannot run "
                "in PASSIVE mode. Use SAFE (info/low severity templates only) or "
                "ACTIVE."
            )

    def build_command(self, context: ToolExecutionContext) -> list[str]:
        command = [
            self.binary_name,
            "-u",
            context.target_url,
            "-jsonl",
            "-silent",
            "-rate-limit",
            str(max(1, int(context.requests_per_second))),
            "-timeout",
            str(int(context.timeout_seconds)),
        ]
        if context.mode == "safe":
            command += ["-severity", "info,low"]
        return command

    def parse(self, raw_output: str) -> list[dict]:
        records = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records

    def normalize(
        self, parsed: list[dict], context: ToolExecutionContext, tool_version: str | None
    ) -> list[NormalizedFinding]:
        findings = []
        for record in parsed:
            info = record.get("info", {})
            findings.append(
                NormalizedFinding(
                    tool_name=self.name,
                    tool_version=tool_version,
                    title=info.get("name", record.get("template-id", "Nuclei match")),
                    severity=info.get("severity", "info"),
                    matched_endpoint=record.get("matched-at", context.target_url),
                    raw_output=json.dumps(record),
                    metadata={
                        "template_id": record.get("template-id"),
                        "type": record.get("type"),
                        "tags": info.get("tags", []),
                    },
                )
            )
        return findings
