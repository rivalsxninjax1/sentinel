"""Adapter for ProjectDiscovery's `httpx` CLI (HTTP probing/metadata collection).

NOT to be confused with the Python `httpx` library used throughout the rest of
SENTINEL (see docs/tools.md's naming note) — this module only shells out to the
`httpx` binary; it never imports the Python package.

License/version: see docs/tools.md.
"""

from __future__ import annotations

import json

from app.tools.base import SecurityToolAdapter, ToolExecutionContext
from app.tools.models import NormalizedFinding


class HttpxAdapter(SecurityToolAdapter):
    name = "httpx"
    binary_name = "httpx"

    async def version(self) -> str | None:
        if not self.is_available():
            return None
        try:
            _, stdout, _ = await self._runner([self.binary_name, "-version"], 10.0)
            return stdout.strip() or None
        except Exception:
            return None

    def build_command(self, context: ToolExecutionContext) -> list[str]:
        return [
            self.binary_name,
            "-u",
            context.target_url,
            "-json",
            "-silent",
            "-rate-limit",
            str(max(1, int(context.requests_per_second))),
            "-timeout",
            str(int(context.timeout_seconds)),
        ]

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
            url = record.get("url", context.target_url)
            status = record.get("status_code")
            title = record.get("title", "")
            findings.append(
                NormalizedFinding(
                    tool_name=self.name,
                    tool_version=tool_version,
                    title=f"HTTP probe: {status} {title}".strip(),
                    severity="info",
                    matched_endpoint=url,
                    raw_output=json.dumps(record),
                    metadata={
                        "status_code": status,
                        "webserver": record.get("webserver"),
                        "technologies": record.get("tech", []),
                        "content_length": record.get("content_length"),
                    },
                )
            )
        return findings
