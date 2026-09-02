"""Adapter for ProjectDiscovery's `katana` (standard + headless crawler).

Complements, not replaces, SENTINEL's own crawler (app/crawler/crawler.py) — Katana
results feed the same AttackSurfaceRepository (wiring for that is Phase 6+, once
orchestration decides when supplementary discovery tools are worth running). Findings
here are informational (discovered endpoints), not vulnerability claims.

License/version: see docs/tools.md.
"""

from __future__ import annotations

import json

from app.tools.base import SecurityToolAdapter, ToolExecutionContext
from app.tools.models import NormalizedFinding


class KatanaAdapter(SecurityToolAdapter):
    name = "katana"
    binary_name = "katana"

    async def version(self) -> str | None:
        if not self.is_available():
            return None
        try:
            _, stdout, _ = await self._runner([self.binary_name, "-version"], 10.0)
            return stdout.strip() or None
        except Exception:
            return None

    def build_command(self, context: ToolExecutionContext) -> list[str]:
        max_depth = context.extra.get("max_depth", 3)
        return [
            self.binary_name,
            "-u",
            context.target_url,
            "-jsonl",
            "-silent",
            "-rate-limit",
            str(max(1, int(context.requests_per_second))),
            "-timeout",
            str(int(context.timeout_seconds)),
            "-depth",
            str(int(max_depth)),
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
            request = record.get("request", {})
            response = record.get("response", {})
            endpoint = request.get("endpoint", context.target_url)
            findings.append(
                NormalizedFinding(
                    tool_name=self.name,
                    tool_version=tool_version,
                    title="Katana-discovered endpoint",
                    severity="info",
                    matched_endpoint=endpoint,
                    raw_output=json.dumps(record),
                    metadata={
                        "method": request.get("method", "GET"),
                        "status_code": response.get("status_code"),
                        "source": request.get("source"),
                    },
                )
            )
        return findings
