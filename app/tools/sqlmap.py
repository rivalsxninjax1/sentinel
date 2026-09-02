"""Adapter for sqlmap (SQL injection detection).

Per docs/architecture.md §15 and non-negotiable rule #2: this adapter NEVER adds
destructive flags (--dump, --os-shell, --os-pwn, --sql-shell, etc.) — only detection
at conservative --level/--risk defaults. Automated data dumping or shell access is out
of scope for this platform, full stop; that is not something a future flag or config
option should change either.

Like XSStrike, sqlmap's stdout doesn't have a stable structured-output mode this
adapter can parse safely, so `parse()` is a line-based heuristic scan for its known
"is vulnerable" / DBMS-identification marker phrases. Treat every finding as
low-confidence pending Phase 9 verification.

Requires ACTIVE mode.

License/version: see docs/tools.md.
"""

from __future__ import annotations

from app.tools.base import SecurityToolAdapter, ToolConfigError, ToolExecutionContext
from app.tools.models import NormalizedFinding

_VULNERABLE_MARKER = "is vulnerable"
_DBMS_MARKER = "back-end dbms"


class SqlmapAdapter(SecurityToolAdapter):
    name = "sqlmap"
    binary_name = "sqlmap"

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
                "sqlmap performs live SQL injection probing; it requires ACTIVE mode."
            )

    def build_command(self, context: ToolExecutionContext) -> list[str]:
        # Conservative, non-destructive defaults. NEVER add --dump/--os-shell/
        # --os-pwn/--sql-shell/--dump-all here — see module docstring.
        return [
            self.binary_name,
            "-u",
            context.target_url,
            "--batch",
            "--random-agent",
            "--level=1",
            "--risk=1",
            "--timeout",
            str(int(context.timeout_seconds)),
        ]

    def parse(self, raw_output: str) -> list[dict]:
        records = []
        for line in raw_output.splitlines():
            lowered = line.lower()
            if _VULNERABLE_MARKER in lowered or _DBMS_MARKER in lowered:
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
                    title="Possible SQL injection (sqlmap heuristic text match — unverified)",
                    severity="high",
                    matched_endpoint=context.target_url,
                    raw_output=record["line"],
                    metadata={"parse_method": "line_heuristic", "confidence": "low"},
                )
            )
        return findings
