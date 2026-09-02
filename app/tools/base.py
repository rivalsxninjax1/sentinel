"""SecurityToolAdapter — the common interface every external security tool
integration implements (docs/architecture.md §20).

Governance rules this file exists to enforce (docs/architecture.md §5, §21, and the
governing spec's non-negotiable rules #1, #7, #8):

  - External tools NEVER bypass SENTINEL's scope system. `run()` enforces scope
    BEFORE invoking any external binary — adapters cannot opt out of this, since
    `run()` is not overridable per-adapter and is the only entry point orchestration
    code is expected to call.
  - The AI can recommend a test; only the orchestrator decides whether an adapter
    actually runs. This file has no AI awareness at all — there is no path from
    app/llm/ or app/intelligence/ into a ToolAdapter.
  - Tool output is untrusted until parsed, normalized, and — in Phase 9 — run through
    the Verification/Confidence/False-Positive engines. `normalize()` produces
    candidates, never confirmed findings.

KNOWN LIMITATION (documented, not hidden): SENTINEL's own RateLimiter paces
SENTINEL's own HTTP client, but it cannot intercept every request an external binary
issues internally. Rate limiting for tool-adapter runs is enforced by passing the
tool's own native rate-limit CLI flag (each adapter's `build_command()` derives one
from `context.requests_per_second`), not by intercepting the child process's sockets.
This mirrors the same tradeoff already documented for Playwright in Phase 3.
"""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from app.core.logging import get_logger
from app.scope.engine import ScopeEngine
from app.tools.models import NormalizedFinding
from app.tools.process import ProcessRunner, ToolTimeoutError, default_process_runner

logger = get_logger(__name__)


@dataclass
class ToolExecutionContext:
    """Everything an adapter needs to run once, against one target, safely."""

    target_url: str
    scope: ScopeEngine
    timeout_seconds: float = 60.0
    requests_per_second: float = 5.0
    mode: str = "safe"  # "passive" | "safe" | "active" — see docs/architecture.md §29
    extra: dict = field(default_factory=dict)


class ToolUnavailable(Exception):
    """Raised when an adapter's underlying binary isn't installed/on PATH."""


class ToolConfigError(Exception):
    """Raised by validate_config() when the execution context is invalid for this
    tool (e.g. an intrusive tool requested while the scan is in PASSIVE mode)."""


class SecurityToolAdapter(ABC):
    """Conceptual interface from docs/architecture.md §20. `run()` provides the
    shared scope-enforcement + subprocess-execution plumbing every adapter needs;
    subclasses implement only the tool-specific pieces (command construction,
    output parsing, normalization)."""

    name: str
    binary_name: str

    def __init__(self, runner: ProcessRunner | None = None) -> None:
        self._runner = runner or default_process_runner

    def is_available(self) -> bool:
        return shutil.which(self.binary_name) is not None

    @abstractmethod
    async def version(self) -> str | None:
        """Return the installed tool's version string, or None if unavailable."""
        raise NotImplementedError

    def validate_config(self, context: ToolExecutionContext) -> None:
        """Raise ToolConfigError if this adapter shouldn't run in this context.
        Default: no extra constraints beyond scope. Override for e.g. tools that
        require ACTIVE mode."""
        return None

    @abstractmethod
    def build_command(self, context: ToolExecutionContext) -> list[str]:
        """Build the full argv for this tool run."""
        raise NotImplementedError

    @abstractmethod
    def parse(self, raw_output: str) -> list[dict]:
        """Parse raw stdout into a list of tool-specific dict records."""
        raise NotImplementedError

    @abstractmethod
    def normalize(
        self, parsed: list[dict], context: ToolExecutionContext, tool_version: str | None
    ) -> list[NormalizedFinding]:
        """Convert parsed records into NormalizedFinding — the only shape the rest
        of SENTINEL (verification, correlation, reporting) understands."""
        raise NotImplementedError

    async def run(self, context: ToolExecutionContext) -> list[NormalizedFinding]:
        """Full adapter lifecycle: scope check -> availability check -> config
        validation -> command build -> subprocess execution -> parse -> normalize.
        This is the only method orchestration code (Phase 6+) needs to call."""
        context.scope.enforce(context.target_url)  # raises ScopeViolation; never caught here

        if not self.is_available():
            raise ToolUnavailable(f"{self.name}: binary '{self.binary_name}' not found on PATH")

        self.validate_config(context)

        version = await self.version()
        command = self.build_command(context)

        logger.info("tool_run_start", tool=self.name, target=context.target_url)
        try:
            returncode, stdout, stderr = await self._runner(command, context.timeout_seconds)
        except ToolTimeoutError:
            logger.warning("tool_run_timeout", tool=self.name, target=context.target_url)
            raise

        if returncode != 0 and not stdout.strip():
            logger.warning(
                "tool_run_nonzero_exit", tool=self.name, returncode=returncode, stderr=stderr[:500]
            )

        parsed = self.parse(stdout)
        findings = self.normalize(parsed, context, version)
        logger.info("tool_run_complete", tool=self.name, findings=len(findings))
        return findings

    async def cleanup(self) -> None:
        """Default no-op. Override for adapters that create temp files/output dirs."""
        return None
