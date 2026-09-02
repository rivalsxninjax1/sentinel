import pytest

from app.scope.engine import ScopeEngine, ScopeViolation
from app.tools.base import (
    SecurityToolAdapter,
    ToolConfigError,
    ToolExecutionContext,
    ToolUnavailable,
)
from app.tools.models import NormalizedFinding
from app.tools.process import ToolTimeoutError


class _FakeAdapter(SecurityToolAdapter):
    name = "fake-tool"
    binary_name = "fake-tool-binary-that-does-not-exist"

    def __init__(self, runner=None, force_available: bool = False, requires_active: bool = False):
        super().__init__(runner=runner)
        self._force_available = force_available
        self._requires_active = requires_active

    def is_available(self) -> bool:
        return self._force_available

    async def version(self) -> str | None:
        return "1.2.3" if self._force_available else None

    def validate_config(self, context: ToolExecutionContext) -> None:
        if self._requires_active and context.mode != "active":
            raise ToolConfigError("fake-tool requires active mode")

    def build_command(self, context: ToolExecutionContext) -> list[str]:
        return ["fake-tool-binary-that-does-not-exist", "-u", context.target_url]

    def parse(self, raw_output: str) -> list[dict]:
        return [{"line": l} for l in raw_output.splitlines() if l.strip()]

    def normalize(self, parsed, context, tool_version):
        return [
            NormalizedFinding(
                tool_name=self.name,
                tool_version=tool_version,
                title="fake finding",
                severity="info",
                matched_endpoint=context.target_url,
                raw_output=r["line"],
            )
            for r in parsed
        ]


async def _fake_runner_success(args: list[str], timeout: float) -> tuple[int, str, str]:
    return 0, "finding one\nfinding two\n", ""


async def _fake_runner_timeout(args: list[str], timeout: float) -> tuple[int, str, str]:
    raise ToolTimeoutError("simulated timeout")


@pytest.mark.asyncio
async def test_run_enforces_scope_before_anything_else():
    scope = ScopeEngine(allow=["app.example.com"])
    adapter = _FakeAdapter(runner=_fake_runner_success, force_available=True)
    context = ToolExecutionContext(target_url="https://evil.com/", scope=scope)

    with pytest.raises(ScopeViolation):
        await adapter.run(context)


@pytest.mark.asyncio
async def test_run_raises_tool_unavailable_when_binary_missing():
    scope = ScopeEngine(allow=["app.example.com"])
    adapter = _FakeAdapter(runner=_fake_runner_success, force_available=False)
    context = ToolExecutionContext(target_url="https://app.example.com/", scope=scope)

    with pytest.raises(ToolUnavailable):
        await adapter.run(context)


@pytest.mark.asyncio
async def test_run_raises_tool_config_error_when_validate_config_fails():
    scope = ScopeEngine(allow=["app.example.com"])
    adapter = _FakeAdapter(runner=_fake_runner_success, force_available=True, requires_active=True)
    context = ToolExecutionContext(target_url="https://app.example.com/", scope=scope, mode="safe")

    with pytest.raises(ToolConfigError):
        await adapter.run(context)


@pytest.mark.asyncio
async def test_run_full_happy_path_produces_normalized_findings():
    scope = ScopeEngine(allow=["app.example.com"])
    adapter = _FakeAdapter(runner=_fake_runner_success, force_available=True)
    context = ToolExecutionContext(target_url="https://app.example.com/", scope=scope)

    findings = await adapter.run(context)

    assert len(findings) == 2
    assert findings[0].tool_name == "fake-tool"
    assert findings[0].tool_version == "1.2.3"
    assert findings[0].matched_endpoint == "https://app.example.com/"


@pytest.mark.asyncio
async def test_run_propagates_timeout():
    scope = ScopeEngine(allow=["app.example.com"])
    adapter = _FakeAdapter(runner=_fake_runner_timeout, force_available=True)
    context = ToolExecutionContext(target_url="https://app.example.com/", scope=scope)

    with pytest.raises(ToolTimeoutError):
        await adapter.run(context)


@pytest.mark.asyncio
async def test_cleanup_default_is_noop():
    adapter = _FakeAdapter(force_available=True)
    await adapter.cleanup()  # should not raise
