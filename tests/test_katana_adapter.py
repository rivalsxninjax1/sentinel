import json

import pytest

from app.scope.engine import ScopeEngine
from app.tools.base import ToolExecutionContext
from app.tools.katana import KatanaAdapter

_SAMPLE_LINE = json.dumps(
    {
        "timestamp": "2026-01-01T00:00:00Z",
        "request": {"method": "GET", "endpoint": "https://app.example.com/dashboard", "source": "body"},
        "response": {"status_code": 200},
    }
)


def test_build_command_includes_depth():
    adapter = KatanaAdapter()
    scope = ScopeEngine(allow=["app.example.com"])
    context = ToolExecutionContext(
        target_url="https://app.example.com/", scope=scope, extra={"max_depth": 5}
    )
    command = adapter.build_command(context)
    assert "-depth" in command
    assert command[command.index("-depth") + 1] == "5"


def test_parse_and_normalize():
    adapter = KatanaAdapter()
    scope = ScopeEngine(allow=["app.example.com"])
    context = ToolExecutionContext(target_url="https://app.example.com/", scope=scope)

    parsed = adapter.parse(_SAMPLE_LINE)
    findings = adapter.normalize(parsed, context, "1.0.0")

    assert len(findings) == 1
    f = findings[0]
    assert f.matched_endpoint == "https://app.example.com/dashboard"
    assert f.metadata["method"] == "GET"
    assert f.metadata["status_code"] == 200


@pytest.mark.asyncio
async def test_full_run_with_injected_runner(monkeypatch):
    import shutil

    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/katana" if name == "katana" else None)

    async def fake_runner(args, timeout):
        if "-version" in args:
            return 0, "katana v1.0.0\n", ""
        return 0, _SAMPLE_LINE + "\n", ""

    adapter = KatanaAdapter(runner=fake_runner)
    scope = ScopeEngine(allow=["app.example.com"])
    context = ToolExecutionContext(target_url="https://app.example.com/", scope=scope)

    findings = await adapter.run(context)
    assert len(findings) == 1
