import json

import pytest

from app.scope.engine import ScopeEngine
from app.tools.base import ToolExecutionContext
from app.tools.httpx import HttpxAdapter

_SAMPLE_LINE = json.dumps(
    {
        "url": "https://app.example.com/",
        "status_code": 200,
        "title": "Example App",
        "webserver": "nginx",
        "tech": ["nginx", "React"],
        "content_length": 1234,
    }
)


async def _fake_runner(args: list[str], timeout: float) -> tuple[int, str, str]:
    if "-version" in args:
        return 0, "httpx v1.6.0\n", ""
    return 0, _SAMPLE_LINE + "\n", ""


def test_build_command_includes_rate_limit_and_timeout():
    adapter = HttpxAdapter()
    scope = ScopeEngine(allow=["app.example.com"])
    context = ToolExecutionContext(
        target_url="https://app.example.com/", scope=scope, requests_per_second=10, timeout_seconds=30
    )
    command = adapter.build_command(context)
    assert "-rate-limit" in command
    assert command[command.index("-rate-limit") + 1] == "10"
    assert "-json" in command


def test_parse_handles_json_lines_and_skips_invalid():
    adapter = HttpxAdapter()
    raw = _SAMPLE_LINE + "\nnot valid json\n\n"
    parsed = adapter.parse(raw)
    assert len(parsed) == 1
    assert parsed[0]["status_code"] == 200


def test_normalize_maps_fields_correctly():
    adapter = HttpxAdapter()
    scope = ScopeEngine(allow=["app.example.com"])
    context = ToolExecutionContext(target_url="https://app.example.com/", scope=scope)
    parsed = adapter.parse(_SAMPLE_LINE)
    findings = adapter.normalize(parsed, context, "1.6.0")

    assert len(findings) == 1
    f = findings[0]
    assert f.tool_name == "httpx"
    assert f.severity == "info"
    assert f.matched_endpoint == "https://app.example.com/"
    assert f.metadata["technologies"] == ["nginx", "React"]


@pytest.mark.asyncio
async def test_full_run_with_injected_runner(monkeypatch):
    import shutil

    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/httpx" if name == "httpx" else None)

    adapter = HttpxAdapter(runner=_fake_runner)
    scope = ScopeEngine(allow=["app.example.com"])
    context = ToolExecutionContext(target_url="https://app.example.com/", scope=scope)

    findings = await adapter.run(context)

    assert len(findings) == 1
    assert findings[0].tool_version == "httpx v1.6.0"
