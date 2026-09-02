import json

import pytest

from app.scope.engine import ScopeEngine
from app.tools.base import ToolConfigError, ToolExecutionContext
from app.tools.nuclei import NucleiAdapter

_SAMPLE_LINE = json.dumps(
    {
        "template-id": "exposed-panel-generic",
        "info": {"name": "Exposed Admin Panel", "severity": "medium", "tags": ["panel", "exposure"]},
        "matched-at": "https://app.example.com/admin",
        "type": "http",
    }
)


def test_validate_config_rejects_passive_mode():
    adapter = NucleiAdapter()
    scope = ScopeEngine(allow=["app.example.com"])
    context = ToolExecutionContext(target_url="https://app.example.com/", scope=scope, mode="passive")
    with pytest.raises(ToolConfigError):
        adapter.validate_config(context)


def test_validate_config_allows_safe_and_active():
    adapter = NucleiAdapter()
    scope = ScopeEngine(allow=["app.example.com"])
    for mode in ("safe", "active"):
        context = ToolExecutionContext(target_url="https://app.example.com/", scope=scope, mode=mode)
        adapter.validate_config(context)  # should not raise


def test_safe_mode_restricts_severity():
    adapter = NucleiAdapter()
    scope = ScopeEngine(allow=["app.example.com"])
    context = ToolExecutionContext(target_url="https://app.example.com/", scope=scope, mode="safe")
    command = adapter.build_command(context)
    assert "-severity" in command
    assert command[command.index("-severity") + 1] == "info,low"


def test_active_mode_does_not_restrict_severity():
    adapter = NucleiAdapter()
    scope = ScopeEngine(allow=["app.example.com"])
    context = ToolExecutionContext(target_url="https://app.example.com/", scope=scope, mode="active")
    command = adapter.build_command(context)
    assert "-severity" not in command


def test_parse_and_normalize():
    adapter = NucleiAdapter()
    scope = ScopeEngine(allow=["app.example.com"])
    context = ToolExecutionContext(target_url="https://app.example.com/", scope=scope, mode="safe")

    parsed = adapter.parse(_SAMPLE_LINE)
    findings = adapter.normalize(parsed, context, "3.2.0")

    assert len(findings) == 1
    f = findings[0]
    assert f.title == "Exposed Admin Panel"
    assert f.severity == "medium"
    assert f.matched_endpoint == "https://app.example.com/admin"
    assert f.metadata["template_id"] == "exposed-panel-generic"


@pytest.mark.asyncio
async def test_full_run_with_injected_runner(monkeypatch):
    import shutil

    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/nuclei" if name == "nuclei" else None)

    async def fake_runner(args, timeout):
        if "-version" in args:
            return 0, "nuclei v3.2.0\n", ""
        return 0, _SAMPLE_LINE + "\n", ""

    adapter = NucleiAdapter(runner=fake_runner)
    scope = ScopeEngine(allow=["app.example.com"])
    context = ToolExecutionContext(target_url="https://app.example.com/", scope=scope, mode="safe")

    findings = await adapter.run(context)
    assert len(findings) == 1
