import json

import pytest

from app.scope.engine import ScopeEngine
from app.tools.base import ToolConfigError, ToolExecutionContext
from app.tools.ffuf import FfufAdapter

_SAMPLE_OUTPUT = json.dumps(
    {
        "results": [
            {"url": "https://app.example.com/admin", "status": 200, "length": 512, "words": 40, "lines": 20},
            {"url": "https://app.example.com/backup", "status": 403, "length": 10, "words": 2, "lines": 1},
        ]
    }
)


def test_validate_config_requires_wordlist():
    adapter = FfufAdapter()
    scope = ScopeEngine(allow=["app.example.com"])
    context = ToolExecutionContext(target_url="https://app.example.com/", scope=scope, mode="safe")
    with pytest.raises(ToolConfigError):
        adapter.validate_config(context)


def test_validate_config_rejects_passive_mode():
    adapter = FfufAdapter()
    scope = ScopeEngine(allow=["app.example.com"])
    context = ToolExecutionContext(
        target_url="https://app.example.com/", scope=scope, mode="passive",
        extra={"wordlist": "/tmp/wordlist.txt"},
    )
    with pytest.raises(ToolConfigError):
        adapter.validate_config(context)


def test_validate_config_passes_with_wordlist_and_safe_mode():
    adapter = FfufAdapter()
    scope = ScopeEngine(allow=["app.example.com"])
    context = ToolExecutionContext(
        target_url="https://app.example.com/", scope=scope, mode="safe",
        extra={"wordlist": "/tmp/wordlist.txt"},
    )
    adapter.validate_config(context)  # should not raise


def test_build_command_fuzzes_path_and_uses_wordlist():
    adapter = FfufAdapter()
    scope = ScopeEngine(allow=["app.example.com"])
    context = ToolExecutionContext(
        target_url="https://app.example.com/", scope=scope, mode="safe",
        extra={"wordlist": "/tmp/wordlist.txt"},
    )
    command = adapter.build_command(context)
    assert "https://app.example.com/FUZZ" in command
    assert "/tmp/wordlist.txt" in command


def test_parse_extracts_results_array():
    adapter = FfufAdapter()
    parsed = adapter.parse(_SAMPLE_OUTPUT)
    assert len(parsed) == 2


def test_parse_handles_empty_output():
    adapter = FfufAdapter()
    assert adapter.parse("") == []


def test_normalize_maps_fields():
    adapter = FfufAdapter()
    scope = ScopeEngine(allow=["app.example.com"])
    context = ToolExecutionContext(
        target_url="https://app.example.com/", scope=scope, mode="safe",
        extra={"wordlist": "/tmp/wordlist.txt"},
    )
    parsed = adapter.parse(_SAMPLE_OUTPUT)
    findings = adapter.normalize(parsed, context, "2.1.0")

    assert len(findings) == 2
    assert findings[0].matched_endpoint == "https://app.example.com/admin"
    assert findings[0].metadata["status"] == 200


@pytest.mark.asyncio
async def test_full_run_with_injected_runner(monkeypatch):
    import shutil

    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/ffuf" if name == "ffuf" else None)

    async def fake_runner(args, timeout):
        if "-V" in args:
            return 0, "ffuf v2.1.0\n", ""
        return 0, _SAMPLE_OUTPUT, ""

    adapter = FfufAdapter(runner=fake_runner)
    scope = ScopeEngine(allow=["app.example.com"])
    context = ToolExecutionContext(
        target_url="https://app.example.com/", scope=scope, mode="safe",
        extra={"wordlist": "/tmp/wordlist.txt"},
    )

    findings = await adapter.run(context)
    assert len(findings) == 2
