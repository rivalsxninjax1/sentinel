import pytest

from app.scope.engine import ScopeEngine
from app.tools.base import ToolConfigError, ToolExecutionContext
from app.tools.sqlmap import SqlmapAdapter


def test_requires_active_mode():
    adapter = SqlmapAdapter()
    scope = ScopeEngine(allow=["app.example.com"])
    context = ToolExecutionContext(target_url="https://app.example.com/", scope=scope, mode="safe")
    with pytest.raises(ToolConfigError):
        adapter.validate_config(context)


def test_build_command_never_includes_destructive_flags():
    adapter = SqlmapAdapter()
    scope = ScopeEngine(allow=["app.example.com"])
    context = ToolExecutionContext(target_url="https://app.example.com/", scope=scope, mode="active")
    command = adapter.build_command(context)
    forbidden = {"--dump", "--dump-all", "--os-shell", "--os-pwn", "--sql-shell"}
    assert forbidden.isdisjoint(set(command))


def test_parse_matches_vulnerable_and_dbms_markers():
    adapter = SqlmapAdapter()
    raw = (
        "sqlmap identified the following injection point(s)\n"
        "Parameter: id (GET)\n"
        "    Type: boolean-based blind\n"
        "id is vulnerable\n"
        "the back-end DBMS is MySQL\n"
    )
    parsed = adapter.parse(raw)
    assert len(parsed) == 2


def test_normalize_marks_low_confidence_high_severity():
    adapter = SqlmapAdapter()
    scope = ScopeEngine(allow=["app.example.com"])
    context = ToolExecutionContext(target_url="https://app.example.com/", scope=scope, mode="active")
    findings = adapter.normalize([{"line": "id is vulnerable"}], context, "1.8")

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].metadata["confidence"] == "low"
