import pytest

from app.scope.engine import ScopeEngine
from app.tools.base import ToolConfigError, ToolExecutionContext
from app.tools.xsstrike import XSStrikeAdapter


def test_requires_active_mode():
    adapter = XSStrikeAdapter()
    scope = ScopeEngine(allow=["app.example.com"])
    context = ToolExecutionContext(target_url="https://app.example.com/", scope=scope, mode="safe")
    with pytest.raises(ToolConfigError):
        adapter.validate_config(context)


def test_allows_active_mode():
    adapter = XSStrikeAdapter()
    scope = ScopeEngine(allow=["app.example.com"])
    context = ToolExecutionContext(target_url="https://app.example.com/", scope=scope, mode="active")
    adapter.validate_config(context)  # should not raise


def test_parse_matches_vulnerable_marker_lines():
    adapter = XSStrikeAdapter()
    raw = (
        "Scanning https://app.example.com/search\n"
        "[!] Reflection found\n"
        "search is vulnerable\n"
        "Payload: <script>alert(1)</script>\n"
    )
    parsed = adapter.parse(raw)
    assert len(parsed) == 1
    assert "vulnerable" in parsed[0]["line"].lower()


def test_parse_returns_empty_when_no_marker_present():
    adapter = XSStrikeAdapter()
    raw = "Scanning https://app.example.com/search\nNo vulnerabilities found.\n"
    assert adapter.parse(raw) == []


def test_normalize_marks_low_confidence():
    adapter = XSStrikeAdapter()
    scope = ScopeEngine(allow=["app.example.com"])
    context = ToolExecutionContext(target_url="https://app.example.com/", scope=scope, mode="active")
    findings = adapter.normalize([{"line": "search is vulnerable"}], context, "3.1.5")

    assert len(findings) == 1
    assert findings[0].metadata["confidence"] == "low"
    assert "unverified" in findings[0].title.lower()
