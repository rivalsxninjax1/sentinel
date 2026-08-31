import pytest

from app.scope.engine import ScopeEngine, ScopeViolation


def test_exact_host_allowed():
    engine = ScopeEngine(allow=["app.example.com"])
    decision = engine.check("https://app.example.com/api/users")
    assert decision.allowed


def test_wildcard_subdomain_allowed():
    engine = ScopeEngine(allow=["*.example.com"])
    assert engine.check("https://app.example.com/x").allowed
    assert engine.check("https://api.example.com/x").allowed
    assert engine.check("https://example.com/x").allowed  # bare domain also matches


def test_url_prefix_rule():
    engine = ScopeEngine(allow=["https://app.example.com/api"])
    assert engine.check("https://app.example.com/api/users").allowed
    assert not engine.check("https://app.example.com/admin").allowed


def test_deny_overrides_allow():
    engine = ScopeEngine(allow=["*.example.com"], deny=["admin.example.com"])
    assert engine.check("https://app.example.com/x").allowed
    assert not engine.check("https://admin.example.com/x").allowed


def test_out_of_scope_host_rejected():
    engine = ScopeEngine(allow=["app.example.com"])
    decision = engine.check("https://evil.com/x")
    assert not decision.allowed


def test_empty_allow_list_refuses_everything():
    engine = ScopeEngine(allow=[])
    decision = engine.check("https://anything.com")
    assert not decision.allowed


def test_enforce_raises_on_violation():
    engine = ScopeEngine(allow=["app.example.com"])
    with pytest.raises(ScopeViolation):
        engine.enforce("https://evil.com")


def test_enforce_passes_silently_when_in_scope():
    engine = ScopeEngine(allow=["app.example.com"])
    engine.enforce("https://app.example.com/anything")  # should not raise


def test_invalid_url_rejected():
    engine = ScopeEngine(allow=["app.example.com"])
    decision = engine.check("not-a-url")
    assert not decision.allowed
