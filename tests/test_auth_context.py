import pytest

from app.core.auth_context import (
    AuthContextConfig,
    AuthenticationContext,
    MissingCredentialError,
    build_contexts,
)


def test_header_context_applies_header(monkeypatch):
    monkeypatch.setenv("SENTINEL_TEST_TOKEN", "Bearer abc123")
    ctx = AuthenticationContext(label="user_a", kind="header", name="Authorization", env_var="SENTINEL_TEST_TOKEN")
    kwargs = ctx.apply({})
    assert kwargs["headers"]["Authorization"] == "Bearer abc123"


def test_cookie_context_applies_cookie(monkeypatch):
    monkeypatch.setenv("SENTINEL_TEST_SESSION", "sess-xyz")
    ctx = AuthenticationContext(label="user_b", kind="cookie", name="session", env_var="SENTINEL_TEST_SESSION")
    kwargs = ctx.apply({})
    assert kwargs["cookies"]["session"] == "sess-xyz"


def test_missing_env_var_raises(monkeypatch):
    monkeypatch.delenv("SENTINEL_TEST_MISSING", raising=False)
    ctx = AuthenticationContext(label="user_a", kind="header", name="Authorization", env_var="SENTINEL_TEST_MISSING")
    with pytest.raises(MissingCredentialError):
        ctx.resolve_value()


def test_apply_does_not_mutate_input_kwargs(monkeypatch):
    monkeypatch.setenv("SENTINEL_TEST_TOKEN2", "value")
    ctx = AuthenticationContext(label="a", kind="header", name="X-Test", env_var="SENTINEL_TEST_TOKEN2")
    original = {"headers": {"Existing": "1"}}
    result = ctx.apply(original)
    assert "X-Test" not in original["headers"]
    assert result["headers"]["Existing"] == "1"
    assert result["headers"]["X-Test"] == "value"


def test_unknown_kind_raises_value_error(monkeypatch):
    monkeypatch.setenv("SENTINEL_TEST_TOKEN3", "value")
    ctx = AuthenticationContext(label="a", kind="bogus", name="x", env_var="SENTINEL_TEST_TOKEN3")
    with pytest.raises(ValueError):
        ctx.apply({})


def test_build_contexts_converts_configs():
    configs = [
        AuthContextConfig(label="user_a", kind="header", name="Authorization", env_var="A"),
        AuthContextConfig(label="user_b", kind="cookie", name="session", env_var="B"),
    ]
    contexts = build_contexts(configs)
    assert len(contexts) == 2
    assert contexts[0].label == "user_a"
    assert contexts[1].kind == "cookie"
