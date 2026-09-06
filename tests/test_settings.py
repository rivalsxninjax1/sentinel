import pytest
from pydantic import ValidationError

from app.config.settings import SentinelConfig


def test_loads_example_config():
    cfg = SentinelConfig.from_yaml("configs/example.yaml")
    assert cfg.target.name == "example-authorized-target"
    assert cfg.scan.mode.value == "passive"
    assert cfg.limits.requests_per_second == 5


def test_rejects_empty_allow_list():
    with pytest.raises(ValidationError):
        SentinelConfig(target={"name": "x", "scope": {"allow": [], "deny": []}})


def test_env_override(monkeypatch):
    monkeypatch.setenv("SENTINEL_STORAGE_PATH", "/tmp/override.db")
    cfg = SentinelConfig.from_yaml("configs/example.yaml")
    assert cfg.storage_path == "/tmp/override.db"


def test_missing_config_file_raises():
    with pytest.raises(FileNotFoundError):
        SentinelConfig.from_yaml("configs/does-not-exist.yaml")


def test_example_config_has_no_auth_contexts_by_default():
    cfg = SentinelConfig.from_yaml("configs/example.yaml")
    assert cfg.target.auth_contexts == []


def test_parses_auth_contexts():
    cfg = SentinelConfig(
        target={
            "name": "x",
            "scope": {"allow": ["app.example.com"], "deny": []},
            "auth_contexts": [
                {"label": "user_a", "kind": "header", "name": "Authorization", "env_var": "A"},
                {"label": "user_b", "kind": "cookie", "name": "session", "env_var": "B"},
            ],
        }
    )
    assert len(cfg.target.auth_contexts) == 2
    assert cfg.target.auth_contexts[0].label == "user_a"
    assert cfg.target.auth_contexts[1].kind == "cookie"


def test_rejects_invalid_auth_context_kind():
    with pytest.raises(ValidationError):
        SentinelConfig(
            target={
                "name": "x",
                "scope": {"allow": ["app.example.com"], "deny": []},
                "auth_contexts": [
                    {"label": "user_a", "kind": "bogus", "name": "Authorization", "env_var": "A"}
                ],
            }
        )
