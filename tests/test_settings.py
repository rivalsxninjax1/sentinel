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
