"""SENTINEL configuration.

Loads settings from a YAML file plus environment variable overrides. Secrets (e.g. an
Ollama API key, if one is ever used, or auth-context credentials) must come from
environment variables / a local secret store — never from the YAML file itself.

Phase 1 scope: target/scope, scan mode, rate limits, storage path, logging level.
The `llm` section is accepted here (schema only) so Phase 4 doesn't need a config
migration, but it is not used by anything yet.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ScanMode(str, Enum):
    PASSIVE = "passive"
    SAFE = "safe"
    ACTIVE = "active"


class ScopeConfig(BaseModel):
    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)

    @field_validator("allow")
    @classmethod
    def must_have_at_least_one_allow_entry(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError(
                "scope.allow must contain at least one entry — SENTINEL refuses to "
                "run with an unbounded (empty-allow-list) scope."
            )
        return v


class AuthContextEntry(BaseModel):
    """Declares a named identity for cross-identity authorization testing
    (docs/architecture.md §25/§26). `env_var` names an environment variable that
    must hold the actual credential value at scan time — the value itself is never
    written here, never persisted to the database, and never logged."""

    label: str
    kind: str = Field(pattern="^(header|cookie)$")
    name: str
    env_var: str


class TargetConfig(BaseModel):
    name: str
    scope: ScopeConfig
    seed_urls: list[str] = Field(default_factory=list)
    auth_contexts: list[AuthContextEntry] = Field(default_factory=list)

    @field_validator("seed_urls")
    @classmethod
    def seed_urls_must_be_absolute(cls, v: list[str]) -> list[str]:
        for url in v:
            if not (url.startswith("http://") or url.startswith("https://")):
                raise ValueError(f"seed_urls entries must be absolute URLs, got: {url!r}")
        return v


class RateLimitConfig(BaseModel):
    requests_per_second: float = 5.0
    concurrency: int = 3
    max_requests: int = 10_000
    max_crawl_depth: int = 5


class ScanConfig(BaseModel):
    mode: ScanMode = ScanMode.PASSIVE


class LLMConfig(BaseModel):
    """Accepted now, unused until Phase 4."""

    provider: str = "ollama"
    model: str = "unset"
    base_url: str = "http://localhost:11434"
    temperature: float = 0.0


class SentinelConfig(BaseSettings):
    """Top-level configuration object.

    Precedence: environment variables (prefixed SENTINEL_) override values loaded from
    the YAML file. Nothing here should ever hold a literal secret; auth-context
    credentials are referenced by name and resolved from the environment at use time
    (Phase 2+), never stored in this object or serialized to disk.
    """

    model_config = SettingsConfigDict(env_prefix="SENTINEL_", env_nested_delimiter="__")

    target: TargetConfig
    scan: ScanConfig = Field(default_factory=ScanConfig)
    limits: RateLimitConfig = Field(default_factory=RateLimitConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)

    storage_path: str = "sentinel.db"
    log_level: str = "INFO"

    @classmethod
    def from_yaml(cls, path: str | Path, **env_overrides: Any) -> SentinelConfig:
        """Load config from a YAML file, then apply env-var overrides via BaseSettings."""
        yaml_path = Path(path)
        if not yaml_path.is_file():
            raise FileNotFoundError(f"Config file not found: {yaml_path}")
        with yaml_path.open("r", encoding="utf-8") as f:
            raw: dict[str, Any] = yaml.safe_load(f) or {}
        return cls(**{**raw, **env_overrides})
