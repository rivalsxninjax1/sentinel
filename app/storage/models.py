"""SQLAlchemy models — Phase 1 subset.

Only `Target` and `Scan` land in Phase 1 (enough to support the scan lifecycle).
The remaining entities from docs/architecture.md §8 (hosts, endpoints, parameters,
forms, technologies, authentication_contexts, tool_runs, tests, findings, evidence)
are added in the phases that actually produce that data (Phase 2+), so we don't create
empty tables years before anything writes to them.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, ForeignKey, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _now() -> datetime:
    return datetime.now(UTC)


def _uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scope_definition_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    scans: Mapped[list[Scan]] = relationship(back_populates="target")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), nullable=False)
    mode: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="created")
    stopped_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    config_snapshot_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    target: Mapped[Target] = relationship(back_populates="scans")


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    first_seen_scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    endpoints: Mapped[list[Endpoint]] = relationship(back_populates="host")
    technologies: Mapped[list[Technology]] = relationship(back_populates="host")
    javascript_assets: Mapped[list[JavaScriptAsset]] = relationship(back_populates="host")


class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"), nullable=False)
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    method: Mapped[str] = mapped_column(String(16), nullable=False, default="GET")
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="crawl")
    status_code: Mapped[int | None] = mapped_column(nullable=True)
    first_seen_scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    host: Mapped[Host] = relationship(back_populates="endpoints")
    parameters: Mapped[list[Parameter]] = relationship(back_populates="endpoint")
    forms: Mapped[list[Form]] = relationship(back_populates="endpoint")


class Parameter(Base):
    __tablename__ = "parameters"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    endpoint_id: Mapped[str] = mapped_column(ForeignKey("endpoints.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    location: Mapped[str] = mapped_column(String(16), nullable=False)  # query | form
    observed_value: Mapped[str] = mapped_column(String(1024), nullable=True, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    endpoint: Mapped[Endpoint] = relationship(back_populates="parameters")


class Form(Base):
    __tablename__ = "forms"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    endpoint_id: Mapped[str] = mapped_column(ForeignKey("endpoints.id"), nullable=False)
    method: Mapped[str] = mapped_column(String(16), nullable=False)
    action: Mapped[str] = mapped_column(String(2048), nullable=False)
    fields_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    endpoint: Mapped[Endpoint] = relationship(back_populates="forms")


class Technology(Base):
    __tablename__ = "technologies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    host: Mapped[Host] = relationship(back_populates="technologies")


class JavaScriptAsset(Base):
    __tablename__ = "javascript_assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    has_source_map: Mapped[bool] = mapped_column(nullable=False, default=False)
    source_map_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    first_seen_scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    host: Mapped[Host] = relationship(back_populates="javascript_assets")


class Classification(Base):
    __tablename__ = "classifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False)
    endpoint_id: Mapped[str] = mapped_column(ForeignKey("endpoints.id"), nullable=False)
    parameter_id: Mapped[str | None] = mapped_column(ForeignKey("parameters.id"), nullable=True)
    classification: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_score: Mapped[int] = mapped_column(nullable=False)
    recommended_tests_json: Mapped[list] = mapped_column(JSON, nullable=False)
    reason: Mapped[str] = mapped_column(String(1024), nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False)  # "ai" | "fallback"
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Test(Base):
    __tablename__ = "tests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False)
    endpoint_id: Mapped[str] = mapped_column(ForeignKey("endpoints.id"), nullable=False)
    parameter_id: Mapped[str | None] = mapped_column(ForeignKey("parameters.id"), nullable=True)
    vulnerability_class: Mapped[str] = mapped_column(String(64), nullable=False)
    scanner_name: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="completed")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False)
    test_id: Mapped[str] = mapped_column(ForeignKey("tests.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    vulnerability_class: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    # info | low | medium | high | confirmed — NEVER set to "confirmed" automatically
    # anywhere in this codebase. See docs/architecture.md §22 and
    # app/verification/engine.py's hard cap at "high".
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="low")
    # unverified | verified | false_positive | needs_manual_review — set by
    # app/verification/engine.py (Phase 9). Defaults to "unverified" for any
    # Finding created before `scan verify` runs.
    verification_status: Mapped[str] = mapped_column(String(24), nullable=False, default="unverified")
    matched_endpoint: Mapped[str] = mapped_column(String(2048), nullable=False)
    description: Mapped[str] = mapped_column(String(2048), nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)  # "raw_output" | "request" | "response"
    content: Mapped[str] = mapped_column(String(4000), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Correlation(Base):
    __tablename__ = "correlations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False)
    endpoint_id: Mapped[str] = mapped_column(ForeignKey("endpoints.id"), nullable=False)
    vulnerability_class: Mapped[str] = mapped_column(String(64), nullable=False)
    finding_ids_json: Mapped[list] = mapped_column(JSON, nullable=False)
    tool_names_json: Mapped[list] = mapped_column(JSON, nullable=False)
    combined_confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    # "agreement" | "conflicting_evidence" | "insufficient_correlation"
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    rationale: Mapped[str] = mapped_column(String(1024), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
