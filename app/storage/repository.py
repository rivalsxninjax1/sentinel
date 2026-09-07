"""Repository layer — the only thing outside app/storage/ that should touch the DB.

Keeps SQLAlchemy specifics out of core/CLI code, so the underlying engine can change
later without touching callers (see docs/architecture.md §8).
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.storage.models import (
    Classification,
    Correlation,
    Endpoint,
    Evidence,
    Finding,
    Form,
    Host,
    JavaScriptAsset,
    Parameter,
    Scan,
    Target,
    Technology,
    Test,
)


class TargetRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, name: str, scope_definition: dict) -> Target:
        target = Target(name=name, scope_definition_json=scope_definition)
        self._session.add(target)
        await self._session.flush()
        return target

    async def get(self, target_id: str) -> Target | None:
        return await self._session.get(Target, target_id)

    async def get_by_name(self, name: str) -> Target | None:
        result = await self._session.execute(select(Target).where(Target.name == name))
        return result.scalar_one_or_none()


class ScanRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, target_id: str, mode: str, config_snapshot: dict) -> Scan:
        scan = Scan(
            target_id=target_id,
            mode=mode,
            status="created",
            config_snapshot_json=config_snapshot,
        )
        self._session.add(scan)
        await self._session.flush()
        return scan

    async def get(self, scan_id: str) -> Scan | None:
        return await self._session.get(Scan, scan_id)

    async def update_status(
        self, scan_id: str, status: str, stopped_reason: str | None = None
    ) -> Scan | None:
        scan = await self._session.get(Scan, scan_id)
        if scan is None:
            return None
        scan.status = status
        if stopped_reason is not None:
            scan.stopped_reason = stopped_reason
        await self._session.flush()
        return scan


class AttackSurfaceRepository:
    """Persists crawler/discovery output. Dedup logic here is intentionally simple
    (exact hostname / path+method match) — Phase 2 scope. Cross-scan merge/diffing
    for regression detection is Phase 12."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_or_create_host(self, target_id: str, hostname: str, scan_id: str) -> Host:
        result = await self._session.execute(
            select(Host).where(Host.target_id == target_id, Host.hostname == hostname)
        )
        host = result.scalar_one_or_none()
        if host is not None:
            return host
        host = Host(target_id=target_id, hostname=hostname, first_seen_scan_id=scan_id)
        self._session.add(host)
        await self._session.flush()
        return host

    async def get_or_create_endpoint(
        self,
        host_id: str,
        path: str,
        method: str,
        scan_id: str,
        source: str = "crawl",
        status_code: int | None = None,
    ) -> Endpoint:
        result = await self._session.execute(
            select(Endpoint).where(
                Endpoint.host_id == host_id,
                Endpoint.path == path,
                Endpoint.method == method,
            )
        )
        endpoint = result.scalar_one_or_none()
        if endpoint is not None:
            if status_code is not None:
                endpoint.status_code = status_code
                await self._session.flush()
            return endpoint
        endpoint = Endpoint(
            host_id=host_id,
            path=path,
            method=method,
            source=source,
            status_code=status_code,
            first_seen_scan_id=scan_id,
        )
        self._session.add(endpoint)
        await self._session.flush()
        return endpoint

    async def add_parameter(
        self, endpoint_id: str, name: str, location: str, observed_value: str = ""
    ) -> Parameter:
        result = await self._session.execute(
            select(Parameter).where(
                Parameter.endpoint_id == endpoint_id,
                Parameter.name == name,
                Parameter.location == location,
            )
        )
        existing = result.scalar_one_or_none()
        if existing is not None:
            return existing
        parameter = Parameter(
            endpoint_id=endpoint_id, name=name, location=location, observed_value=observed_value
        )
        self._session.add(parameter)
        await self._session.flush()
        return parameter

    async def add_form(
        self, endpoint_id: str, method: str, action: str, fields: list[dict]
    ) -> Form:
        form = Form(endpoint_id=endpoint_id, method=method, action=action, fields_json=fields)
        self._session.add(form)
        await self._session.flush()
        return form

    async def add_technology(
        self, host_id: str, name: str, version: str | None, confidence: str, source: str
    ) -> Technology:
        result = await self._session.execute(
            select(Technology).where(Technology.host_id == host_id, Technology.name == name)
        )
        existing = result.scalar_one_or_none()
        if existing is not None:
            return existing
        technology = Technology(
            host_id=host_id, name=name, version=version, confidence=confidence, source=source
        )
        self._session.add(technology)
        await self._session.flush()
        return technology

    async def list_endpoints_for_host(self, host_id: str) -> list[Endpoint]:
        result = await self._session.execute(
            select(Endpoint)
            .where(Endpoint.host_id == host_id)
            .options(selectinload(Endpoint.parameters), selectinload(Endpoint.forms))
        )
        return list(result.scalars().all())

    async def list_hosts_for_target(self, target_id: str) -> list[Host]:
        result = await self._session.execute(select(Host).where(Host.target_id == target_id))
        return list(result.scalars().all())

    async def list_technologies_for_host(self, host_id: str) -> list[Technology]:
        result = await self._session.execute(
            select(Technology).where(Technology.host_id == host_id)
        )
        return list(result.scalars().all())

    async def add_javascript_asset(
        self,
        host_id: str,
        url: str,
        has_source_map: bool,
        source_map_url: str | None,
        scan_id: str,
    ) -> JavaScriptAsset:
        result = await self._session.execute(
            select(JavaScriptAsset).where(
                JavaScriptAsset.host_id == host_id, JavaScriptAsset.url == url
            )
        )
        existing = result.scalar_one_or_none()
        if existing is not None:
            if has_source_map and not existing.has_source_map:
                existing.has_source_map = True
                existing.source_map_url = source_map_url
                await self._session.flush()
            return existing
        asset = JavaScriptAsset(
            host_id=host_id,
            url=url,
            has_source_map=has_source_map,
            source_map_url=source_map_url,
            first_seen_scan_id=scan_id,
        )
        self._session.add(asset)
        await self._session.flush()
        return asset


class IntelligenceRepository:
    """Persists SecurityReasoningEngine output (both AI-sourced and fallback
    outcomes — see app/intelligence/reasoning.py). Recording fallback outcomes too
    (not just successful AI ones) keeps an honest record of what was and wasn't
    actually reasoned about by the AI for a given scan."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add_classification(
        self,
        scan_id: str,
        endpoint_id: str,
        classification: str,
        risk_score: int,
        recommended_tests: list[str],
        reason: str,
        source: str,
        parameter_id: str | None = None,
    ) -> Classification:
        record = Classification(
            scan_id=scan_id,
            endpoint_id=endpoint_id,
            parameter_id=parameter_id,
            classification=classification,
            risk_score=risk_score,
            recommended_tests_json=recommended_tests,
            reason=reason,
            source=source,
        )
        self._session.add(record)
        await self._session.flush()
        return record

    async def list_for_scan(self, scan_id: str) -> list[Classification]:
        result = await self._session.execute(
            select(Classification).where(Classification.scan_id == scan_id)
        )
        return list(result.scalars().all())


class FindingsRepository:
    """Persists Test/Finding/Evidence records produced by the TestOrchestrator
    (app/core/test_orchestrator.py). Every NormalizedFinding becomes exactly one
    Finding row plus one Evidence row (the raw_output) — see docs/architecture.md
    §39 (every finding must carry evidence)."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create_test(
        self,
        scan_id: str,
        endpoint_id: str,
        vulnerability_class: str,
        scanner_name: str,
        parameter_id: str | None = None,
        status: str = "completed",
    ) -> Test:
        test = Test(
            scan_id=scan_id,
            endpoint_id=endpoint_id,
            parameter_id=parameter_id,
            vulnerability_class=vulnerability_class,
            scanner_name=scanner_name,
            status=status,
        )
        self._session.add(test)
        await self._session.flush()
        return test

    async def create_finding_from_normalized(
        self, scan_id: str, test_id: str, finding, confidence: str = "low"
    ) -> Finding:
        """`finding` is an app.tools.models.NormalizedFinding — the shared shape
        produced by both tool adapters (Phase 5) and deterministic scanners
        (Phase 6)."""
        record = Finding(
            scan_id=scan_id,
            test_id=test_id,
            title=finding.title,
            vulnerability_class=finding.metadata.get("vulnerability_class", "unknown"),
            severity=finding.severity,
            confidence=finding.metadata.get("confidence", confidence),
            matched_endpoint=finding.matched_endpoint,
            description=finding.raw_output[:2000],
            metadata_json=finding.metadata,
        )
        self._session.add(record)
        await self._session.flush()

        evidence = Evidence(
            finding_id=record.id, kind="raw_output", content=finding.raw_output[:4000]
        )
        self._session.add(evidence)
        await self._session.flush()

        return record

    async def list_findings_for_scan(self, scan_id: str) -> list[Finding]:
        result = await self._session.execute(
            select(Finding).where(Finding.scan_id == scan_id)
        )
        return list(result.scalars().all())

    async def list_findings_with_source_for_scan(self, scan_id: str) -> list[dict]:
        """Same findings as list_findings_for_scan, but joined with Test to include
        endpoint_id and scanner_name (as "tool_name") — the shape
        app.verification.correlation.CorrelationEngine expects. Returned as plain
        dicts (not ORM rows) since the correlation engine is deliberately
        database-agnostic."""
        result = await self._session.execute(
            select(Finding, Test.endpoint_id, Test.scanner_name)
            .join(Test, Finding.test_id == Test.id)
            .where(Finding.scan_id == scan_id)
        )
        return [
            {
                "id": finding.id,
                "endpoint_id": endpoint_id,
                "vulnerability_class": finding.vulnerability_class,
                "tool_name": scanner_name,
                "verification_status": finding.verification_status,
                "confidence": finding.confidence,
            }
            for finding, endpoint_id, scanner_name in result.all()
        ]

    async def update_verification(
        self, finding_id: str, verification_status: str, confidence: str
    ) -> Finding | None:
        finding = await self._session.get(Finding, finding_id)
        if finding is None:
            return None
        finding.verification_status = verification_status
        finding.confidence = confidence
        await self._session.flush()
        return finding

    async def create_correlation(
        self,
        scan_id: str,
        endpoint_id: str,
        vulnerability_class: str,
        finding_ids: list[str],
        tool_names: list[str],
        combined_confidence: str,
        status: str,
        rationale: str,
    ) -> Correlation:
        record = Correlation(
            scan_id=scan_id,
            endpoint_id=endpoint_id,
            vulnerability_class=vulnerability_class,
            finding_ids_json=finding_ids,
            tool_names_json=tool_names,
            combined_confidence=combined_confidence,
            status=status,
            rationale=rationale,
        )
        self._session.add(record)
        await self._session.flush()
        return record

    async def list_correlations_for_scan(self, scan_id: str) -> list[Correlation]:
        result = await self._session.execute(
            select(Correlation).where(Correlation.scan_id == scan_id)
        )
        return list(result.scalars().all())

    async def list_evidence_for_finding(self, finding_id: str) -> list[Evidence]:
        result = await self._session.execute(
            select(Evidence).where(Evidence.finding_id == finding_id)
        )
        return list(result.scalars().all())
