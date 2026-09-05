import pytest

from app.scanners.base import ScanTarget
from app.scanners.idor_candidate import IDORCandidateScanner


@pytest.mark.asyncio
async def test_flags_id_shaped_parameter_name():
    scanner = IDORCandidateScanner()
    target = ScanTarget(url="https://app.example.com/orders", parameter_name="order_id")
    findings = await scanner.scan(target, http_client=None)  # no network call made

    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert findings[0].metadata["confidence"] == "info"
    assert "requires" in findings[0].metadata


@pytest.mark.asyncio
async def test_no_finding_for_non_identifier_parameter():
    scanner = IDORCandidateScanner()
    target = ScanTarget(url="https://app.example.com/search", parameter_name="query")
    findings = await scanner.scan(target, http_client=None)

    assert findings == []


@pytest.mark.asyncio
async def test_no_finding_without_parameter():
    scanner = IDORCandidateScanner()
    target = ScanTarget(url="https://app.example.com/orders")
    findings = await scanner.scan(target, http_client=None)

    assert findings == []


def test_value_looks_like_identifier_helper():
    assert IDORCandidateScanner.value_looks_like_identifier("12345") is True
    assert IDORCandidateScanner.value_looks_like_identifier("550e8400-e29b-41d4-a716-446655440000") is True
    assert IDORCandidateScanner.value_looks_like_identifier("hello world") is False
