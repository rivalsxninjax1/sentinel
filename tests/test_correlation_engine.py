from app.verification.correlation import CorrelationEngine


def _finding(id_, endpoint_id, vuln_class, tool_name, verification_status, confidence):
    return {
        "id": id_,
        "endpoint_id": endpoint_id,
        "vulnerability_class": vuln_class,
        "tool_name": tool_name,
        "verification_status": verification_status,
        "confidence": confidence,
    }


def test_no_correlation_below_two_findings():
    findings = [_finding("f1", "e1", "xss", "reflected_xss", "verified", "medium")]
    groups = CorrelationEngine().correlate(findings)
    assert groups == []


def test_no_correlation_when_same_tool_reports_twice():
    findings = [
        _finding("f1", "e1", "xss", "reflected_xss", "verified", "medium"),
        _finding("f2", "e1", "xss", "reflected_xss", "verified", "medium"),
    ]
    groups = CorrelationEngine().correlate(findings)
    assert groups == []  # same tool_name twice isn't independent corroboration


def test_agreement_when_two_distinct_sources_both_verified():
    findings = [
        _finding("f1", "e1", "xss", "reflected_xss", "verified", "medium"),
        _finding("f2", "e1", "xss", "xsstrike", "verified", "medium"),
    ]
    groups = CorrelationEngine().correlate(findings)

    assert len(groups) == 1
    assert groups[0].status == "agreement"
    assert groups[0].combined_confidence == "high"
    assert set(groups[0].tool_names) == {"reflected_xss", "xsstrike"}
    assert set(groups[0].finding_ids) == {"f1", "f2"}


def test_conflicting_evidence_when_one_verified_one_false_positive():
    findings = [
        _finding("f1", "e1", "xss", "reflected_xss", "verified", "medium"),
        _finding("f2", "e1", "xss", "xsstrike", "false_positive", "low"),
    ]
    groups = CorrelationEngine().correlate(findings)

    assert len(groups) == 1
    assert groups[0].status == "conflicting_evidence"
    assert groups[0].combined_confidence == "low"


def test_insufficient_correlation_when_not_all_verified():
    findings = [
        _finding("f1", "e1", "idor_bola", "idor_candidate", "needs_manual_review", "info"),
        _finding("f2", "e1", "idor_bola", "identity_authorization", "needs_manual_review", "low"),
    ]
    groups = CorrelationEngine().correlate(findings)

    assert len(groups) == 1
    assert groups[0].status == "insufficient_correlation"
    assert groups[0].combined_confidence == "low"  # highest individual confidence in the group


def test_different_endpoints_do_not_correlate_together():
    findings = [
        _finding("f1", "e1", "xss", "reflected_xss", "verified", "medium"),
        _finding("f2", "e2", "xss", "xsstrike", "verified", "medium"),
    ]
    groups = CorrelationEngine().correlate(findings)
    assert groups == []


def test_different_vulnerability_classes_do_not_correlate_together():
    findings = [
        _finding("f1", "e1", "xss", "reflected_xss", "verified", "medium"),
        _finding("f2", "e1", "sqli", "sqlmap", "verified", "medium"),
    ]
    groups = CorrelationEngine().correlate(findings)
    assert groups == []


def test_never_produces_confirmed_confidence():
    findings = [
        _finding("f1", "e1", "xss", "a", "verified", "high"),
        _finding("f2", "e1", "xss", "b", "verified", "high"),
        _finding("f3", "e1", "xss", "c", "verified", "high"),
    ]
    groups = CorrelationEngine().correlate(findings)
    assert all(g.combined_confidence != "confirmed" for g in groups)
