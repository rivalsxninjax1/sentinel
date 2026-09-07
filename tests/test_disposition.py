from app.reporting.disposition import approximate_cvss, disposition


def test_verified_high_confidence_is_likely():
    assert disposition("verified", "high") == "Likely"


def test_verified_medium_confidence_is_potential():
    assert disposition("verified", "medium") == "Potential"


def test_verified_low_confidence_is_potential():
    assert disposition("verified", "low") == "Potential"


def test_verified_info_confidence_is_informational():
    assert disposition("verified", "info") == "Informational"


def test_needs_manual_review_maps_directly():
    assert disposition("needs_manual_review", "low") == "Requires Manual Verification"
    assert disposition("needs_manual_review", "high") == "Requires Manual Verification"


def test_unverified_maps_to_requires_manual_verification():
    assert disposition("unverified", "medium") == "Requires Manual Verification"


def test_confirmed_confidence_maps_to_confirmed_disposition():
    # Documented as unreachable given the current hard cap (see
    # app/verification/engine.py) — this only proves the mapping is total.
    assert disposition("verified", "confirmed") == "Confirmed"


def test_unknown_confidence_falls_back_to_manual_review():
    assert disposition("verified", "not_a_real_confidence") == "Requires Manual Verification"


def test_approximate_cvss_scales_with_severity():
    assert approximate_cvss("critical") == 9.0
    assert approximate_cvss("high") == 7.5
    assert approximate_cvss("medium") == 5.4
    assert approximate_cvss("low") == 3.1
    assert approximate_cvss("info") is None


def test_approximate_cvss_unknown_severity_returns_none():
    assert approximate_cvss("not_a_real_severity") is None
