from app.scanners.base import mode_allows


def test_passive_scan_only_allows_passive_scanners():
    assert mode_allows("passive", "passive") is True
    assert mode_allows("passive", "safe") is False
    assert mode_allows("passive", "active") is False


def test_safe_scan_allows_passive_and_safe():
    assert mode_allows("safe", "passive") is True
    assert mode_allows("safe", "safe") is True
    assert mode_allows("safe", "active") is False


def test_active_scan_allows_everything():
    assert mode_allows("active", "passive") is True
    assert mode_allows("active", "safe") is True
    assert mode_allows("active", "active") is True


def test_unknown_mode_allows_nothing():
    assert mode_allows("bogus", "passive") is False
