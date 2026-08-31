import pytest

from app.core.lifecycle import InvalidTransition, ScanLifecycle, ScanState


def test_initial_state_is_created():
    lifecycle = ScanLifecycle()
    assert lifecycle.state == ScanState.CREATED
    assert not lifecycle.is_terminal


def test_advances_through_full_pipeline_in_order():
    lifecycle = ScanLifecycle()
    expected_order = [
        ScanState.SCOPE_VALIDATED,
        ScanState.RECON,
        ScanState.DISCOVERY,
        ScanState.INTELLIGENCE,
        ScanState.PRIORITIZED,
        ScanState.TESTING,
        ScanState.VERIFYING,
        ScanState.CORRELATING,
        ScanState.REPORTING,
        ScanState.COMPLETE,
    ]
    for expected in expected_order:
        assert lifecycle.advance() == expected
    assert lifecycle.is_terminal


def test_cannot_advance_past_complete():
    lifecycle = ScanLifecycle(ScanState.REPORTING)
    lifecycle.advance()
    assert lifecycle.state == ScanState.COMPLETE
    with pytest.raises(InvalidTransition):
        lifecycle.advance()


def test_stop_from_any_non_terminal_state():
    lifecycle = ScanLifecycle(ScanState.TESTING)
    lifecycle.stop("scope violation detected mid-scan")
    assert lifecycle.state == ScanState.STOPPED
    assert lifecycle.stopped_reason == "scope violation detected mid-scan"


def test_cannot_stop_a_terminal_scan():
    lifecycle = ScanLifecycle(ScanState.COMPLETE)
    with pytest.raises(InvalidTransition):
        lifecycle.stop("too late")
