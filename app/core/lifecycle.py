"""Scan lifecycle state machine.

See docs/architecture.md §9:

    CREATED -> SCOPE_VALIDATED -> RECON -> DISCOVERY -> INTELLIGENCE -> PRIORITIZED
            -> TESTING -> VERIFYING -> CORRELATING -> REPORTING -> COMPLETE
                                                             \\-> STOPPED (from any state)

Phase 1 only implements the state machine itself (valid transitions + persistence
hook) — the stages beyond SCOPE_VALIDATED don't have real logic behind them yet, so
this module just proves the mechanism works and is unit-testable.
"""

from __future__ import annotations

from enum import Enum


class ScanState(str, Enum):
    CREATED = "created"
    SCOPE_VALIDATED = "scope_validated"
    RECON = "recon"
    DISCOVERY = "discovery"
    INTELLIGENCE = "intelligence"
    PRIORITIZED = "prioritized"
    TESTING = "testing"
    VERIFYING = "verifying"
    CORRELATING = "correlating"
    REPORTING = "reporting"
    COMPLETE = "complete"
    STOPPED = "stopped"


_FORWARD_TRANSITIONS: dict[ScanState, ScanState] = {
    ScanState.CREATED: ScanState.SCOPE_VALIDATED,
    ScanState.SCOPE_VALIDATED: ScanState.RECON,
    ScanState.RECON: ScanState.DISCOVERY,
    ScanState.DISCOVERY: ScanState.INTELLIGENCE,
    ScanState.INTELLIGENCE: ScanState.PRIORITIZED,
    ScanState.PRIORITIZED: ScanState.TESTING,
    ScanState.TESTING: ScanState.VERIFYING,
    ScanState.VERIFYING: ScanState.CORRELATING,
    ScanState.CORRELATING: ScanState.REPORTING,
    ScanState.REPORTING: ScanState.COMPLETE,
}

_TERMINAL_STATES = {ScanState.COMPLETE, ScanState.STOPPED}


class InvalidTransition(Exception):
    pass


class ScanLifecycle:
    """In-memory state machine. Callers persist `.state` via the ScanRepository after
    each transition so a scan can resume from its last completed stage."""

    def __init__(self, initial_state: ScanState = ScanState.CREATED) -> None:
        self._state = initial_state
        self._stopped_reason: str | None = None

    @property
    def state(self) -> ScanState:
        return self._state

    @property
    def stopped_reason(self) -> str | None:
        return self._stopped_reason

    @property
    def is_terminal(self) -> bool:
        return self._state in _TERMINAL_STATES

    def advance(self) -> ScanState:
        """Move to the next state in the normal forward pipeline."""
        if self.is_terminal:
            raise InvalidTransition(f"cannot advance from terminal state {self._state}")
        next_state = _FORWARD_TRANSITIONS.get(self._state)
        if next_state is None:
            raise InvalidTransition(f"no forward transition defined from {self._state}")
        self._state = next_state
        return self._state

    def stop(self, reason: str) -> ScanState:
        """Stop the scan from any non-terminal state (scope violation, request limit
        exceeded, instability, timeout, operator cancel — see docs/architecture.md §9
        and the governing spec's stop-condition list)."""
        if self.is_terminal:
            raise InvalidTransition(f"cannot stop from terminal state {self._state}")
        self._state = ScanState.STOPPED
        self._stopped_reason = reason
        return self._state
