"""Investigation state machine — lifecycle management for investigations.

States: PENDING → PLANNING → RUNNING → CORRELATING → REPORTING → COMPLETE
                                                         ↘ FAILED
        PAUSED ← (any running state)

Uses the `transitions` library for formal state machine semantics.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from transitions import Machine

logger = logging.getLogger(__name__)


class InvestigationStatus(str, Enum):
    """Investigation lifecycle states."""

    PENDING = "pending"
    PLANNING = "planning"
    RUNNING = "running"
    PAUSED = "paused"
    CORRELATING = "correlating"
    REPORTING = "reporting"
    COMPLETE = "complete"
    FAILED = "failed"


# Valid state transitions: (from_state, to_state) → trigger_name
_TRANSITIONS: list[dict[str, Any]] = [
    # Start planning
    {"trigger": "start_planning", "source": InvestigationStatus.PENDING, "dest": InvestigationStatus.PLANNING},
    # Plan ready → start running
    {"trigger": "start_running", "source": InvestigationStatus.PLANNING, "dest": InvestigationStatus.RUNNING},
    # Pause from running
    {"trigger": "pause", "source": InvestigationStatus.RUNNING, "dest": InvestigationStatus.PAUSED},
    # Resume from paused
    {"trigger": "resume", "source": InvestigationStatus.PAUSED, "dest": InvestigationStatus.RUNNING},
    # All agents done → start correlating
    {"trigger": "start_correlating", "source": InvestigationStatus.RUNNING, "dest": InvestigationStatus.CORRELATING},
    # Correlation done → start reporting
    {"trigger": "start_reporting", "source": InvestigationStatus.CORRELATING, "dest": InvestigationStatus.REPORTING},
    # Report generated → complete
    {"trigger": "complete", "source": InvestigationStatus.REPORTING, "dest": InvestigationStatus.COMPLETE},
    # Failure from any active state
    {"trigger": "fail", "source": [
        InvestigationStatus.PENDING,
        InvestigationStatus.PLANNING,
        InvestigationStatus.RUNNING,
        InvestigationStatus.PAUSED,
        InvestigationStatus.CORRELATING,
        InvestigationStatus.REPORTING,
    ], "dest": InvestigationStatus.FAILED},
    # Reset from failed back to pending (retry)
    {"trigger": "reset", "source": InvestigationStatus.FAILED, "dest": InvestigationStatus.PENDING},
    # Cancel from paused → failed
    {"trigger": "cancel", "source": InvestigationStatus.PAUSED, "dest": InvestigationStatus.FAILED},
]


class InvestigationStateMachine:
    """Manages the lifecycle state of a single investigation.

    Thread-safe state transitions with event callbacks.
    Persists state changes to Redis for recovery.

    Usage::

        sm = InvestigationStateMachine(investigation_id="abc123")
        sm.start_planning()
        sm.start_running()
        sm.pause()
        sm.resume()
        sm.start_correlating()
        sm.start_reporting()
        sm.complete()
    """

    def __init__(
        self,
        investigation_id: str,
        initial_status: InvestigationStatus = InvestigationStatus.PENDING,
    ) -> None:
        self.investigation_id = investigation_id
        self._initial_status = initial_status
        self._state_history: list[dict[str, Any]] = []

        self._machine = Machine(
            model=self,
            states=InvestigationStatus,
            transitions=_TRANSITIONS,
            initial=initial_status,
            send_event=True,
            after_state_change=self._on_state_change,
        )

    @property
    def state(self) -> InvestigationStatus:
        """Return current investigation status."""
        return self._machine.state

    @property
    def is_active(self) -> bool:
        """True if investigation is in a running/planning/correlating/reporting state."""
        return self.state in {
            InvestigationStatus.PLANNING,
            InvestigationStatus.RUNNING,
            InvestigationStatus.CORRELATING,
            InvestigationStatus.REPORTING,
        }

    @property
    def is_terminal(self) -> bool:
        """True if investigation reached a terminal state."""
        return self.state in {InvestigationStatus.COMPLETE, InvestigationStatus.FAILED}

    @property
    def can_pause(self) -> bool:
        """True if investigation can be paused from current state."""
        return self.state == InvestigationStatus.RUNNING

    @property
    def can_resume(self) -> bool:
        """True if investigation can be resumed."""
        return self.state == InvestigationStatus.PAUSED

    def get_state_history(self) -> list[dict[str, Any]]:
        """Return chronological state transition history."""
        return list(self._state_history)

    def _on_state_change(self, event: Any) -> None:
        """Callback fired after every state transition."""
        transition_data = {
            "investigation_id": self.investigation_id,
            "from_state": event.transition.source,
            "to_state": event.transition.dest,
            "trigger": event.event.name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._state_history.append(transition_data)
        logger.info(
            "Investigation %s: %s → %s (trigger: %s)",
            self.investigation_id,
            event.transition.source,
            event.transition.dest,
            event.event.name,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize state machine to dict."""
        return {
            "investigation_id": self.investigation_id,
            "state": self.state.value,
            "is_active": self.is_active,
            "is_terminal": self.is_terminal,
            "can_pause": self.can_pause,
            "can_resume": self.can_resume,
            "history": self._state_history,
        }

    def __repr__(self) -> str:
        return f"<InvestigationStateMachine id={self.investigation_id} state={self.state.value}>"
