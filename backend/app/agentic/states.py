"""Explicit incident state machine. State is persisted on Incident.state; every change is stored in incident_state_transitions."""
from __future__ import annotations
from enum import Enum
from ..db import IncidentStateTransition, IncidentTimeline
from .events import EventPublisher
from .util import utcnow


class IncidentState(str, Enum):
    RECEIVED = "RECEIVED"; DETECTED = "DETECTED"; TRIAGING = "TRIAGING"; INVESTIGATING = "INVESTIGATING"
    THREAT_INTEL_LOOKUP = "THREAT_INTEL_LOOKUP"; CORRELATING = "CORRELATING"; ATTACK_RECONSTRUCTION = "ATTACK_RECONSTRUCTION"
    RISK_ASSESSMENT = "RISK_ASSESSMENT"; RESPONSE_PLANNING = "RESPONSE_PLANNING"; AWAITING_HUMAN_APPROVAL = "AWAITING_HUMAN_APPROVAL"
    CONTAINED = "CONTAINED"; RESOLVED = "RESOLVED"; FAILED = "FAILED"


S = IncidentState
TRANSITIONS: dict = {
    S.RECEIVED: {S.DETECTED, S.FAILED},
    S.DETECTED: {S.TRIAGING, S.FAILED},
    S.TRIAGING: {S.THREAT_INTEL_LOOKUP, S.FAILED},
    S.THREAT_INTEL_LOOKUP: {S.INVESTIGATING, S.FAILED},
    S.INVESTIGATING: {S.CORRELATING, S.FAILED},
    S.CORRELATING: {S.INVESTIGATING, S.ATTACK_RECONSTRUCTION, S.FAILED},      # CORRELATING -> INVESTIGATING is the bounded loop
    S.ATTACK_RECONSTRUCTION: {S.RISK_ASSESSMENT, S.FAILED},
    S.RISK_ASSESSMENT: {S.RESPONSE_PLANNING, S.FAILED},
    S.RESPONSE_PLANNING: {S.AWAITING_HUMAN_APPROVAL, S.RESOLVED, S.FAILED},
    S.AWAITING_HUMAN_APPROVAL: {S.CONTAINED, S.RESOLVED, S.RECEIVED, S.FAILED},   # RECEIVED = new evidence re-opens the pipeline
    S.CONTAINED: {S.RESOLVED, S.AWAITING_HUMAN_APPROVAL, S.RECEIVED, S.FAILED},
    S.RESOLVED: set(),                                                           # terminal
    S.FAILED: {S.RECEIVED},
}
ACTIVE_STATES = {S.DETECTED, S.TRIAGING, S.INVESTIGATING, S.THREAT_INTEL_LOOKUP, S.CORRELATING, S.ATTACK_RECONSTRUCTION, S.RISK_ASSESSMENT, S.RESPONSE_PLANNING}


class InvalidTransition(Exception):
    def __init__(self, cur, to):
        super().__init__(f"illegal state transition {getattr(cur, 'value', cur)} -> {getattr(to, 'value', to)}"); self.cur, self.to = cur, to


def can_transition(cur, to) -> bool:
    return IncidentState(to) in TRANSITIONS[IncidentState(cur)]


def current_state(incident) -> IncidentState:
    return IncidentState(incident.state or IncidentState.RECEIVED.value)


class StateMachine:
    def __init__(self, publisher: EventPublisher | None = None): self.publisher = publisher or EventPublisher()

    def transition(self, db, incident, to, reason: str = "", actor: str = "SupervisorAgent", run_id: str | None = None) -> IncidentStateTransition:
        to = IncidentState(to); cur = current_state(incident)
        if to not in TRANSITIONS[cur]: raise InvalidTransition(cur, to)
        incident.state = to.value; incident.updated_at = utcnow()
        if to == IncidentState.RESOLVED: incident.status = "closed"
        row = IncidentStateTransition(incident_id=incident.id, run_id=run_id, from_state=cur.value, to_state=to.value, reason=reason, actor=actor, timestamp=utcnow())
        db.add(row)
        db.add(IncidentTimeline(incident_id=incident.id, kind="state", message=f"{cur.value} → {to.value}" + (f": {reason}" if reason else ""), detail={"run_id": run_id}))
        db.flush()
        self.publisher.publish("incident_state", {"incident_id": incident.id, "run_id": run_id, "from": cur.value, "to": to.value, "reason": reason})
        return row
