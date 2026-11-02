"""Human-in-the-loop response decisions: approve / reject / modify. Every decision is authorised, validated, audited and (for approve) SIMULATED."""
from __future__ import annotations
import logging
from ..db import AuditLog, Incident, IncidentTimeline, ResponseRecommendation
from .events import EventPublisher
from .executor import SimulationResponseExecutor
from .guardrails import ACTION_POLICIES, CONTAINMENT_ACTIONS, Guardrails, PolicyViolation
from .states import ACTIVE_STATES, IncidentState as S, StateMachine, current_state
from .util import utcnow

log = logging.getLogger("agentic.approvals")


PAST = {"approve": "approved", "reject": "rejected", "modify": "modified"}


class NotFound(Exception): pass
class Conflict(Exception): pass


class ResponseDecisionService:
    def __init__(self, guard: Guardrails, executor: SimulationResponseExecutor | None = None, machine: StateMachine | None = None, publisher: EventPublisher | None = None):
        self.guard, self.executor = guard, executor or SimulationResponseExecutor()
        self.publisher = publisher or EventPublisher(); self.sm = machine or StateMachine(self.publisher)

    # ---- helpers
    def _load(self, db, incident_id: str, response_id: str):
        inc = db.get(Incident, incident_id)
        if not inc: raise NotFound(f"incident {incident_id} not found")
        rec = db.get(ResponseRecommendation, response_id)
        if not rec or rec.incident_id != incident_id: raise NotFound(f"response {response_id} not found on incident {incident_id}")
        return inc, rec

    def _deny(self, db, inc, rec, actor, role, verb, pv: PolicyViolation):
        db.add(AuditLog(actor=actor, action="response_denied", detail=dict(incident_id=inc.id, response_id=rec.id, verb=verb, action=rec.action, role=role, code=pv.code, message=pv.message)))
        db.add(IncidentTimeline(incident_id=inc.id, kind="approval", message=f"{actor} ({role}) was denied: {verb} {rec.action} — {pv.message}", detail=dict(response_id=rec.id, code=pv.code)))
        db.commit()

    def _precheck(self, inc, rec) -> None:
        if rec.status != "pending": raise Conflict(f"response is already {rec.status}")
        st = current_state(inc)
        if st in ACTIVE_STATES: raise Conflict(f"an investigation is in progress (state {st.value}); try again when it completes")
        if st == S.RESOLVED: raise Conflict("incident is resolved")

    def _finish(self, db, inc, rec, verb, actor, role, comment) -> dict:
        db.add(AuditLog(actor=actor, action=f"response_{rec.status if verb != 'modify' else 'modified'}", detail=dict(incident_id=inc.id, response_id=rec.id, action=rec.action, target=rec.target, role=role, comment=comment, simulated=True)))
        db.add(IncidentTimeline(incident_id=inc.id, kind="approval", message=f"{actor} ({role}) {PAST[verb]} {rec.action} → {rec.target}" + (f": {comment}" if comment else ""), detail=dict(response_id=rec.id)))
        db.commit()
        self.publisher.publish("response_decision", dict(incident_id=inc.id, response_id=rec.id, status=rec.status, action=rec.action, target=rec.target, actor=actor, incident_state=inc.state))
        return dict(response_id=rec.id, incident_id=inc.id, status=rec.status, action=rec.action, target=rec.target, incident_state=inc.state, execution_result=rec.execution_result,
                    note="Simulated action only; nothing was executed on any real system.")

    # ---- decisions
    def approve(self, db, incident_id, response_id, actor="analyst", role="analyst", comment=None) -> dict:
        inc, rec = self._load(db, incident_id, response_id); self._precheck(inc, rec); role = self.guard.normalize_role(role)
        if rec.approval_level is None:      # legacy (Phase 1/2) free-text recommendation: keep its original behaviour
            self.guard.authorize_reject(role); rec.status, rec.decided_at, rec.decided_by, rec.decision_comment = "approved", utcnow(), actor, comment
            rec.execution_result = dict(simulated=True, message="legacy recommendation approved; nothing executed")
            return self._finish(db, inc, rec, "approve", actor, role, comment)
        try:
            self.guard.authorize(role, rec.action, inc.risk_level)
            va = self.guard.validate_action(rec.action, rec.target, rec.params)      # re-validated at approval time
        except PolicyViolation as pv: self._deny(db, inc, rec, actor, role, "approve", pv); raise
        result = self.executor.execute(db, inc, rec, va, actor)
        rec.status, rec.decided_at, rec.decided_by, rec.decision_comment, rec.executed_at, rec.execution_result = "approved", utcnow(), actor, comment, utcnow(), result
        st = current_state(inc)
        if rec.action == "close_incident" and st in (S.AWAITING_HUMAN_APPROVAL, S.CONTAINED): self.sm.transition(db, inc, S.RESOLVED, f"closed by {actor}", actor=actor)
        elif rec.action in CONTAINMENT_ACTIONS and st == S.AWAITING_HUMAN_APPROVAL: self.sm.transition(db, inc, S.CONTAINED, f"{rec.action} approved by {actor}", actor=actor)
        return self._finish(db, inc, rec, "approve", actor, role, comment)

    def reject(self, db, incident_id, response_id, actor="analyst", role="analyst", comment=None) -> dict:
        inc, rec = self._load(db, incident_id, response_id); self._precheck(inc, rec)
        try: role = self.guard.authorize_reject(role)
        except PolicyViolation as pv: self._deny(db, inc, rec, actor, role, "reject", pv); raise
        rec.status, rec.decided_at, rec.decided_by, rec.decision_comment = "rejected", utcnow(), actor, comment
        out = self._finish(db, inc, rec, "reject", actor, role, comment)
        if not any(r.status == "pending" for r in inc.recommendations) and not any(r.status == "approved" for r in inc.recommendations):
            inc.needs_review = 1; db.add(IncidentTimeline(incident_id=inc.id, kind="note", message="all recommended responses were rejected; manual handling required")); db.commit()
        return out

    def modify(self, db, incident_id, response_id, actor="analyst", role="analyst", action=None, target=None, comment=None) -> dict:
        inc, rec = self._load(db, incident_id, response_id); self._precheck(inc, rec); role = self.guard.normalize_role(role)
        new_action, new_target = action or rec.action, (target if target is not None else rec.target)
        try:
            if (new_action, new_target) == (rec.action, rec.target): raise PolicyViolation("no_change", "modification changes nothing", 422)
            va = self.guard.validate_action(new_action, new_target, rec.params)
            self.guard.authorize(role, new_action, inc.risk_level)
        except PolicyViolation as pv: self._deny(db, inc, rec, actor, role, "modify", pv); raise
        pol = ACTION_POLICIES[new_action]; old = f"{rec.action}→{rec.target}"
        if not rec.modified: rec.original_action = rec.action
        rec.action, rec.target, rec.modified = new_action, va.target, 1
        rec.approval_level = self.guard.required_level(new_action, inc.risk_level); rec.destructive = int(pol.destructive); rec.expected_impact = pol.expected_impact.format(target=va.target)
        rec.rationale = f"{rec.rationale or ''} [modified by {actor}: {old} → {new_action}→{va.target}]".strip(); rec.decision_comment = comment
        return self._finish(db, inc, rec, "modify", actor, role, comment)   # stays PENDING: the final action must still be approved
