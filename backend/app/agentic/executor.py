"""SimulationResponseExecutor: SIMULATES approved responses by writing rows to `simulated_effects`, the incident timeline and the audit log.

SAFETY: this module deliberately imports nothing that can touch a real system (no subprocess, os, socket, HTTP clients).
tests/test_agentic.py::test_executor_has_no_real_side_effect_imports enforces that by scanning this file's source.
"""
from __future__ import annotations
import hashlib
from ..chain import incident_events
from ..db import AuditLog, IncidentTimeline, SimulatedEffect
from .guardrails import ValidatedAction
from .util import utcnow

EFFECT_KIND = {"block_ip": "blocklist", "disable_account": "disabled_account", "revoke_session": "revoked_session", "isolate_endpoint": "isolated_host",
               "increase_monitoring": "monitoring", "preserve_evidence": "evidence_snapshot", "close_incident": "incident_closed"}
MESSAGE = {"block_ip": "SIMULATED: {t} added to the blocklist (no real firewall change)", "disable_account": "SIMULATED: account {t} disabled (no real directory change)",
           "revoke_session": "SIMULATED: sessions of {t} revoked (no real session change)", "isolate_endpoint": "SIMULATED: host {t} isolated (no real network change)",
           "increase_monitoring": "SIMULATED: {t} added to the monitoring watchlist", "preserve_evidence": "SIMULATED: evidence manifest created for incident {t}",
           "close_incident": "SIMULATED: incident {t} closed"}


class SimulationResponseExecutor:
    def execute(self, db, incident, rec, va: ValidatedAction, actor: str) -> dict:
        action, target = va.action, va.target; kind = EFFECT_KIND[action]
        existing = db.query(SimulatedEffect).filter(SimulatedEffect.kind == kind, SimulatedEffect.target == target, SimulatedEffect.active == 1).first()
        detail: dict = {}
        if action == "preserve_evidence":
            ev_ids = sorted(e.id for e in incident_events(db, incident)); al_ids = sorted(a.id for a in incident.alerts)
            detail = dict(event_count=len(ev_ids), alert_count=len(al_ids), manifest_sha256=hashlib.sha256("|".join(ev_ids + al_ids).encode()).hexdigest())
            existing = None   # every snapshot is a new record
        if action == "close_incident": incident.status = "closed"
        status = "already_active" if existing else "applied"
        if not existing:
            db.add(SimulatedEffect(incident_id=incident.id, response_id=rec.id, kind=kind, target=target, active=1, detail=detail, created_at=utcnow()))
        msg = MESSAGE[action].format(t=target)
        db.add(IncidentTimeline(incident_id=incident.id, kind="execution", message=msg, detail=dict(response_id=rec.id, action=action, target=target, status=status, actor=actor)))
        db.add(AuditLog(actor=actor, action="response_executed_simulated", detail=dict(incident_id=incident.id, response_id=rec.id, action=action, target=target, status=status, simulated=True)))
        db.flush()
        return dict(simulated=True, action=action, target=target, effect=kind, status=status, message=msg, detail=detail, executed_at=utcnow().isoformat())


def simulation_state(db) -> dict:
    rows = db.query(SimulatedEffect).filter(SimulatedEffect.active == 1).order_by(SimulatedEffect.created_at).all()
    pick = lambda k: [dict(target=r.target, incident_id=r.incident_id, since=r.created_at.isoformat(), detail=r.detail or {}) for r in rows if r.kind == k]
    return dict(blocklist=pick("blocklist"), disabled_accounts=pick("disabled_account"), revoked_sessions=pick("revoked_session"), isolated_hosts=pick("isolated_host"),
                monitoring=pick("monitoring"), evidence_snapshots=pick("evidence_snapshot"), closed_incidents=pick("incident_closed"),
                note="All entries are simulated; nothing here reflects a real firewall, directory or endpoint.")
