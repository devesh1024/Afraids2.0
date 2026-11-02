"""Read models for the UI: investigation view (per run), flat replay, timeline."""
from __future__ import annotations
from datetime import datetime
from ..db import (AgentExecution, Incident, IncidentStateTransition, IncidentTimeline, InvestigationFinding, ResponseRecommendation, ToolCall)
from .agents import AGENT_ORDER

LEGACY_STATUS = {"success": "COMPLETED", "failed": "FAILED"}


def ser(o, skip=()) -> dict:
    return {c.name: (getattr(o, c.name).isoformat() if isinstance(getattr(o, c.name), datetime) else getattr(o, c.name)) for c in o.__table__.columns if c.name not in skip}


def norm_status(s: str | None) -> str: return LEGACY_STATUS.get(s or "", s or "WAITING")


def _dur(ex) -> float | None:
    return round((ex.finished_at - ex.started_at).total_seconds() * 1000, 1) if ex.finished_at and ex.started_at else None


def execution_view(ex, calls: list, findings: list) -> dict:
    return dict(id=ex.id, agent=ex.agent, status=norm_status(ex.status), confidence=ex.confidence, started_at=ex.started_at.isoformat() if ex.started_at else None,
                finished_at=ex.finished_at.isoformat() if ex.finished_at else None, duration_ms=_dur(ex), run_id=ex.run_id, sequence=ex.sequence, iteration=ex.iteration,
                input_summary=ex.input_summary, output_summary=ex.output_summary, tools_used=ex.tools_used or [], evidence=ex.evidence or [], evidence_ids=ex.evidence_ids or [],
                error=ex.error, output=ex.output or {}, tool_calls=[ser(c) for c in calls], findings=[ser(f) for f in findings])


def _maps(db, iid):
    calls: dict = {}; finds: dict = {}
    for c in db.query(ToolCall).filter(ToolCall.incident_id == iid).order_by(ToolCall.started_at).all(): calls.setdefault(c.execution_id, []).append(c)
    for f in db.query(InvestigationFinding).filter(InvestigationFinding.incident_id == iid).order_by(InvestigationFinding.created_at).all(): finds.setdefault(f.execution_id, []).append(f)
    return calls, finds


def build_investigation_view(db, iid: str) -> dict | None:
    inc = db.get(Incident, iid)
    if not inc: return None
    execs = db.query(AgentExecution).filter(AgentExecution.incident_id == iid).order_by(AgentExecution.started_at).all(); calls, finds = _maps(db, iid)
    trans = db.query(IncidentStateTransition).filter(IncidentStateTransition.incident_id == iid).order_by(IncidentStateTransition.timestamp).all()
    groups: dict = {}
    for ex in execs: groups.setdefault(ex.run_id or "legacy", []).append(ex)
    runs = []
    for rid, items in groups.items():
        items.sort(key=lambda x: (x.sequence if x.sequence is not None else 99, x.started_at or datetime.min)); sup = next((x for x in items if x.agent == "SupervisorAgent"), None)
        views = [execution_view(x, calls.get(x.id, []), finds.get(x.id, [])) for x in items]
        status = norm_status(sup.status) if sup else norm_status(items[-1].status)
        runs.append(dict(run_id=rid, started_at=min((x.started_at for x in items if x.started_at), default=None).isoformat() if items else None,
                         finished_at=sup.finished_at.isoformat() if sup and sup.finished_at else None, status=status, iterations=sum(1 for x in items if x.agent == "InvestigationAgent"),
                         executions=views, transitions=[ser(t) for t in trans if t.run_id == rid]))
    runs.sort(key=lambda r: r["started_at"] or "")
    tl = db.query(IncidentTimeline).filter(IncidentTimeline.incident_id == iid).order_by(IncidentTimeline.timestamp).all()
    recs = db.query(ResponseRecommendation).filter(ResponseRecommendation.incident_id == iid).order_by(ResponseRecommendation.created_at).all()
    keys = ("id", "title", "status", "state", "risk_score", "risk_level", "confidence", "needs_review", "verdict", "assessment", "iterations", "techniques", "updated_at")
    s = ser(inc)
    return dict(incident={k: s.get(k) for k in keys}, pipeline=AGENT_ORDER, runs=runs, responses=[ser(r) for r in recs], timeline=[ser(t) for t in tl])


def build_replay(db, iid: str, run_id: str | None = None) -> dict | None:
    inc = db.get(Incident, iid)
    if not inc: return None
    q = db.query(AgentExecution).filter(AgentExecution.incident_id == iid)
    if run_id: q = q.filter(AgentExecution.run_id == run_id)
    execs = q.all(); calls, finds = _maps(db, iid)
    tq = db.query(IncidentStateTransition).filter(IncidentStateTransition.incident_id == iid)
    if run_id: tq = tq.filter(IncidentStateTransition.run_id == run_id)
    steps = []
    for t in tq.all():
        steps.append(dict(ts=t.timestamp, order=0, kind="state", run_id=t.run_id, title=f"{t.from_state} → {t.to_state}", detail=t.reason or "", state=t.to_state))
    for x in execs:
        v = execution_view(x, calls.get(x.id, []), finds.get(x.id, []))
        steps.append(dict(ts=x.started_at, order=1, kind="agent", run_id=x.run_id, title=f"{x.agent} {v['status']}", detail=x.output_summary or "", agent=x.agent, status=v["status"], duration_ms=v["duration_ms"],
                          confidence=x.confidence, input_summary=x.input_summary, output_summary=x.output_summary, tools=v["tools_used"], findings=v["findings"], evidence=v["evidence"],
                          evidence_ids=v["evidence_ids"], error=x.error, iteration=x.iteration))
    for t in db.query(IncidentTimeline).filter(IncidentTimeline.incident_id == iid, IncidentTimeline.kind.in_(["approval", "execution", "response"])).all():
        steps.append(dict(ts=t.timestamp, order=2, kind="decision", run_id=None, title=t.message, detail="", subkind=t.kind))
    steps.sort(key=lambda s: (s["ts"] or datetime.min, s["order"]))
    for i, s in enumerate(steps): s["index"] = i; s["ts"] = s["ts"].isoformat() if s["ts"] else None
    return dict(incident_id=iid, run_id=run_id, count=len(steps), steps=steps)
