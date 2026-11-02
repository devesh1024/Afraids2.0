"""Phase 3 REST API (mounted by main.py)."""
from __future__ import annotations
import asyncio
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field
from ..db import Incident, IncidentTimeline, InvestigationFinding, ResponseRecommendation, SessionLocal
from . import runtime as rt
from .agents import AGENT_ORDER
from .approvals import Conflict, NotFound
from .executor import simulation_state
from .guardrails import PolicyViolation
from .queries import build_investigation_view, build_replay, ser

router = APIRouter()


class DecisionBody(BaseModel):
    response_id: str = Field(..., min_length=1, max_length=64); comment: str | None = Field(None, max_length=500)


class ModifyBody(DecisionBody):
    action: str | None = Field(None, max_length=64); target: str | None = Field(None, max_length=128)


def _http(e: Exception) -> HTTPException:
    if isinstance(e, NotFound): return HTTPException(404, str(e))
    if isinstance(e, Conflict): return HTTPException(409, str(e))
    if isinstance(e, PolicyViolation): return HTTPException(e.status, dict(code=e.code, message=e.message))
    raise e


def _decide(verb: str, iid: str, body, actor: str, role: str) -> dict:
    svc = rt.default.decisions
    with SessionLocal() as db:
        try:
            if verb == "approve": return svc.approve(db, iid, body.response_id, actor, role, body.comment)
            if verb == "reject": return svc.reject(db, iid, body.response_id, actor, role, body.comment)
            return svc.modify(db, iid, body.response_id, actor, role, body.action, body.target, body.comment)
        except (NotFound, Conflict, PolicyViolation) as e:
            db.rollback(); raise _http(e)


@router.post("/api/incidents/{iid}/approve-response")
async def approve_response(iid: str, body: DecisionBody, x_role: str = Header("analyst"), x_actor: str = Header("analyst")):
    rt.LOOP = asyncio.get_running_loop(); return await asyncio.to_thread(_decide, "approve", iid, body, x_actor, x_role)


@router.post("/api/incidents/{iid}/reject-response")
async def reject_response(iid: str, body: DecisionBody, x_role: str = Header("analyst"), x_actor: str = Header("analyst")):
    rt.LOOP = asyncio.get_running_loop(); return await asyncio.to_thread(_decide, "reject", iid, body, x_actor, x_role)


@router.post("/api/incidents/{iid}/modify-response")
async def modify_response(iid: str, body: ModifyBody, x_role: str = Header("analyst"), x_actor: str = Header("analyst")):
    rt.LOOP = asyncio.get_running_loop(); return await asyncio.to_thread(_decide, "modify", iid, body, x_actor, x_role)


@router.get("/api/incidents/{iid}/investigation")
def investigation(iid: str):
    with SessionLocal() as db:
        v = build_investigation_view(db, iid)
        if v is None: raise HTTPException(404, "not found")
        return v


@router.get("/api/incidents/{iid}/replay")
def replay(iid: str, run_id: str | None = None):
    with SessionLocal() as db:
        v = build_replay(db, iid, run_id)
        if v is None: raise HTTPException(404, "not found")
        return v


@router.get("/api/incidents/{iid}/timeline")
def timeline(iid: str):
    with SessionLocal() as db:
        if not db.get(Incident, iid): raise HTTPException(404, "not found")
        return [ser(t) for t in db.query(IncidentTimeline).filter(IncidentTimeline.incident_id == iid).order_by(IncidentTimeline.timestamp)]


@router.get("/api/incidents/{iid}/findings")
def findings(iid: str):
    with SessionLocal() as db:
        if not db.get(Incident, iid): raise HTTPException(404, "not found")
        return [ser(f) for f in db.query(InvestigationFinding).filter(InvestigationFinding.incident_id == iid).order_by(InvestigationFinding.created_at)]


@router.get("/api/agents/pipeline")
def pipeline(): return {"agents": AGENT_ORDER, "statuses": ["WAITING", "RUNNING", "COMPLETED", "FAILED"]}


@router.get("/api/tools")
def tools(): return rt.default.registry.describe()


@router.get("/api/policy")
def policy(): return rt.default.guard.policy_snapshot()


@router.get("/api/simulation/state")
def sim_state():
    with SessionLocal() as db: return simulation_state(db)
