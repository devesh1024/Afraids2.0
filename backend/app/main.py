"""FastAPI app: REST + WebSocket. Simulation -> agents -> DB -> WS broadcast."""
import asyncio, logging, os
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from .db import *
from .agents import SupervisorAgent, ANOMALY, TI
from .agentic import runtime as rt
from .agentic.api import router as agentic_router
from .agentic.approvals import Conflict, NotFound
from .agentic.guardrails import PolicyViolation
from .chain import incident_events, build_graph, reconstruct_chain
from .intel import KB
from .simulator import SCENARIOS

log = logging.getLogger("api")
app = FastAPI(title="AFRAIDS SOC API", version="1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
AGENT_MODE = os.getenv("AGENT_MODE", "workflow").lower()
supervisor, SIMS = (SupervisorAgent() if AGENT_MODE == "legacy" else rt.default.supervisor), {}
init_db()

class Hub:
    def __init__(self): self.conns: set[WebSocket] = set()
    async def broadcast(self, msg: dict):
        for c in list(self.conns):
            try: await c.send_json(msg)
            except Exception: self.conns.discard(c)
hub = Hub()

def _sink(msg: dict):
    """Called from worker threads by the agentic publisher; hops onto the event loop to broadcast over WebSocket."""
    loop = rt.LOOP
    if loop is not None and loop.is_running(): asyncio.run_coroutine_threadsafe(hub.broadcast(msg), loop)
rt.default.publisher.sink = _sink
app.include_router(agentic_router)

def ser(o, skip=()): return {c.name: (getattr(o, c.name).isoformat() if isinstance(getattr(o, c.name), datetime) else getattr(o, c.name)) for c in o.__table__.columns if c.name not in skip}

class SimReq(BaseModel): scenario: str

def _process_event(sid, kw):
    with SessionLocal() as db:
        e = SecurityEvent(simulation_id=sid, **kw); db.add(e); db.flush(); ev = ser(e)
        res = supervisor.process(db, e); db.commit()
        return ev, res, [ser(db.get(Incident, i)) for i in res["incidents"]]

async def run_sim(sid, scenario):
    rt.LOOP = asyncio.get_running_loop(); SIMS[sid]["status"] = "running"
    try:
        for delay, kw in SCENARIOS[scenario]():
            await asyncio.sleep(delay)
            ev, res, incs = await asyncio.to_thread(_process_event, sid, kw); SIMS[sid]["events"] += 1
            await hub.broadcast({"type": "event", "data": ev})
            for a in res["alerts"]: await hub.broadcast({"type": "alert", "data": a})
            for i in incs: await hub.broadcast({"type": "incident", "data": i})
        SIMS[sid]["status"] = "completed"
    except Exception as ex:
        log.exception("sim failed"); SIMS[sid].update(status="failed", error=str(ex))
    await hub.broadcast({"type": "simulation", "data": SIMS[sid]})

@app.get("/api/health")
def health(): return {"status": "ok", "time": datetime.utcnow().isoformat()}

@app.post("/api/simulations/start")
async def start(req: SimReq):
    if req.scenario not in SCENARIOS: raise HTTPException(422, f"scenario must be one of {list(SCENARIOS)}")
    sid = uid(); SIMS[sid] = {"id": sid, "scenario": req.scenario, "status": "queued", "events": 0, "started_at": datetime.utcnow().isoformat()}
    asyncio.create_task(run_sim(sid, req.scenario)); return SIMS[sid]

@app.get("/api/simulations")
def sims(): return {"available": list(SCENARIOS), "runs": list(SIMS.values())}

@app.get("/api/events")
def events(limit: int = 100):
    with SessionLocal() as db: return [ser(e) for e in db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(limit)]

@app.get("/api/alerts")
def alerts():
    with SessionLocal() as db: return [ser(a) for a in db.query(Alert).order_by(Alert.created_at.desc())]

@app.get("/api/incidents")
def incidents():
    with SessionLocal() as db: return [ser(i) for i in db.query(Incident).order_by(Incident.updated_at.desc())]

@app.get("/api/incidents/{iid}")
def incident(iid: str):
    with SessionLocal() as db:
        i = db.get(Incident, iid)
        if not i: raise HTTPException(404, "not found")
        return {**ser(i), "alerts": [ser(a) for a in i.alerts], "recommendations": [ser(r) for r in i.recommendations]}

@app.get("/api/agents/executions")
def execs(limit: int = 100, incident_id: str | None = None, run_id: str | None = None):
    with SessionLocal() as db:
        q = db.query(AgentExecution)
        if incident_id: q = q.filter(AgentExecution.incident_id == incident_id)
        if run_id: q = q.filter(AgentExecution.run_id == run_id)
        return [ser(x) for x in q.order_by(AgentExecution.started_at.desc()).limit(limit)]

@app.get("/api/stats")
def stats():
    with SessionLocal() as db:
        inc = db.query(Incident).all()
        dist = {l: sum(1 for i in inc if i.risk_level == l) for l in ("low", "medium", "high", "critical")}
        return {"events": db.query(SecurityEvent).count(), "alerts": db.query(Alert).count(), "incidents": len(inc), "risk_distribution": dist}

@app.post("/api/responses/{rid}/{decision}")
async def decide(rid: str, decision: str, x_role: str = Header("analyst"), x_actor: str = Header("analyst")):
    """Kept for the Phase 1/2 UI; now goes through the same authorisation, audit and simulation path as /api/incidents/{id}/approve-response."""
    if decision not in ("approve", "reject"): raise HTTPException(422, "approve|reject")
    rt.LOOP = asyncio.get_running_loop()
    def work():
        with SessionLocal() as db:
            r = db.get(ResponseRecommendation, rid)
            if not r: raise HTTPException(404, "not found")
            svc = rt.default.decisions
            try: res = svc.approve(db, r.incident_id, rid, x_actor, x_role) if decision == "approve" else svc.reject(db, r.incident_id, rid, x_actor, x_role)
            except NotFound as e: raise HTTPException(404, str(e))
            except Conflict as e: raise HTTPException(409, str(e))
            except PolicyViolation as e: raise HTTPException(e.status, dict(code=e.code, message=e.message))
            return {**ser(db.get(ResponseRecommendation, rid)), "note": res["note"]}
    out = await asyncio.to_thread(work)
    await hub.broadcast({"type": "response", "data": out}); return out

@app.websocket("/ws")
async def ws(w: WebSocket):
    await w.accept(); hub.conns.add(w); rt.LOOP = asyncio.get_running_loop()
    try:
        while True: await w.receive_text()
    except WebSocketDisconnect: hub.conns.discard(w)

@app.get("/api/responses")
def responses():
    with SessionLocal() as db:
        return [{**ser(r), "incident_title": r.incident.title} for r in db.query(ResponseRecommendation).order_by(ResponseRecommendation.id)]


def _seed():
    with SessionLocal() as db:
        for k, v in KB.items():
            if not db.get(AttackTechnique, k): db.add(AttackTechnique(technique_id=k, name=v["name"], tactic=v["tactic"], description=v["description"]))
        db.commit()
_seed()

def _inc(db, iid):
    i = db.get(Incident, iid)
    if not i: raise HTTPException(404, "not found")
    return i

@app.get("/api/incidents/{iid}/graph")
def inc_graph(iid: str):
    with SessionLocal() as db: return build_graph(db, _inc(db, iid))

@app.get("/api/incidents/{iid}/chain")
def inc_chain(iid: str):
    with SessionLocal() as db: return {"steps": reconstruct_chain(incident_events(db, _inc(db, iid)))}

class TrainReq(BaseModel): samples: int = 3000; seed: int = 42
class PredictReq(BaseModel): features: dict | None = None; event_id: str | None = None

@app.get("/api/ml/status")
def ml_status(): return {"model_version": ANOMALY.version, "model_path": ANOMALY.path, "note": "Trained on synthetic baselines; heuristic, not a proven detector."}

@app.post("/api/ml/train")
def ml_train(r: TrainReq): return ANOMALY.train(r.samples, r.seed)

@app.post("/api/ml/predict")
def ml_predict(r: PredictReq):
    from .ml import extract_features
    if r.features is not None: return ANOMALY.predict(r.features)
    with SessionLocal() as db:
        e = db.get(SecurityEvent, r.event_id or "")
        if not e: raise HTTPException(404, "provide features or a valid event_id")
        f = extract_features(db, e); return {"features": f, **ANOMALY.predict(f)}

@app.get("/api/ti/{kind}/{value}")
def ti(kind: str, value: str):
    fn = {"ip": TI.lookup_ip, "domain": TI.lookup_domain, "hash": TI.lookup_hash}.get(kind)
    if not fn: raise HTTPException(422, "kind: ip|domain|hash")
    from dataclasses import asdict
    i = fn(value); return {"found": i is not None, "indicator": asdict(i) if i else None}

@app.get("/api/attack/techniques")
def techniques(): return list(KB.values())
