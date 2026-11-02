"""Agent layer: deterministic agents behind a common interface (LLM agents can subclass BaseAgent later)."""
import logging
from datetime import datetime, timedelta
from typing import Any
from pydantic import BaseModel, Field
from dataclasses import asdict
from .db import *
from .intel import KB, LocalThreatIntel
from .ml import AnomalyDetectionService, extract_features, ext
from .rules import RuleEngine, SCORING, anomaly_strength, score_incident
from .chain import incident_events, build_graph, reconstruct_chain, to_networkx

log = logging.getLogger("agents")
ANOMALY, TI, RULES = AnomalyDetectionService(), LocalThreatIntel(), RuleEngine()
class AgentResult(BaseModel):
    agent: str; status: str = "success"; confidence: float | None = None
    started_at: datetime; finished_at: datetime | None = None
    output: dict[str, Any] = Field(default_factory=dict); evidence: list[str] = Field(default_factory=list); error: str | None = None

class BaseAgent:
    """Input: dict context. Output: AgentResult. Subclasses implement _run."""
    name = "BaseAgent"
    def run(self, db, ctx: dict) -> AgentResult:
        r = AgentResult(agent=self.name, started_at=datetime.utcnow())
        try: self._run(db, ctx, r)
        except Exception as e:
            log.exception("%s failed", self.name); r.status, r.error = "failed", str(e)
        r.finished_at = datetime.utcnow()
        db.add(AgentExecution(agent=r.agent, status=r.status, confidence=r.confidence, started_at=r.started_at,
                              finished_at=r.finished_at, output=r.output, evidence=r.evidence, error=r.error))
        return r
    def _run(self, db, ctx, r): raise NotImplementedError

class DetectionAgent(BaseAgent):
    """Hybrid: rule hits (primary) + Isolation Forest anomaly (corroboration / ML-only fallback). Scoring: see rules.py docstring."""
    name = "DetectionAgent"
    def _run(self, db, ctx, r):
        e = ctx["event"]; feats = extract_features(db, e); an = ANOMALY.predict(feats); hits = [asdict(h) for h in RULES.evaluate(db, e)]
        if not hits and an["is_anomaly"]:
            pts = max(10, round(SCORING["anomaly_ml_only_cap"] * anomaly_strength(an["anomaly_score"])))
            hits.append(dict(rule_id="ML001", name="ML behavioural anomaly", severity="medium", kind="ml", points=pts, confidence=0.5, technique=None, uncertain=True,
                             evidence=[f"Isolation Forest score {an['anomaly_score']} (model {an['model_version']})", "Contributing: " + ", ".join(f"{c['feature']}={c['value']:g} (z={c['z']})" for c in an["contributing_features"])]))
        r.output = {"hits": hits, "anomaly": an, "features": feats}; r.confidence = max([h["confidence"] for h in hits], default=1.0)
        r.evidence = [x for h in hits for x in h["evidence"]] or ["No rule or anomaly signal"]

class LogAnalysisAgent(BaseAgent):
    name = "LogAnalysisAgent"
    def _run(self, db, ctx, r):
        e = ctx["event"]; n = db.query(SecurityEvent).filter(SecurityEvent.host == e.host).count()
        r.output = {"host_event_count": n}; r.evidence = [f"{n} events seen for host {e.host}"]; r.confidence = 1.0

class ThreatIntelligenceAgent(BaseAgent):
    name = "ThreatIntelligenceAgent"
    def _run(self, db, ctx, r):
        e = ctx["event"]; m = {ip: asdict(i) for ip in {e.src_ip, e.dst_ip} if (i := TI.lookup_ip(ip))}
        r.output = {"matches": m}; r.evidence = [f"{k}: {v['category']} (reputation {v['reputation']}, {v['source']})" for k, v in m.items()] or ["No IOC matches"]; r.confidence = 0.9 if m else 0.5

class InvestigationAgent(BaseAgent):
    """Correlates alerts into incidents by host|user and links evidence."""
    name = "InvestigationAgent"
    def _run(self, db, ctx, r):
        e, a = ctx["event"], ctx["alert"]; key = f"{e.host}|{e.user}"; inc = db.query(Incident).filter(Incident.key == key, Incident.status == "open").first(); new = inc is None
        if new: inc = Incident(key=key, title=f"Suspicious activity on {e.host} ({e.user})"); db.add(inc); db.flush()
        a.incident_id = inc.id; db.add(IncidentEvidence(incident_id=inc.id, event_id=e.id, alert_id=a.id, note=a.evidence[0])); db.flush(); db.refresh(inc)
        r.output = {"incident_id": inc.id, "new": new}; r.evidence = [f"Correlated by key {key}"]; r.confidence = 0.8; ctx["incident"] = inc

class AttackGraphAgent(BaseAgent):
    name = "AttackGraphAgent"
    def _run(self, db, ctx, r):
        inc = ctx["incident"]; seen = {}
        for a in inc.alerts:
            if a.technique and a.technique not in seen: seen[a.technique] = dict(id=a.technique, name=KB[a.technique]["name"], tactic=KB[a.technique]["tactic"], uncertain=bool(a.uncertain))
        inc.techniques = list(seen.values()); g = build_graph(db, inc); G = to_networkx(g); chain = reconstruct_chain(incident_events(db, inc))
        r.output = {"nodes": G.number_of_nodes(), "edges": G.number_of_edges(), "chain_steps": len(chain)}
        r.evidence = ["Chain: " + " → ".join(s["label"] for s in chain)]; r.confidence = 0.8

class RiskAssessmentAgent(BaseAgent):
    name = "RiskAssessmentAgent"
    def _run(self, db, ctx, r):
        inc = ctx["incident"]; ips = {x for e in incident_events(db, inc) for x in (e.src_ip, e.dst_ip)}
        ti = [dict(indicator=i.indicator, reputation=i.reputation, category=i.category) for ip in sorted(ips) if (i := TI.lookup_ip(ip))]
        an = [a.anomaly_score for a in inc.alerts if a.anomaly_score is not None]; inc.anomaly_score = max(an, default=0.0)
        al = [dict(rule_id=a.rule_id, name=a.rule, points=a.points, evidence=a.evidence[0]) for a in inc.alerts]
        inc.risk_score, inc.risk_level, inc.risk_factors = score_incident(al, inc.anomaly_score, bool(an), ti, len(inc.techniques or []))
        inc.updated_at = datetime.utcnow(); db.add(RiskAssessment(incident_id=inc.id, score=inc.risk_score, level=inc.risk_level, factors=inc.risk_factors))
        r.output = {"score": inc.risk_score, "level": inc.risk_level, "factors": inc.risk_factors}; r.evidence = [f"{f['label']}: +{f['points']}" for f in inc.risk_factors]; r.confidence = 0.75

class ResponseAgent(BaseAgent):
    name = "ResponseAgent"
    PLAYBOOK = {"R001": "Lock account & reset credentials", "R002": "Lock account & reset credentials", "R003": "Force MFA re-verification for user", "R004": "Isolate host & revoke elevated privileges",
                "R005": "Kill process & quarantine host", "R006": "Restrict file-share access for user", "R007": "Block outbound destination & isolate host", "R008": "Block source IP at firewall",
                "ML001": "Increase monitoring & review user activity"}
    def _run(self, db, ctx, r):
        inc, a = ctx["incident"], ctx["alert"]; act = self.PLAYBOOK[a.rule_id]
        if act not in {x.action for x in inc.recommendations}: db.add(ResponseRecommendation(incident_id=inc.id, action=act, rationale=f"Triggered by {a.rule_id} {a.rule}: {a.evidence[0]}"))
        r.output = {"recommended": act, "requires_approval": True}; r.evidence = [a.evidence[0]]; r.confidence = a.confidence

class SupervisorAgent(BaseAgent):
    """Orchestrates the pipeline per event. A Gemini planner can replace this class later."""
    name = "SupervisorAgent"
    def __init__(self): self.det, self.log, self.ti = DetectionAgent(), LogAnalysisAgent(), ThreatIntelligenceAgent()
    def _run(self, db, ctx, r): pass
    def _register(self, db, e):
        def up(M, col, val, **kw):
            if val and val != "n/a" and not db.query(M).filter(getattr(M, col) == val).first(): db.add(M(**{col: val}, **kw))
        up(User, "username", e.user); up(Host, "hostname", e.host)
        for ip in (e.src_ip, e.dst_ip): up(IPAddress, "address", ip, internal=int(not ext(ip)))
        for k, v in (("user", e.user), ("host", e.host), ("ip", e.src_ip), ("ip", e.dst_ip)):
            if v and v != "n/a" and not db.query(Entity).filter(Entity.kind == k, Entity.value == v).first(): db.add(Entity(kind=k, value=v))
        if (e.meta or {}).get("process"): db.add(Process(name=e.meta["process"], host=e.host))
    def process(self, db, e: SecurityEvent) -> dict:
        self._register(db, e); ctx = {"event": e}; self.log.run(db, ctx); tir = self.ti.run(db, ctx); ctx["ti"] = tir.output["matches"]
        res = self.det.run(db, ctx); an = ctx["anomaly"] = res.output["anomaly"]; out = {"alerts": [], "incidents": set()}
        for h in res.output["hits"]:
            a = Alert(rule=h["name"], rule_id=h["rule_id"], severity=h["severity"], confidence=h["confidence"], technique=h["technique"], uncertain=int(h["uncertain"]), points=h["points"],
                      anomaly_score=an["anomaly_score"] if an["is_anomaly"] else None, event_id=e.id,
                      evidence=h["evidence"] + [f"Threat intel: {k} {v['category']} (reputation {v['reputation']})" for k, v in ctx["ti"].items()]); db.add(a); db.flush(); ctx["alert"] = a
            for ag in (InvestigationAgent(), AttackGraphAgent(), RiskAssessmentAgent(), ResponseAgent()): ag.run(db, ctx)
            out["alerts"].append({"id": a.id, "rule": a.rule, "rule_id": a.rule_id, "severity": a.severity}); out["incidents"].add(ctx["incident"].id)
        out["incidents"] = list(out["incidents"]); db.commit(); return out
