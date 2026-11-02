"""Phase 3 workflow agents.

Pattern: an agent (1) records an AgentExecution (RUNNING), (2) gathers evidence ONLY via BoundTools, (3) delegates judgment to the Reasoner,
(4) records the outcome (COMPLETED/FAILED) with tools used, findings, evidence IDs and confidence, (5) streams status over the publisher.
Agents never mutate incident-level state; the SupervisorAgent applies results.
"""
from __future__ import annotations
import logging, time
from collections import Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from sqlalchemy.exc import SQLAlchemyError
from ..db import AgentExecution, IncidentTimeline, InvestigationFinding
from ..ml import extract_features
from ..rules import SCORING, anomaly_strength
from .config import Settings
from .events import EventPublisher
from .guardrails import Guardrails
from .reasoning import LoopState, Reasoner
from .tools import BoundTools, ToolBudget, ToolContext, ToolRegistry, ToolServices
from .util import is_public_ip, jsonable, real_name, utcnow

log = logging.getLogger("agentic.agents")
AGENT_ORDER = ["SupervisorAgent", "DetectionAgent", "LogAnalysisAgent", "ThreatIntelligenceAgent", "InvestigationAgent", "AttackGraphAgent", "RiskAssessmentAgent", "ResponseAgent"]


class AgentError(Exception): """Raised by an agent when it cannot produce a usable result."""


class AgentFailure(Exception):
    """Raised by the supervisor when a *critical* agent failed (the run ends in FAILED)."""


@dataclass
class AgentDeps:
    settings: Settings; guard: Guardrails; registry: ToolRegistry; reasoner: Reasoner; publisher: EventPublisher; services: ToolServices


@dataclass
class RunContext:
    db: object; settings: Settings; event: object; run_id: str; budget: ToolBudget; started_at: datetime
    incident: object = None; incident_id: str | None = None; alerts: list = field(default_factory=list); seq: int = 0
    iteration: int = 0; iterations_done: int = 0; new_event_count: int = 0
    detection: dict = field(default_factory=dict); log_context: dict = field(default_factory=dict); ti: dict = field(default_factory=dict)
    ti_checked: set = field(default_factory=set); seen_event_ids: set = field(default_factory=set)
    events: list = field(default_factory=list); findings: list = field(default_factory=list); baseline: dict | None = None
    techniques: list = field(default_factory=list); graph: dict = field(default_factory=dict); risk: dict = field(default_factory=dict)
    verification: dict = field(default_factory=dict); plan: dict = field(default_factory=dict); degraded: list = field(default_factory=list)

    def next_seq(self) -> int: self.seq += 1; return self.seq

    def alert_views(self) -> list:
        return [dict(id=a.id, rule_id=a.rule_id, name=a.rule, severity=a.severity, confidence=a.confidence or 0.0, technique=a.technique, uncertain=bool(a.uncertain),
                     anomaly_score=a.anomaly_score, event_id=a.event_id, evidence=list(a.evidence or [])) for a in self.alerts]

    def case_file(self) -> dict:
        return dict(alerts=self.alert_views(), findings=self.findings, event_count=len(self.events))


@dataclass
class AgentOutcome:
    agent: str; critical: bool = True; status: str = "RUNNING"; output: dict = field(default_factory=dict); confidence: float | None = None
    input_summary: str = ""; output_summary: str = ""; evidence: list = field(default_factory=list); evidence_ids: list = field(default_factory=list)
    findings: list = field(default_factory=list); error: str | None = None; execution_id: str | None = None; duration_ms: float = 0.0; tools_used: list = field(default_factory=list)


def _ext_ips(events) -> list:
    out: list = []
    for e in events:
        if e and is_public_ip(e.get("src_ip")) and e["src_ip"] not in out: out.append(e["src_ip"])
    return out


class WorkflowAgent:
    name = "WorkflowAgent"; critical = True

    def __init__(self, deps: AgentDeps):
        self.deps = deps; self.settings, self.guard, self.registry = deps.settings, deps.guard, deps.registry
        self.reasoner, self.publisher, self.services = deps.reasoner, deps.publisher, deps.services

    # ---- lifecycle helpers (also used by the SupervisorAgent for its own record)
    def _emit(self, rc: RunContext, ex_id: str, status: str, out: AgentOutcome | None = None, iteration=None, sequence=None) -> None:
        d = dict(incident_id=rc.incident_id, run_id=rc.run_id, agent=self.name, status=status, execution_id=ex_id, iteration=iteration, sequence=sequence, timestamp=utcnow().isoformat())
        if out is not None:
            d.update(duration_ms=out.duration_ms, confidence=out.confidence, summary=out.output_summary, tools=len(out.tools_used), findings=len(out.findings), error=out.error)
        self.publisher.publish("agent_update", d)

    def _begin(self, rc: RunContext, iteration: int | None = None, sequence: int | None = None) -> str:
        seq = rc.next_seq() if sequence is None else sequence
        ex = AgentExecution(agent=self.name, status="RUNNING", started_at=utcnow(), incident_id=rc.incident_id, run_id=rc.run_id, sequence=seq, iteration=iteration,
                            tools_used=[], evidence=[], evidence_ids=[], output={})
        rc.db.add(ex); rc.db.flush(); ex_id = ex.id; rc.db.commit()
        self._emit(rc, ex_id, "RUNNING", iteration=iteration, sequence=seq)
        if self.settings.step_delay_ms: time.sleep(self.settings.step_delay_ms / 1000)
        return ex_id

    def _finish(self, rc: RunContext, ex_id: str, out: AgentOutcome, status: str, started_at: datetime | None = None, iteration: int | None = None) -> None:
        db = rc.db; out.status = status; ex = db.get(AgentExecution, ex_id)
        ex.status, ex.finished_at, ex.confidence = status, utcnow(), out.confidence
        if started_at: ex.started_at = started_at
        out.duration_ms = round((ex.finished_at - ex.started_at).total_seconds() * 1000, 1)
        ex.output = jsonable(out.output); ex.evidence = jsonable(out.evidence); ex.evidence_ids = jsonable(out.evidence_ids); ex.tools_used = jsonable(out.tools_used)
        ex.input_summary, ex.output_summary, ex.error = out.input_summary, out.output_summary, out.error
        for f in out.findings:
            db.add(InvestigationFinding(incident_id=rc.incident_id, execution_id=ex_id, run_id=rc.run_id, iteration=iteration, description=f["description"], evidence=jsonable(f.get("evidence", [])),
                                        severity=f["severity"], confidence=f["confidence"], source=f["source"], contradicts=int(bool(f.get("contradicts"))), evidence_ids=jsonable(f.get("evidence_ids", []))))
        if rc.incident_id:
            db.add(IncidentTimeline(incident_id=rc.incident_id, kind="agent", message=f"{self.name} {status}" + (f": {out.output_summary}" if out.output_summary else "") + (f" — {out.error}" if out.error else ""),
                                    detail={"run_id": rc.run_id, "execution_id": ex_id}))
        db.commit()
        self._emit(rc, ex_id, status, out, iteration=iteration, sequence=ex.sequence)

    def run(self, rc: RunContext, iteration: int | None = None) -> AgentOutcome:
        out = AgentOutcome(agent=self.name, critical=self.critical); ex_id = self._begin(rc, iteration); out.execution_id = ex_id
        tools = BoundTools(self.registry, ToolContext(db=rc.db, guard=self.guard, budget=rc.budget, agent=self.name, services=self.services,
                                                     incident_id=rc.incident_id, execution_id=ex_id, run_id=rc.run_id))
        t0 = time.perf_counter(); status = "COMPLETED"
        try: self._run(rc, tools, out)
        except Exception as e:
            log.exception("%s failed", self.name); status, out.error = "FAILED", f"{type(e).__name__}: {e}"
            if isinstance(e, SQLAlchemyError): rc.db.rollback()
        out.tools_used = tools.used()
        if status == "FAILED" and not out.output_summary: out.output_summary = "failed"
        self._finish(rc, ex_id, out, status, iteration=iteration)
        out.duration_ms = out.duration_ms or round((time.perf_counter() - t0) * 1000, 1)
        return out

    def _run(self, rc: RunContext, tools: BoundTools, out: AgentOutcome) -> None: raise NotImplementedError


# ------------------------------------------------------------------ DetectionAgent
class DetectionAgent(WorkflowAgent):
    """Rule engine (primary) + Isolation Forest (corroboration / ML-only fallback). Uses the detection engines directly; may read baselines via a tool."""
    name = "DetectionAgent"

    def _run(self, rc, tools, out):
        e, db = rc.event, rc.db; svc = self.services
        feats = extract_features(db, e); an = svc.anomaly.predict(feats); hits = [asdict(h) for h in svc.rules.evaluate(db, e)]
        if not hits and an["is_anomaly"]:
            pts = max(10, round(SCORING["anomaly_ml_only_cap"] * anomaly_strength(an["anomaly_score"])))
            hits.append(dict(rule_id="ML001", name="ML behavioural anomaly", severity="medium", kind="ml", points=pts, confidence=0.5, technique=None, uncertain=True,
                             evidence=[f"Isolation Forest score {an['anomaly_score']} (model {an['model_version']})",
                                       "Contributing: " + ", ".join(f"{c['feature']}={c['value']:g} (z={c['z']})" for c in an["contributing_features"])]))
        if real_name(e.user): tools.call("get_security_baseline", kind="user", value=e.user)
        rc.detection = dict(hits=hits, anomaly=an, features=feats)
        out.output = dict(hits=hits, anomaly=an, features=feats)
        out.confidence = max([h["confidence"] for h in hits], default=1.0)
        out.evidence = [x for h in hits for x in h["evidence"]] or ["No rule or anomaly signal"]; out.evidence_ids = [f"event:{e.id}"]
        out.input_summary = f"{e.event_type} {e.user}@{e.host} {e.src_ip}→{e.dst_ip}"
        out.output_summary = f"{len(hits)} detection(s): " + ", ".join(h["rule_id"] for h in hits) if hits else "no detection signal"


# ------------------------------------------------------------------ LogAnalysisAgent
class LogAnalysisAgent(WorkflowAgent):
    name = "LogAnalysisAgent"; critical = False

    def _run(self, rc, tools, out):
        e = rc.event; end = e.timestamp + timedelta(seconds=1); win = self.settings.window_for(1)
        host = tools.call("search_security_events", host=e.host, end=end, window_minutes=win, limit=200)
        hh = tools.call("get_host_history", host=e.host, end=end, window_minutes=win)
        uh = tools.call("get_user_history", user=e.user, end=end, window_minutes=win) if real_name(e.user) else None
        results = [r for r in (host, hh, uh) if r is not None]
        if not any(r.ok for r in results): raise AgentError("no log data could be retrieved: " + "; ".join(r.error or "?" for r in results))
        events = host.data["events"] if host.ok else []; by = Counter(x["event_type"] for x in events)
        rc.log_context = dict(events=events, by_type=dict(by), host_history=hh.data if hh.ok else None, user_history=uh.data if uh and uh.ok else None)
        out.output = dict(host_events=len(events), by_type=dict(by), distinct_sources=sorted({x["src_ip"] for x in events if x["src_ip"]}), window_minutes=win,
                          host_prior_incidents=(hh.data or {}).get("prior_incidents") if hh.ok else None, user_prior_incidents=(uh.data or {}).get("prior_incidents") if uh and uh.ok else None)
        out.confidence = round(tools.success_ratio(), 2); out.evidence_ids = [f"event:{x['id']}" for x in events[-10:]]
        out.evidence = [f"{len(events)} event(s) on {e.host} in the last {win} min: " + (", ".join(f"{k}×{v}" for k, v in by.most_common(4)) or "none")]
        out.input_summary = f"host {e.host}, user {e.user}, window {win} min"; out.output_summary = f"{len(events)} host event(s); types: " + (", ".join(by) or "none")


# ------------------------------------------------------------------ ThreatIntelligenceAgent
class ThreatIntelligenceAgent(WorkflowAgent):
    name = "ThreatIntelligenceAgent"; critical = False

    def _run(self, rc, tools, out):
        e = rc.event; evs = [{"src_ip": e.src_ip, "dst_ip": e.dst_ip, "meta": e.meta or {}}] + list(rc.log_context.get("events", []))
        cand: list = []
        for x in evs:
            for ip in (x.get("src_ip"), x.get("dst_ip")):
                if is_public_ip(ip) and ip not in cand: cand.append(ip)
        matches: dict = {}; lookups = 0
        for ip in cand[:self.settings.max_ti_lookups]:
            r = tools.call("lookup_ip_reputation", ip=ip); lookups += 1; rc.ti_checked.add(ip)
            if r.ok and r.data["found"]: matches[ip] = r.data["indicator"]
        doms, hashes = set(), set()
        for x in evs:
            m = x.get("meta") or {}
            if isinstance(m.get("domain"), str): doms.add(m["domain"])
            for k in ("hash", "sha256", "sha1", "md5"):
                if isinstance(m.get(k), str): hashes.add(m[k])
        for d in sorted(doms)[:3]:
            r = tools.call("lookup_domain_reputation", domain=d); lookups += 1
            if r.ok and r.data["found"]: matches[d] = r.data["indicator"]
        for h in sorted(hashes)[:3]:
            r = tools.call("lookup_hash_reputation", hash=h); lookups += 1
            if r.ok and r.data["found"]: matches[h] = r.data["indicator"]
        rc.ti.update(matches)
        out.output = dict(matches=matches, lookups=lookups, checked=sorted(rc.ti_checked))
        out.evidence = [f"{k}: {v['category']} (reputation {v['reputation']}, {v['source']})" for k, v in matches.items()] or ["No IOC matches (offline synthetic feed)"]
        out.evidence_ids = [f"ioc:{k}" for k in matches]; out.confidence = 0.9 if matches else 0.5
        out.input_summary = f"{len(cand)} candidate indicator(s)"; out.output_summary = f"{len(matches)} IOC match(es) from {lookups} lookup(s)"


# ------------------------------------------------------------------ InvestigationAgent
class InvestigationAgent(WorkflowAgent):
    """Correlates event sequences, user/host behaviour, IP and process relationships, threat intel and ATT&CK mappings into InvestigationFindings."""
    name = "InvestigationAgent"

    def _run(self, rc, tools, out):
        s, e, it = self.settings, rc.event, rc.iteration; end = e.timestamp + timedelta(seconds=1); window = s.window_for(it); alerts = rc.alert_views()
        user = e.user if real_name(e.user) else None; events: dict = {}

        def collect(r):
            if r.ok:
                for ev in r.data["events"]: events[ev["id"]] = ev
        collect(tools.call("search_security_events", host=e.host, end=end, window_minutes=window, limit=300))
        if user: collect(tools.call("search_security_events", user=user, end=end, window_minutes=window, limit=300))
        alert_event_ids = {a["event_id"] for a in alerts if a.get("event_id")}
        for ip in _ext_ips([events.get(i) for i in alert_event_ids] + [{"src_ip": e.src_ip}])[:3]:
            collect(tools.call("search_security_events", ip=ip, end=end, window_minutes=window, limit=300))
        ids = set(events); rc.new_event_count = len(ids - rc.seen_event_ids); rc.seen_event_ids |= ids
        rc.events = sorted(events.values(), key=lambda x: x["timestamp"])
        start_iso = min([events[i]["timestamp"] for i in alert_event_ids if i in events] or [e.timestamp.isoformat()])
        prior = None
        if user:
            r = tools.call("search_security_events", user=user, event_type="login_success", end=datetime.fromisoformat(start_iso) - timedelta(seconds=1), window_minutes=43200, limit=500)
            if r.ok: prior = dict(Counter(x["src_ip"] for x in r.data["events"]))
        uh = tools.call("get_user_history", user=user, end=end, window_minutes=window) if user else None
        hh = tools.call("get_host_history", host=e.host, end=end, window_minutes=window)
        rel = tools.call("get_related_incidents", incident_id=rc.incident_id)
        if it == 1 and user:
            b = tools.call("get_security_baseline", kind="user", value=user); rc.baseline = b.data if b.ok else None
        techs, seen = [], set()
        for a in alerts:
            t = a.get("technique")
            if t and t not in seen:
                seen.add(t); r = tools.call("query_attack_technique", technique_id=t)
                if r.ok and r.data.get("found"): techs.append(dict(id=t, name=r.data["name"], tactic=r.data["tactic"], weight=r.data["severity_weight"], uncertain=a["uncertain"]))
        for ip in [x for x in _ext_ips(events.values()) if x not in rc.ti_checked][:3]:
            r = tools.call("lookup_ip_reputation", ip=ip); rc.ti_checked.add(ip)
            if r.ok and r.data["found"]: rc.ti[ip] = r.data["indicator"]
        bundle = dict(alerts=alerts, events=rc.events, user=user, host=e.host, user_history=uh.data if uh and uh.ok else None, host_history=hh.data if hh.ok else None,
                      prior_logins_by_ip=prior, ti=rc.ti, techniques=techs, related=rel.data["incidents"] if rel.ok else [], incident_start=start_iso)
        drafts = self.reasoner.analyze(bundle)
        out.findings = [dict(asdict(d) if hasattr(d, "__dataclass_fields__") else d, iteration=it) for d in drafts]; rc.findings = out.findings
        good = [f["confidence"] for f in out.findings if not f.get("contradicts")]
        out.confidence = round(sum(good) / len(good), 2) if good else 0.3
        out.evidence_ids = list(dict.fromkeys(i for f in out.findings for i in f.get("evidence_ids", [])))[:50]
        out.evidence = [f["description"] for f in out.findings[:6]]
        src = Counter(f["source"] for f in out.findings)
        out.output = dict(iteration=it, window_minutes=window, events_correlated=len(events), new_events=rc.new_event_count, finding_count=len(out.findings),
                          sources=dict(src), contradictions=sum(1 for f in out.findings if f.get("contradicts")), attacker_ips=_ext_ips(events.values())[:5])
        out.input_summary = f"iteration {it}/{s.effective_max_iterations}, window {window} min, {len(alerts)} alert(s)"
        out.output_summary = f"{len(out.findings)} finding(s) from {len(events)} correlated event(s) ({rc.new_event_count} new)"


# ------------------------------------------------------------------ AttackGraphAgent
class AttackGraphAgent(WorkflowAgent):
    name = "AttackGraphAgent"; critical = False

    def _run(self, rc, tools, out):
        r = tools.call("build_attack_graph", incident_id=rc.incident_id)
        if not r.ok: raise AgentError(r.error or "attack graph unavailable")
        d = r.data; rc.techniques = d["techniques"]; rc.graph = dict(nodes=d["node_count"], edges=d["edge_count"], chain=d["chain_labels"])
        out.output = dict(nodes=d["node_count"], edges=d["edge_count"], chain_steps=len(d["chain"]), chain=d["chain_labels"], techniques=[t["id"] for t in d["techniques"]])
        out.confidence = 0.8 if len(d["chain"]) >= 2 else 0.5; out.evidence = ["Chain: " + " → ".join(d["chain_labels"])] if d["chain_labels"] else ["No chain reconstructed"]
        out.evidence_ids = [f"event:{s['event_id']}" for s in d["chain"]][:20]
        out.input_summary = f"incident {rc.incident_id}"; out.output_summary = f"{d['node_count']} nodes, {d['edge_count']} edges, {len(d['chain'])} chain step(s)"


# ------------------------------------------------------------------ RiskAssessmentAgent
class RiskAssessmentAgent(WorkflowAgent):
    name = "RiskAssessmentAgent"

    def _run(self, rc, tools, out):
        r = tools.call("calculate_risk", incident_id=rc.incident_id, run_id=rc.run_id)
        if not r.ok: raise AgentError(r.error or "risk calculation unavailable")
        rc.risk = r.data["risk"]; k = rc.risk
        out.output = dict(risk_score=k["risk_score"], severity=k["severity"], confidence=k["confidence"], risk_factors=k["risk_factors"], inputs=r.data["inputs"])
        out.confidence = k["confidence"]; out.evidence = [f"{f['label']}: {f['points']:+d}" for f in k["risk_factors"]]
        out.evidence_ids = [f"alert:{a.id}" for a in rc.alerts]; out.input_summary = f"{len(rc.alerts)} alert(s), {len(rc.findings)} finding(s)"
        out.output_summary = f"risk {k['risk_score']} ({k['severity']}), confidence {k['confidence']}"


# ------------------------------------------------------------------ ResponseAgent
class ResponseAgent(WorkflowAgent):
    """PLANS responses only. It cannot execute anything: execution requires human approval and happens in SimulationResponseExecutor."""
    name = "ResponseAgent"

    def _run(self, rc, tools, out):
        rel = tools.call("get_related_incidents", incident_id=rc.incident_id)
        e, v = rc.event, rc.verification or {}
        case = dict(incident_id=rc.incident_id, risk=rc.risk, needs_review=bool(v.get("needs_review")), alerts=rc.alert_views(), events=rc.events, ti=rc.ti,
                    contradictions=v.get("contradictions", []), primary_user=e.user, primary_host=e.host, related=rel.data["incidents"] if rel.ok else [])
        plan = self.reasoner.plan_responses(case); pd = plan.to_dict(); rc.plan = pd
        out.output = pd; acts = pd["actions"]
        out.confidence = round(sum(a["confidence"] for a in acts) / len(acts), 2) if acts else 1.0
        out.evidence = [f"{a['action']} → {a['target']} ({a['approval_level']} approval)" for a in acts] or ["No response required"]
        out.evidence_ids = list(dict.fromkeys(i for a in acts for i in a["evidence_ids"]))[:30]
        out.input_summary = f"risk {rc.risk.get('risk_score')} ({rc.risk.get('severity')}), verdict {v.get('verdict', 'n/a')}"
        out.output_summary = f"{len(acts)} action(s) recommended" + (f", {len(pd['withheld'])} withheld pending review" if pd["withheld"] else "") + (f", {len(pd['rejected_by_policy'])} rejected by policy" if pd["rejected_by_policy"] else "")
