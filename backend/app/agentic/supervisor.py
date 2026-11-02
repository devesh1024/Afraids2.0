"""SupervisorAgent: receives a suspicious event and orchestrates the whole investigation.

Flow: Detection -> (triage decision) -> incident -> LogAnalysis -> ThreatIntel -> [Investigation <-> Correlation loop, bounded]
      -> AttackGraph -> RiskAssessment -> verification -> Response planning -> proportionality check -> AWAITING_HUMAN_APPROVAL.
It STOPS before any destructive action: responses are only stored as pending recommendations. Hard bounds: max iterations, tool budget.
"""
from __future__ import annotations
import logging
from dataclasses import dataclass, field, asdict
from ..agents import SupervisorAgent as LegacySupervisor
from ..db import (Alert, AgentExecution, AuditLog, Incident, IncidentEvidence, IncidentTimeline, ResponseRecommendation, RiskAssessment, ToolCall, uid)
from .agents import (AGENT_ORDER, AgentDeps, AgentFailure, AgentOutcome, AttackGraphAgent, DetectionAgent, InvestigationAgent, LogAnalysisAgent, ResponseAgent,
                     RiskAssessmentAgent, RunContext, ThreatIntelligenceAgent, WorkflowAgent)
from .guardrails import PolicyViolation
from .reasoning import LoopState
from .risk import techniques_from_alerts
from .states import ACTIVE_STATES, IncidentState as S, InvalidTransition, StateMachine, current_state
from .tools import ToolBudget
from .util import utcnow
from .verification import Verifier

log = logging.getLogger("agentic.supervisor")
_LEGACY = LegacySupervisor()   # reused only for its entity-registration helper (users/hosts/IPs/processes)


@dataclass
class RunResult:
    investigated: bool = False; incident_id: str | None = None; run_id: str | None = None; state: str | None = None
    risk_score: float | None = None; risk_level: str | None = None; verdict: str | None = None; needs_review: bool = False
    iterations: int = 0; stop_reason: str | None = None; alerts: list = field(default_factory=list); degraded: list = field(default_factory=list)
    reason: str | None = None; error: str | None = None; rejected: bool = False

    def to_dict(self) -> dict: return asdict(self)


class SupervisorAgent(WorkflowAgent):
    name = "SupervisorAgent"

    def __init__(self, deps: AgentDeps, state_machine: StateMachine | None = None, verifier: Verifier | None = None):
        super().__init__(deps)
        self.sm = state_machine or StateMachine(deps.publisher); self.verifier = verifier or Verifier(deps.settings)
        self.detection, self.log_agent, self.ti = DetectionAgent(deps), LogAnalysisAgent(deps), ThreatIntelligenceAgent(deps)
        self.investigation, self.graph, self.risk, self.response = InvestigationAgent(deps), AttackGraphAgent(deps), RiskAssessmentAgent(deps), ResponseAgent(deps)

    # ------------------------------------------------------------ legacy-compatible entry point used by main.run_sim
    def process(self, db, e) -> dict:
        r = self.handle_event(db, e)
        return {"alerts": r.alerts, "incidents": [r.incident_id] if r.incident_id else [], "run": r.to_dict()}

    # ------------------------------------------------------------ main entry
    def handle_event(self, db, event) -> RunResult:
        d = self.deps
        try: d.guard.validate_event(event)
        except PolicyViolation as pv:
            db.add(AuditLog(actor=self.name, action="event_rejected", detail=dict(event_id=event.id, code=pv.code, message=pv.message))); db.commit()
            return RunResult(rejected=True, reason=pv.message)
        s = d.settings
        rc = RunContext(db=db, settings=s, event=event, run_id=uid(), budget=ToolBudget(s.max_tool_calls, s.reserved_tool_calls, s.max_tool_calls_per_agent), started_at=utcnow())
        _LEGACY._register(db, event)
        det = self.detection.run(rc)
        if det.status != "COMPLETED":
            db.add(AuditLog(actor=self.name, action="detection_failed", detail=dict(event_id=event.id, error=det.error))); db.commit()
            return RunResult(run_id=rc.run_id, error=det.error, reason="detection failed")
        triage = d.reasoner.should_investigate(det.output)
        if not triage.investigate: db.commit(); return RunResult(run_id=rc.run_id, reason=triage.reason)

        sup_ex = None
        try:
            inc, new, created = self._open_incident(rc, det.output)
            if not new: self._restart(rc, inc)
            db.commit()
            sup_ex = self._begin(rc, sequence=0)
            d.publisher.publish("run_started", dict(incident_id=inc.id, run_id=rc.run_id, new_incident=new, agents=AGENT_ORDER))
            for n in AGENT_ORDER[2:]: d.publisher.publish("agent_update", dict(incident_id=inc.id, run_id=rc.run_id, agent=n, status="WAITING", timestamp=utcnow().isoformat()))
            return self._investigate(rc, det.output, created, sup_ex)
        except Exception as ex:
            return self._fail(rc, sup_ex, ex)

    # ------------------------------------------------------------ steps
    def _open_incident(self, rc, det):
        db, e = rc.db, rc.event; key = f"{e.host}|{e.user}"
        inc = db.query(Incident).filter(Incident.key == key, Incident.status == "open").first(); new = inc is None
        if new:
            inc = Incident(key=key, title=f"Suspicious activity on {e.host} ({e.user})", state=S.RECEIVED.value); db.add(inc); db.flush()
        an = det["anomaly"]; created = []
        for h in det["hits"]:
            a = Alert(rule=h["name"], rule_id=h["rule_id"], severity=h["severity"], confidence=h["confidence"], technique=h["technique"], uncertain=int(h["uncertain"]), points=h["points"],
                      anomaly_score=an["anomaly_score"] if an["is_anomaly"] else None, event_id=e.id, evidence=list(h["evidence"]), incident_id=inc.id)
            db.add(a); created.append(a)
        db.flush()
        for a in created: db.add(IncidentEvidence(incident_id=inc.id, event_id=e.id, alert_id=a.id, note=(a.evidence or [""])[0]))
        db.add(IncidentTimeline(incident_id=inc.id, kind="detection", message=f"{len(created)} detection(s) on {e.event_type}: " + ", ".join(a.rule_id for a in created), detail={"run_id": rc.run_id}))
        for M in (AgentExecution, ToolCall): db.query(M).filter(M.run_id == rc.run_id, M.incident_id.is_(None)).update({M.incident_id: inc.id}, synchronize_session=False)
        db.flush(); db.refresh(inc)
        rc.incident, rc.incident_id, rc.alerts = inc, inc.id, list(inc.alerts)
        return inc, new, created

    def _restart(self, rc, inc) -> None:
        cur = current_state(inc)
        if cur == S.RECEIVED: return
        if cur in ACTIVE_STATES: self.sm.transition(rc.db, inc, S.FAILED, "previous run was interrupted", run_id=rc.run_id)
        self.sm.transition(rc.db, inc, S.RECEIVED, "new evidence on an open incident", run_id=rc.run_id)

    def _after(self, rc, out: AgentOutcome) -> AgentOutcome:
        if out.status == "COMPLETED": return out
        if out.critical: raise AgentFailure(f"{out.agent} failed: {out.error}")
        rc.degraded.append(out.agent); return out

    def _go(self, rc, to, reason) -> None:
        self.sm.transition(rc.db, rc.incident, to, reason, run_id=rc.run_id); rc.db.commit()

    def _investigate(self, rc, det, created, sup_ex) -> RunResult:
        db, d, inc, s = rc.db, self.deps, rc.incident, rc.settings
        self._go(rc, S.DETECTED, f"{len(det['hits'])} detection(s): " + ", ".join(h["rule_id"] for h in det["hits"]))
        self._go(rc, S.TRIAGING, "investigation required; gathering log context"); self._after(rc, self.log_agent.run(rc))
        self._go(rc, S.THREAT_INTEL_LOOKUP, "checking indicators against threat intelligence"); self._after(rc, self.ti.run(rc))

        stop_reason = "max_iterations"
        for it in range(1, s.effective_max_iterations + 1):          # HARD bound, independent of what the reasoner says
            d.guard.check_iteration(it); rc.iteration = it
            self._go(rc, S.INVESTIGATING, f"iteration {it} of max {s.effective_max_iterations}")
            self._after(rc, self.investigation.run(rc, iteration=it)); rc.iterations_done = it
            self._go(rc, S.CORRELATING, "correlating findings and checking evidence sufficiency")
            rep = self.verifier.verify(rc.case_file())
            dec = d.reasoner.next_step(LoopState(it, s.effective_max_iterations, rep.needs_more_evidence, rc.new_event_count, rc.budget.can_continue_investigation()))
            db.add(IncidentTimeline(incident_id=inc.id, kind="note", message=f"iteration {it}: {dec.action} ({dec.reason}); failing checks: {', '.join(rep.failed()) or 'none'}", detail={"run_id": rc.run_id}))
            if dec.action == "stop": stop_reason = dec.reason; break
        else: stop_reason = "max_iterations"

        self._go(rc, S.ATTACK_RECONSTRUCTION, "reconstructing the attack chain and graph"); self._after(rc, self.graph.run(rc))
        inc.techniques = rc.techniques or techniques_from_alerts(inc.alerts)
        self._go(rc, S.RISK_ASSESSMENT, "scoring risk"); self._after(rc, self.risk.run(rc))
        k = rc.risk; inc.risk_score, inc.risk_level, inc.risk_factors = k["risk_score"], k["severity"], k["risk_factors"]
        inc.anomaly_score = max([a.anomaly_score for a in inc.alerts if a.anomaly_score is not None], default=0.0); inc.updated_at = utcnow()
        db.add(RiskAssessment(incident_id=inc.id, score=inc.risk_score, level=inc.risk_level, factors=inc.risk_factors))
        v1 = self.verifier.verify(rc.case_file(), risk=k, degraded=len(rc.degraded)); rc.verification = v1.to_dict(); db.commit()

        self._go(rc, S.RESPONSE_PLANNING, f"planning proportionate responses (verdict: {v1.verdict})"); self._after(rc, self.response.run(rc))
        actions, withheld = list(rc.plan["actions"]), list(rc.plan["withheld"])
        final = self.verifier.verify(rc.case_file(), risk=k, responses=actions, degraded=len(rc.degraded))
        if final.needs_review:        # defence in depth: a reasoner (e.g. a future LLM) must never smuggle destructive actions past a failed verification
            keep = [a for a in actions if not a["destructive"]]
            withheld += [dict(action=a["action"], target=a["target"], reason="withheld: verification failed") for a in actions if a["destructive"]]; actions = keep
        pending = self._persist_responses(rc, actions)
        inc.confidence = final.confidence; inc.needs_review = int(final.needs_review); inc.verdict = final.verdict; inc.iterations = rc.iterations_done
        inc.assessment = dict(verdict=final.verdict, summary=f"risk {k['risk_score']} ({k['severity']}), confidence {final.confidence}; {len(actions)} action(s) recommended",
                              risk=dict(score=k["risk_score"], severity=k["severity"], confidence=k["confidence"]), verification=final.to_dict(), iterations=rc.iterations_done,
                              stop_reason=stop_reason, findings=len(rc.findings), run_id=rc.run_id, degraded_agents=list(rc.degraded), withheld=withheld,
                              rejected_by_policy=rc.plan["rejected_by_policy"], generated_at=utcnow().isoformat())
        db.add(AuditLog(actor=self.name, action="incident_assessed", detail=dict(incident_id=inc.id, run_id=rc.run_id, risk=k["risk_score"], verdict=final.verdict, actions=[a["action"] for a in actions])))
        if pending or actions: self._go(rc, S.AWAITING_HUMAN_APPROVAL, "awaiting human approval of recommended responses" + (" (NEEDS_REVIEW)" if final.needs_review else ""))
        else: self._go(rc, S.RESOLVED, "no response required")
        out = AgentOutcome(agent=self.name, output=inc.assessment, confidence=final.confidence, input_summary=f"{rc.event.event_type} {rc.event.user}@{rc.event.host}",
                           output_summary=inc.assessment["summary"] + (" — NEEDS_REVIEW" if final.needs_review else ""), evidence=[f"{f['label']}: {f['points']:+d}" for f in k["risk_factors"]][:8],
                           evidence_ids=[f"alert:{a.id}" for a in rc.alerts])
        self._finish(rc, sup_ex, out, "COMPLETED", started_at=rc.started_at)
        d.publisher.publish("incident_assessed", dict(incident_id=inc.id, run_id=rc.run_id, state=inc.state, risk_score=inc.risk_score, risk_level=inc.risk_level, verdict=inc.verdict, needs_review=bool(inc.needs_review)))
        return RunResult(True, inc.id, rc.run_id, inc.state, inc.risk_score, inc.risk_level, inc.verdict, bool(inc.needs_review), rc.iterations_done, stop_reason,
                         [dict(id=a.id, rule=a.rule, rule_id=a.rule_id, severity=a.severity) for a in created], list(rc.degraded))

    def _persist_responses(self, rc, actions: list) -> int:
        """Stores recommendations as PENDING. Re-validates every action (guardrail) and supersedes stale pending ones from earlier runs."""
        db, inc = rc.db, rc.incident; keep: set = set(); n_new = 0
        existing = {(r.action, r.target): r for r in inc.recommendations if r.status in ("pending", "approved")}
        for a in actions:
            try: va = self.deps.guard.validate_action(a["action"], a["target"], a.get("params"))
            except PolicyViolation as pv:
                db.add(AuditLog(actor=self.name, action="policy_violation", detail=dict(incident_id=inc.id, action=a["action"], target=a["target"], code=pv.code, message=pv.message))); continue
            keep.add((a["action"], va.target))
            if (a["action"], va.target) in existing: continue
            db.add(ResponseRecommendation(incident_id=inc.id, action=a["action"], target=va.target, rationale=a["reason"], expected_impact=a["expected_impact"], confidence=a["confidence"],
                                          approval_level=a["approval_level"], destructive=int(va.policy.destructive), params=va.params, status="pending", created_at=utcnow(), run_id=rc.run_id)); n_new += 1
        for k, r in existing.items():
            if r.status == "pending" and r.approval_level is not None and k not in keep:
                r.status = "superseded"; r.decided_by = self.name; r.decided_at = utcnow()
                db.add(IncidentTimeline(incident_id=inc.id, kind="response", message=f"superseded by a newer assessment: {r.action} → {r.target}", detail={"response_id": r.id}))
        db.flush(); db.refresh(inc)
        return sum(1 for r in inc.recommendations if r.status == "pending")

    def _fail(self, rc, sup_ex, ex: Exception) -> RunResult:
        db = rc.db; log.exception("investigation run failed"); db.rollback(); inc = db.get(Incident, rc.incident_id) if rc.incident_id else None
        if inc is not None:
            try:
                if current_state(inc) not in (S.FAILED, S.RESOLVED): self.sm.transition(db, inc, S.FAILED, f"{type(ex).__name__}: {ex}", run_id=rc.run_id)
            except InvalidTransition: pass
            db.add(AuditLog(actor=self.name, action="investigation_failed", detail=dict(incident_id=inc.id, run_id=rc.run_id, error=str(ex))))
        if sup_ex:
            out = AgentOutcome(agent=self.name, error=f"{type(ex).__name__}: {ex}", output_summary="investigation failed")
            self._finish(rc, sup_ex, out, "FAILED", started_at=rc.started_at)
        db.commit()
        return RunResult(True, rc.incident_id, rc.run_id, S.FAILED.value, error=str(ex), degraded=list(rc.degraded), iterations=rc.iterations_done)
