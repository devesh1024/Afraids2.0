"""Phase 3 tests: orchestration, state machine, tools, loops, risk, approvals, guardrails, simulated executor, API.

UNVERIFIED: written without being executed. Tests that create incidents through the supervisor use UNIQUE hosts/users/IPs because the
test database is shared across the whole session (the rule engine de-duplicates on IPs/users already alerted).
"""
import ast, dataclasses, pathlib
from datetime import timedelta
from types import SimpleNamespace
import pytest
from sqlalchemy import inspect
from tests.conftest import ev, T0
from app.db import (AgentExecution, AuditLog, Base, Incident, IncidentStateTransition, IncidentTimeline, InvestigationFinding, ResponseRecommendation,
                    SecurityEvent, SessionLocal, SimulatedEffect, ToolCall, engine)
from app.agentic.agents import AGENT_ORDER
from app.agentic.approvals import Conflict, NotFound
from app.agentic.config import HARD_MAX_ITERATIONS, Settings
from app.agentic.events import EventPublisher
from app.agentic.executor import SimulationResponseExecutor
from app.agentic.guardrails import ACTION_POLICIES, TOOL_PERMISSIONS, Guardrails, PolicyViolation
from app.agentic.reasoning import DeterministicReasoner, LoopDecision, LoopState
from app.agentic.risk import RiskInputs, compute_risk
from app.agentic.runtime import build_runtime
from app.agentic.states import TRANSITIONS, IncidentState as S, InvalidTransition, StateMachine, can_transition
from app.agentic.tools import BoundTools, ToolBudget, ToolBudgetExceeded, ToolContext, ToolServices, build_default_registry
from app.agentic.verification import Verifier

FEED_IP = "45.155.205.233"      # in the synthetic threat-intel feed, reputation 95


# ---------------------------------------------------------------- helpers
def play(rt, db, specs):
    """specs: (event_type, minute, kwargs). Each event is created then handed to the SupervisorAgent, like the live pipeline."""
    out = []
    for t, m, kw in specs:
        out.append(rt.supervisor.handle_event(db, ev(db, t, m, **kw)))
    return out


def bf_specs(tag, ip=FEED_IP, base=0):
    k = dict(host=f"{tag}-host", user=f"{tag}-user", src=ip, dst="10.0.0.5")
    return [("login_failure", base + i, dict(k)) for i in range(6)] + [("login_success", base + 6, dict(k)), ("process_execution", base + 7, dict(k, process="whoami.exe"))]


def lone(tag, minute=0):
    return [("privilege_escalation", minute, dict(host=f"{tag}-host", user=f"{tag}-user", method="token_theft"))]


def incident_of(db, tag):
    db.expire_all()
    return db.query(Incident).filter(Incident.key == f"{tag}-host|{tag}-user").order_by(Incident.created_at.desc()).first()


def mk_incident(db, tag, risk="high", state="AWAITING_HUMAN_APPROVAL"):
    inc = Incident(key=f"{tag}-host|{tag}-user", title=f"inc {tag}", state=state, risk_level=risk, risk_score=70)
    db.add(inc); db.flush(); return inc


def mk_rec(db, inc, action, target, level=None, **kw):
    pol = ACTION_POLICIES[action]
    r = ResponseRecommendation(incident_id=inc.id, action=action, target=target, rationale="r", expected_impact="i", confidence=0.9, approval_level=level or pol.approval_level,
                               destructive=int(pol.destructive), status="pending", **kw)
    db.add(r); db.flush(); return r


@pytest.fixture
def rt(): return build_runtime(Settings(), EventPublisher())


# ---------------------------------------------------------------- state machine
def test_state_machine_is_complete_and_reachable():
    assert set(TRANSITIONS) == set(S) and len(S) == 13
    seen, todo = {S.RECEIVED}, [S.RECEIVED]
    while todo:
        for n in TRANSITIONS[todo.pop()]:
            if n not in seen: seen.add(n); todo.append(n)
    assert seen == set(S)                                   # every state reachable from RECEIVED
    assert TRANSITIONS[S.RESOLVED] == set()                 # terminal
    assert can_transition("RECEIVED", "DETECTED") and not can_transition("RECEIVED", "RESOLVED") and not can_transition("RESOLVED", "RECEIVED")


def test_state_machine_persists_and_rejects_illegal_transitions(db):
    inc = Incident(key="sm-host|sm-user", title="sm", state="RECEIVED"); db.add(inc); db.flush()
    pub = EventPublisher(); sm = StateMachine(pub)
    sm.transition(db, inc, S.DETECTED, "because", run_id="r1"); db.commit()
    assert inc.state == "DETECTED"
    with pytest.raises(InvalidTransition): sm.transition(db, inc, S.RESOLVED)
    assert inc.state == "DETECTED"
    rows = db.query(IncidentStateTransition).filter(IncidentStateTransition.incident_id == inc.id).all()
    assert [(r.from_state, r.to_state, r.reason) for r in rows] == [("RECEIVED", "DETECTED", "because")]
    assert any(m["type"] == "incident_state" and m["data"]["to"] == "DETECTED" for m in pub.history)
    assert db.query(IncidentTimeline).filter(IncidentTimeline.incident_id == inc.id, IncidentTimeline.kind == "state").count() == 1


# ---------------------------------------------------------------- settings
def test_settings_are_bounded(monkeypatch):
    assert Settings(max_iterations=999).effective_max_iterations == HARD_MAX_ITERATIONS and Settings(max_iterations=0).effective_max_iterations == 1
    assert Settings().window_for(1) == 30 and Settings().window_for(99) == 1440
    monkeypatch.setenv("AGENT_MAX_ITERATIONS", "999"); assert Settings.from_env().max_iterations == HARD_MAX_ITERATIONS
    monkeypatch.setenv("AGENT_MAX_ITERATIONS", "abc"); assert Settings.from_env().max_iterations == 3


# ---------------------------------------------------------------- tool registry
def _ctx(db, agent, budget=None):
    return ToolContext(db=db, guard=Guardrails(), budget=budget or ToolBudget(50, 5, 30), agent=agent, services=ToolServices(), incident_id=None, execution_id="ex-test", run_id="run-test")


def test_registry_has_all_eleven_tools():
    assert set(build_default_registry().names()) == {"search_security_events", "get_user_history", "get_host_history", "lookup_ip_reputation", "lookup_domain_reputation",
        "lookup_hash_reputation", "query_attack_technique", "build_attack_graph", "calculate_risk", "get_related_incidents", "get_security_baseline"}
    assert all(d["input_schema"] for d in build_default_registry().describe())
    used = set().union(*TOOL_PERMISSIONS.values()); assert used <= set(build_default_registry().names())


def test_tool_validation_structured_output_and_recording(db):
    reg = build_default_registry(); t = BoundTools(reg, _ctx(db, "InvestigationAgent"))
    ok = t.call("lookup_ip_reputation", ip=FEED_IP)
    assert ok.ok and ok.data["found"] and ok.data["reputation"] == 95 and ok.summary and ok.call_id
    bad = t.call("lookup_ip_reputation", ip="not-an-ip"); assert not bad.ok and bad.code == "invalid_input" and bad.data is None
    assert t.call("no_such_tool").code == "unknown_tool"
    assert t.call("search_security_events").code == "invalid_input"                       # needs at least one filter
    assert t.call("query_attack_technique", technique_id="T1110").data["found"] is True
    assert t.call("query_attack_technique", technique_id="bogus").code == "invalid_input"
    assert t.call("query_attack_technique", technique_id="T9999").data["found"] is False
    db.flush()
    rows = db.query(ToolCall).filter(ToolCall.execution_id == "ex-test").all()
    assert len(rows) == len(t.calls) and {r.status for r in rows} == {"ok", "error"}
    assert t.used()[0]["tool"] == "lookup_ip_reputation" and 0 <= t.success_ratio() < 1


def test_tool_search_events_and_histories(db):
    for i in range(3): ev(db, "login_failure", i, user="ts-user", host="ts-host", src="45.33.32.5")
    t = BoundTools(build_default_registry(), _ctx(db, "InvestigationAgent"))
    r = t.call("search_security_events", user="ts-user", end=T0 + timedelta(minutes=5), window_minutes=60)
    assert r.ok and r.data["count"] == 3 and r.data["events"][0]["event_type"] == "login_failure" and not r.data["truncated"]
    h = t.call("get_user_history", user="ts-user", end=T0 + timedelta(minutes=5), window_minutes=60)
    assert h.data["failed_logins"] == 3 and h.data["external_ips"] == ["45.33.32.5"]
    assert t.call("get_host_history", host="ts-host", end=T0 + timedelta(minutes=5), window_minutes=60).data["total_events"] == 3
    assert t.call("get_security_baseline", kind="user", value="ts-user").data["model_baseline"]
    assert t.call("get_security_baseline", kind="nope", value="x").code == "invalid_input"


def test_tool_permissions_are_enforced_per_agent(db):
    t = BoundTools(build_default_registry(), _ctx(db, "DetectionAgent"))
    assert t.call("build_attack_graph", incident_id="x").code == "tool_not_permitted"
    assert BoundTools(build_default_registry(), _ctx(db, "SupervisorAgent")).call("lookup_ip_reputation", ip=FEED_IP).code == "tool_not_permitted"
    assert BoundTools(build_default_registry(), _ctx(db, "LogAnalysisAgent")).call("calculate_risk", incident_id="x").code == "tool_not_permitted"


def test_tool_budget_total_reserve_and_per_agent(db):
    b = ToolBudget(total=5, reserved=2, per_agent=10)
    for _ in range(3): b.consume("InvestigationAgent")
    with pytest.raises(ToolBudgetExceeded): b.consume("InvestigationAgent")           # reserve is off-limits to greedy agents
    b.consume("RiskAssessmentAgent"); b.consume("ResponseAgent")                      # but reserved agents can still run
    with pytest.raises(ToolBudgetExceeded): b.consume("ResponseAgent")
    p = ToolBudget(total=50, reserved=0, per_agent=2); p.consume("LogAnalysisAgent", "e1"); p.consume("LogAnalysisAgent", "e1")
    with pytest.raises(ToolBudgetExceeded): p.consume("LogAnalysisAgent", "e1")
    t = BoundTools(build_default_registry(), _ctx(db, "InvestigationAgent", ToolBudget(1, 0, 10)))
    assert t.call("lookup_ip_reputation", ip=FEED_IP).ok and t.call("lookup_ip_reputation", ip=FEED_IP).code == "budget_exceeded"


# ---------------------------------------------------------------- risk engine
def _alert(rule="R004", sev="critical", conf=0.9, anomaly=None): return dict(rule_id=rule, name=f"rule {rule}", severity=sev, confidence=conf, anomaly_score=anomaly)


def test_risk_hand_computed_example_is_explainable():
    inp = RiskInputs(alerts=[_alert()], correlated_event_count=2, techniques=[dict(id="T1134", name="x", tactic="Defense Evasion, Privilege Escalation", uncertain=False)], privilege_escalation=True)
    r = compute_risk(inp)
    pts = {f["kind"]: f["points"] for f in r.risk_factors}
    assert pts == {"severity": 25, "correlated_events": 1, "attack_technique": 13, "privilege_escalation": 10, "confidence_adjustment": -1}
    assert (r.risk_score, r.severity, r.confidence) == (48, "medium", 0.9) and sum(pts.values()) == r.risk_score


def test_risk_caps_and_invariant():
    alerts = [_alert(f"R00{i}", "critical", 0.95, 0.9) for i in range(1, 9)]
    big = RiskInputs(alerts=alerts, correlated_event_count=30, ti_hits=[dict(indicator=x, reputation=100, category="c") for x in "abc"],
                     techniques=[dict(id="T1041", name="x", tactic="Exfiltration, Collection", uncertain=False)], assets=[dict(name="fileserver-01", weight=10, label="x")],
                     sensitive_data=True, privilege_escalation=True)
    r = compute_risk(big)
    assert r.risk_score == 100 and sum(f["points"] for f in r.risk_factors) == 100 and any(f["kind"] == "cap" for f in r.risk_factors) and r.severity == "critical"
    ml = compute_risk(RiskInputs(alerts=[_alert("ML001", "medium", 0.5, 0.9)], correlated_event_count=30, assets=[dict(name="fileserver-01", weight=10, label="x")]))
    assert ml.risk_score <= 35 and sum(f["points"] for f in ml.risk_factors) == ml.risk_score and any(f["kind"] == "cap" for f in ml.risk_factors)
    empty = compute_risk(RiskInputs()); assert (empty.risk_score, empty.severity, empty.risk_factors) == (0, "low", [])


def test_risk_is_monotonic_in_evidence():
    base = RiskInputs(alerts=[_alert("R002", "critical", 0.9)], correlated_event_count=3)
    more = dataclasses.replace(base, ti_hits=[dict(indicator=FEED_IP, reputation=95, category="Botnet C2")], privilege_escalation=True)
    assert compute_risk(more).risk_score >= compute_risk(base).risk_score
    contradicted = dataclasses.replace(base, findings=[dict(source="baseline", confidence=0.7, contradicts=True)])
    assert compute_risk(contradicted).confidence < compute_risk(base).confidence


# ---------------------------------------------------------------- verification (self-reflection)
GOOD = dict(alerts=[dict(rule_id="R002", severity="critical", confidence=0.95)], event_count=5,
            findings=[dict(source="threat_intel", confidence=0.88, contradicts=False, description="ti"), dict(source="sequence", confidence=0.8, contradicts=False, description="seq")])


def test_verifier_flags_thin_single_signal_evidence():
    r = Verifier(Settings()).verify(dict(alerts=[dict(rule_id="R004", severity="critical", confidence=0.75)], event_count=1, findings=[]))
    assert r.needs_review and r.needs_more_evidence and {"sufficient_evidence", "independent_signals"} <= set(r.failed())


def test_verifier_accepts_corroborated_evidence_and_checks_proportionality():
    v = Verifier(Settings()); assert v.verify(GOOD).verdict == "confirmed"
    risk = dict(severity="medium", confidence=0.9)
    assert v.verify(GOOD, risk, [dict(action="revoke_session")]).verdict == "confirmed"
    over = v.verify(GOOD, risk, [dict(action="isolate_endpoint")]); assert over.needs_review and "response_proportional" in over.failed()
    cov = v.verify(GOOD, dict(severity="high", confidence=0.9), [dict(action="increase_monitoring")])
    assert not cov.needs_review and "response_coverage" in cov.failed()                    # warning only


def test_verifier_contradiction_and_low_confidence():
    v = Verifier(Settings()); c = dict(GOOD, findings=GOOD["findings"] + [dict(source="baseline", confidence=0.7, contradicts=True, description="established IP")])
    r = v.verify(c); assert r.needs_review and r.contradictions == ["established IP"]
    low = v.verify(GOOD, dict(severity="high", confidence=0.4)); assert "confidence_threshold" in low.failed() and low.needs_review and low.needs_more_evidence
    assert Verifier(Settings()).verify(GOOD, dict(severity="high", confidence=0.62), degraded=1).confidence == 0.57


# ---------------------------------------------------------------- guardrails
def test_action_policy_rejects_unsafe_actions():
    g = Guardrails(Settings())
    for bad, code in [(("format_disk", "x"), "action_not_allowed"), (("block_ip", "10.0.0.5"), "protected_target"), (("block_ip", "999.1.1.1"), "invalid_target"),
                      (("block_ip", "127.0.0.1"), "protected_target"), (("disable_account", "root"), "protected_target"), (("disable_account", "n/a"), "invalid_target"),
                      (("isolate_endpoint", "dc-01"), "protected_target"), (("revoke_session", "bad name!"), "invalid_target"), (("close_incident", None), "invalid_target")]:
        with pytest.raises(PolicyViolation) as e: g.validate_action(*bad)
        assert e.value.code == code, bad
    assert g.validate_action("block_ip", FEED_IP).target == FEED_IP and g.validate_action("isolate_endpoint", "ws-1").target == "ws-1"
    with pytest.raises(PolicyViolation): g.validate_action("block_ip", FEED_IP, {"x": "y" * 3000})


def test_authorization_and_event_and_iteration_guardrails():
    g = Guardrails(Settings(max_iterations=2))
    assert g.authorize("senior_analyst", "block_ip") == "senior_analyst" and g.authorize("admin", "isolate_endpoint") == "admin"
    for role, action, risk in [("analyst", "block_ip", None), ("analyst", "isolate_endpoint", None), ("viewer", "increase_monitoring", None), ("analyst", "close_incident", "high")]:
        with pytest.raises(PolicyViolation) as e: g.authorize(role, action, risk)
        assert e.value.code == "insufficient_role"
    assert g.authorize("analyst", "close_incident", "low") == "analyst" and g.authorize("admin", "close_incident", "critical") == "admin"
    with pytest.raises(PolicyViolation) as e: g.authorize("god", "block_ip")
    assert e.value.code == "unknown_role"
    g.check_iteration(2)
    with pytest.raises(PolicyViolation): g.check_iteration(3)
    good = SimpleNamespace(event_type="login_failure", user="u", host="h", src_ip=FEED_IP, dst_ip="n/a", meta={})
    g.validate_event(good)
    for bad in [dict(event_type="bogus"), dict(src_ip="300.1.1.1"), dict(host=""), dict(user=None), dict(meta={"x": "y" * 20000})]:
        with pytest.raises(PolicyViolation): g.validate_event(SimpleNamespace(**{**good.__dict__, **bad}))
    snap = g.policy_snapshot(); assert {a["name"] for a in snap["actions"]} == set(ACTION_POLICIES) and snap["limits"]["max_iterations"] == 2


# ---------------------------------------------------------------- reasoner (deterministic judgment)
def test_loop_decisions_table():
    r = DeterministicReasoner(Settings())
    st = lambda **k: LoopState(**{**dict(iteration=1, max_iterations=3, needs_more_evidence=True, new_event_count=5, budget_ok=True), **k})
    assert r.next_step(st(needs_more_evidence=False)).reason == "sufficient_evidence"
    assert r.next_step(st()).action == "continue"
    assert r.next_step(st(iteration=3)).reason == "max_iterations"
    assert r.next_step(st(iteration=2, new_event_count=0)).reason == "no_new_evidence"
    assert r.next_step(st(budget_ok=False)).reason == "tool_budget"


def _e(i, t, minute, **k):
    return dict(id=f"e{i}", timestamp=f"2026-01-01T12:{minute:02d}:00", event_type=t, user="bob", host="h", src_ip="45.33.32.60", dst_ip="10.0.0.5", severity="low", meta=k)


def _bundle(prior):
    events = [_e(i, "login_failure", i) for i in range(5)] + [_e(5, "login_success", 5), _e(6, "process_execution", 6, process="whoami.exe")]
    alerts = [dict(id="a1", rule_id="R002", name="Successful login after brute force", severity="critical", confidence=0.95, technique="T1078", uncertain=False, anomaly_score=None, event_id="e5", evidence=["x"])]
    return dict(alerts=alerts, events=events, user="bob", host="h", prior_logins_by_ip=prior, ti={}, techniques=[], related=[])


def test_investigation_findings_sequence_baseline_and_contradiction():
    r = DeterministicReasoner(Settings()); f = r.analyze(_bundle({}))
    assert {x.source for x in f} >= {"rule", "sequence", "baseline"} and not any(x.contradicts for x in f)
    assert all(x.description and x.severity and 0 < x.confidence <= 1 and x.source for x in f)
    c = r.analyze(_bundle({"45.33.32.60": 4}))
    assert any(x.contradicts for x in c) and not any(x.source == "baseline" and not x.contradicts for x in c)


def _case(level="critical", needs_review=False, user="bob", host="ws-1", src="45.33.32.50", rules=("R002", "R004"), contradictions=()):
    events = [dict(id="e1", user=user, host=host, src_ip=src, dst_ip="10.0.0.5", event_type="login_success", timestamp="2026-01-01T12:00:00", meta={})]
    return dict(incident_id="inc-1", risk=dict(severity=level, risk_score=90, confidence=0.9), needs_review=needs_review, events=events, ti={src: dict(category="Botnet C2")},
                alerts=[dict(id=f"a{i}", rule_id=x, event_id="e1") for i, x in enumerate(rules)], contradictions=list(contradictions), primary_user=user, primary_host=host)


def test_response_plan_is_complete_proportionate_and_requires_approval_levels():
    p = DeterministicReasoner(Settings()).plan_responses(_case())
    acts = {a.action: a for a in p.actions}
    assert set(acts) == {"preserve_evidence", "increase_monitoring", "revoke_session", "block_ip", "disable_account", "isolate_endpoint"}
    assert acts["block_ip"].target == "45.33.32.50" and acts["isolate_endpoint"].approval_level == "admin" and acts["block_ip"].approval_level == "senior_analyst"
    assert all(a.reason and a.expected_impact and 0 < a.confidence <= 0.98 and a.approval_level for a in p.actions)
    med = {a.action for a in DeterministicReasoner(Settings()).plan_responses(_case("medium")).actions}
    assert med == {"preserve_evidence", "increase_monitoring", "revoke_session"}          # no block/disable/isolate at medium
    assert {a.action for a in DeterministicReasoner(Settings()).plan_responses(_case("low")).actions} == {"increase_monitoring"}


def test_response_plan_withholds_destructive_when_review_needed_and_respects_policy():
    r = DeterministicReasoner(Settings()); p = r.plan_responses(_case(needs_review=True))
    assert {a.action for a in p.actions} == {"preserve_evidence", "increase_monitoring"} and {w["action"] for w in p.withheld} >= {"block_ip", "disable_account", "isolate_endpoint"}
    q = r.plan_responses(_case(user="root", host="dc-01", src="10.0.0.9"))
    assert not any(a.action in ("disable_account", "revoke_session", "isolate_endpoint", "block_ip") for a in q.actions)
    assert {x["action"] for x in q.rejected_by_policy} >= {"disable_account", "revoke_session", "isolate_endpoint"}
    c = r.plan_responses(_case("low", rules=("ML001",), contradictions=["x"])); assert "close_incident" in {a.action for a in c.actions}


# ---------------------------------------------------------------- end-to-end orchestration
def test_full_workflow_bruteforce_to_human_approval(db):
    pub = EventPublisher(); rt = build_runtime(Settings(), pub); res = play(rt, db, bf_specs("e2e")); last = res[-1]
    assert last.investigated and last.state == "AWAITING_HUMAN_APPROVAL" and last.risk_level in ("high", "critical") and last.verdict == "confirmed" and not last.needs_review
    inc = incident_of(db, "e2e"); assert inc.state == "AWAITING_HUMAN_APPROVAL" and inc.confidence >= 0.6 and inc.assessment["stop_reason"] and inc.risk_factors
    assert sum(f["points"] for f in inc.risk_factors) == round(inc.risk_score)                               # explainable
    # every agent ran and left a complete execution record
    ex = db.query(AgentExecution).filter(AgentExecution.run_id == last.run_id).all(); by = {e.agent for e in ex}
    assert by == set(AGENT_ORDER)
    for e in ex:
        assert e.incident_id == inc.id and e.status == "COMPLETED" and e.started_at and e.finished_at and e.input_summary and e.output_summary is not None and e.tools_used is not None and e.evidence_ids is not None
    assert next(e for e in ex if e.agent == "LogAnalysisAgent").tools_used and next(e for e in ex if e.agent == "InvestigationAgent").evidence_ids
    assert db.query(InvestigationFinding).filter(InvestigationFinding.run_id == last.run_id).count() >= 3
    assert db.query(ToolCall).filter(ToolCall.run_id == last.run_id, ToolCall.incident_id == inc.id).count() >= 8
    # state progression of the final run (a subsequence in order)
    to = [t.to_state for t in db.query(IncidentStateTransition).filter(IncidentStateTransition.run_id == last.run_id).order_by(IncidentStateTransition.timestamp)]
    want = ["DETECTED", "TRIAGING", "THREAT_INTEL_LOOKUP", "INVESTIGATING", "CORRELATING", "ATTACK_RECONSTRUCTION", "RISK_ASSESSMENT", "RESPONSE_PLANNING", "AWAITING_HUMAN_APPROVAL"]
    it = iter(to); assert all(w in it for w in want), to
    # responses are PENDING (supervisor stops before destructive response) and complete
    recs = db.query(ResponseRecommendation).filter(ResponseRecommendation.incident_id == inc.id, ResponseRecommendation.status == "pending").all()
    acts = {r.action: r for r in recs}; assert {"block_ip", "disable_account"} <= set(acts) and acts["block_ip"].target == FEED_IP and acts["disable_account"].target == "e2e-user"
    assert all(r.rationale and r.expected_impact and r.confidence and r.approval_level for r in recs)
    assert db.query(SimulatedEffect).filter(SimulatedEffect.incident_id == inc.id).count() == 0           # nothing executed
    # streaming: ordered updates for the final run
    msgs = [(m["data"]["agent"], m["data"]["status"]) for m in pub.history if m["type"] == "agent_update" and m["data"].get("run_id") == last.run_id]
    pos = lambda x: msgs.index(x)
    assert pos(("DetectionAgent", "COMPLETED")) < pos(("LogAnalysisAgent", "RUNNING")) < pos(("LogAnalysisAgent", "COMPLETED")) < pos(("ThreatIntelligenceAgent", "RUNNING"))
    assert pos(("ThreatIntelligenceAgent", "WAITING")) < pos(("ThreatIntelligenceAgent", "RUNNING")) and ("ResponseAgent", "COMPLETED") in msgs


def test_new_evidence_reopens_pipeline_on_same_incident(db, rt):
    play(rt, db, bf_specs("reopen")); inc = incident_of(db, "reopen"); first_runs = {e.run_id for e in db.query(AgentExecution).filter(AgentExecution.incident_id == inc.id)}
    r = play(rt, db, [("privilege_escalation", 30, dict(host="reopen-host", user="reopen-user", method="token_theft"))])[0]
    assert r.investigated and r.incident_id == inc.id and r.run_id not in first_runs
    t = [(x.from_state, x.to_state) for x in db.query(IncidentStateTransition).filter(IncidentStateTransition.run_id == r.run_id).order_by(IncidentStateTransition.timestamp)]
    assert t[0] == ("AWAITING_HUMAN_APPROVAL", "RECEIVED")
    from app.agentic.queries import build_investigation_view, build_replay
    v = build_investigation_view(db, inc.id); assert len(v["runs"]) >= 2 and v["incident"]["state"] == "AWAITING_HUMAN_APPROVAL"
    rp = build_replay(db, inc.id); assert rp["count"] > 20 and [s["index"] for s in rp["steps"]] == list(range(rp["count"])) and {"state", "agent"} <= {s["kind"] for s in rp["steps"]}


def test_thin_evidence_is_marked_needs_review_not_certain(db, rt):
    r = play(rt, db, lone("thin"))[0]; inc = incident_of(db, "thin")
    assert r.investigated and r.needs_review and r.verdict == "needs_review" and inc.needs_review == 1 and r.state == "AWAITING_HUMAN_APPROVAL"
    assert r.stop_reason == "no_new_evidence" and r.iterations == 2
    recs = db.query(ResponseRecommendation).filter(ResponseRecommendation.incident_id == inc.id).all()
    assert recs and not any(x.destructive for x in recs)
    failed = [c["name"] for c in inc.assessment["verification"]["checks"] if not c["passed"]]; assert "independent_signals" in failed and "sufficient_evidence" in failed


def test_contradicting_baseline_forces_review_and_withholds_containment(db, rt):
    tag, ip = "contra", "45.33.32.71"; k = dict(host=f"{tag}-host", user=f"{tag}-user", src=ip, dst="10.0.0.5")
    for m in (-3000, -2000, -1000, -500): ev(db, "login_success", m, **k)                       # established, legitimate history from this IP
    specs = [("login_failure", i, dict(k)) for i in range(5)] + [("login_success", 5, dict(k))]
    last = play(rt, db, specs)[-1]; inc = incident_of(db, tag)
    assert last.needs_review and inc.assessment["verification"]["contradictions"]
    assert not any(r.destructive for r in db.query(ResponseRecommendation).filter(ResponseRecommendation.incident_id == inc.id))
    assert any(w["action"] in ("revoke_session", "block_ip", "disable_account") for w in inc.assessment["withheld"]) or inc.risk_level == "low"


# ---------------------------------------------------------------- bounded loops / budgets / failures
class Greedy(DeterministicReasoner):
    def next_step(self, st): return LoopDecision("continue", "always")


@pytest.mark.parametrize("limit", [1, 2])
def test_investigation_loop_is_bounded_even_if_reasoner_never_stops(db, limit):
    s = Settings(max_iterations=limit); rt = build_runtime(s, EventPublisher(), reasoner=Greedy(s, Guardrails(s)))
    r = play(rt, db, lone(f"bound{limit}"))[0]
    assert r.iterations == limit and r.stop_reason == "max_iterations"
    assert db.query(AgentExecution).filter(AgentExecution.run_id == r.run_id, AgentExecution.agent == "InvestigationAgent").count() == limit


def test_tiny_tool_budget_degrades_gracefully(db):
    rt = build_runtime(Settings(max_tool_calls=12, reserved_tool_calls=6), EventPublisher())
    r = play(rt, db, lone("tiny"))[0]
    assert r.investigated and r.state in ("AWAITING_HUMAN_APPROVAL", "FAILED", "RESOLVED")
    assert db.query(ToolCall).filter(ToolCall.run_id == r.run_id, ToolCall.status == "ok").count() <= 12


def _boom_registry(tool):
    reg = build_default_registry(); spec = reg.get(tool)
    def boom(ctx, a): raise RuntimeError("kaboom")
    reg.register(dataclasses.replace(spec, handler=boom), replace=True); return reg


def test_critical_agent_failure_fails_the_run(db):
    rt = build_runtime(Settings(), EventPublisher(), registry=_boom_registry("calculate_risk"))
    r = play(rt, db, lone("critfail"))[0]; inc = incident_of(db, "critfail")
    assert r.state == "FAILED" and "RiskAssessmentAgent" in r.error and inc.state == "FAILED"
    ex = {e.agent: e for e in db.query(AgentExecution).filter(AgentExecution.run_id == r.run_id)}
    assert ex["RiskAssessmentAgent"].status == "FAILED" and "kaboom" in ex["RiskAssessmentAgent"].error and ex["SupervisorAgent"].status == "FAILED" and "ResponseAgent" not in ex
    assert db.query(AuditLog).filter(AuditLog.action == "investigation_failed").count() >= 1
    again = play(rt, db, lone("critfail", 5))[0]; assert again.investigated      # FAILED -> RECEIVED recovery path works


def test_noncritical_agent_failure_degrades_but_completes(db):
    rt = build_runtime(Settings(), EventPublisher(), registry=_boom_registry("build_attack_graph"))
    r = play(rt, db, lone("degrade"))[0]; inc = incident_of(db, "degrade")
    assert r.state == "AWAITING_HUMAN_APPROVAL" and r.degraded == ["AttackGraphAgent"] and inc.assessment["degraded_agents"] == ["AttackGraphAgent"] and inc.techniques
    assert db.query(AgentExecution).filter(AgentExecution.run_id == r.run_id, AgentExecution.agent == "AttackGraphAgent").one().status == "FAILED"


def test_invalid_event_is_rejected_by_guardrails_and_benign_event_is_ignored(db, rt):
    bad = rt.supervisor.handle_event(db, ev(db, "bogus_event", 0, host="rej-host", user="rej-user"))
    assert bad.rejected and incident_of(db, "rej") is None and db.query(AuditLog).filter(AuditLog.action == "event_rejected").count() >= 1
    ok = rt.supervisor.handle_event(db, ev(db, "login_success", 0, host="calm-host", user="calm-user"))
    assert not ok.investigated and not ok.rejected and incident_of(db, "calm") is None


# ---------------------------------------------------------------- approvals + simulated executor
def test_approve_executes_only_in_simulation_and_audits(rt, db):
    inc = mk_incident(db, "ap1"); rec = mk_rec(db, inc, "block_ip", "45.33.32.101")
    out = rt.decisions.approve(db, inc.id, rec.id, "alice", "senior_analyst", "looks malicious"); db.expire_all()
    assert out["status"] == "approved" and out["execution_result"]["simulated"] is True and "no real" in out["execution_result"]["message"]
    assert db.get(ResponseRecommendation, rec.id).decided_by == "alice" and db.get(Incident, inc.id).state == "CONTAINED"
    assert db.query(SimulatedEffect).filter(SimulatedEffect.kind == "blocklist", SimulatedEffect.target == "45.33.32.101", SimulatedEffect.incident_id == inc.id).count() == 1
    assert db.query(IncidentTimeline).filter(IncidentTimeline.incident_id == inc.id, IncidentTimeline.kind == "execution").count() == 1
    acts = {a.action for a in db.query(AuditLog) if (a.detail or {}).get("incident_id") == inc.id}; assert {"response_approved", "response_executed_simulated"} <= acts
    with pytest.raises(Conflict): rt.decisions.approve(db, inc.id, rec.id, "alice", "senior_analyst")


def test_insufficient_role_is_denied_and_logged(rt, db):
    inc = mk_incident(db, "ap2"); rec = mk_rec(db, inc, "block_ip", "45.33.32.102")
    with pytest.raises(PolicyViolation) as e: rt.decisions.approve(db, inc.id, rec.id, "bob", "analyst")
    assert e.value.code == "insufficient_role"; db.expire_all()
    assert db.get(ResponseRecommendation, rec.id).status == "pending" and db.query(SimulatedEffect).filter(SimulatedEffect.target == "45.33.32.102").count() == 0
    assert any(a.action == "response_denied" and a.detail["incident_id"] == inc.id for a in db.query(AuditLog).filter(AuditLog.action == "response_denied"))
    with pytest.raises(PolicyViolation): rt.decisions.reject(db, inc.id, rec.id, "eve", "viewer")


def test_reject_and_not_found_and_active_investigation_conflict(rt, db):
    inc = mk_incident(db, "ap3"); rec = mk_rec(db, inc, "revoke_session", "ap3-user")
    assert rt.decisions.reject(db, inc.id, rec.id, "carol", "analyst", "false positive")["status"] == "rejected"
    assert db.query(SimulatedEffect).filter(SimulatedEffect.target == "ap3-user").count() == 0
    with pytest.raises(NotFound): rt.decisions.approve(db, inc.id, "nope", "a", "admin")
    with pytest.raises(NotFound): rt.decisions.approve(db, "nope", rec.id, "a", "admin")
    busy = mk_incident(db, "ap3b", state="INVESTIGATING"); r2 = mk_rec(db, busy, "increase_monitoring", "ap3b-user")
    with pytest.raises(Conflict): rt.decisions.approve(db, busy.id, r2.id, "a", "admin")


def test_modify_revalidates_policy_and_keeps_pending(rt, db):
    inc = mk_incident(db, "ap4"); rec = mk_rec(db, inc, "block_ip", "45.33.32.104")
    for kw, code in [(dict(action="format_disk"), "action_not_allowed"), (dict(target="10.0.0.9"), "protected_target"), (dict(), "no_change")]:
        with pytest.raises(PolicyViolation) as e: rt.decisions.modify(db, inc.id, rec.id, "dave", "senior_analyst", **kw)
        assert e.value.code == code
    with pytest.raises(PolicyViolation) as e: rt.decisions.modify(db, inc.id, rec.id, "dave", "analyst", action="isolate_endpoint", target="ws-9")
    assert e.value.code == "insufficient_role"
    out = rt.decisions.modify(db, inc.id, rec.id, "dave", "analyst", action="increase_monitoring", target="ap4-user"); db.expire_all(); r = db.get(ResponseRecommendation, rec.id)
    assert out["status"] == "pending" and (r.action, r.target, r.modified, r.original_action, r.approval_level, r.destructive) == ("increase_monitoring", "ap4-user", 1, "block_ip", "analyst", 0)
    assert rt.decisions.approve(db, inc.id, rec.id, "dave", "analyst")["status"] == "approved"


def test_protected_target_is_blocked_at_approval_time(rt, db):
    inc = mk_incident(db, "ap5"); rec = mk_rec(db, inc, "disable_account", "root")
    with pytest.raises(PolicyViolation) as e: rt.decisions.approve(db, inc.id, rec.id, "x", "admin")
    assert e.value.code == "protected_target" and db.query(SimulatedEffect).filter(SimulatedEffect.target == "root", SimulatedEffect.incident_id == inc.id).count() == 0


def test_close_incident_resolves_and_needs_admin_for_high_risk(rt, db):
    inc = mk_incident(db, "ap6", risk="high"); rec = mk_rec(db, inc, "close_incident", inc.id, level="analyst")
    with pytest.raises(PolicyViolation): rt.decisions.approve(db, inc.id, rec.id, "a", "analyst")
    rt.decisions.approve(db, inc.id, rec.id, "root-admin", "admin"); db.expire_all(); i = db.get(Incident, inc.id)
    assert i.state == "RESOLVED" and i.status == "closed"


def test_legacy_recommendations_still_work(rt, db):
    inc = mk_incident(db, "ap7", state="RECEIVED"); r = ResponseRecommendation(incident_id=inc.id, action="Lock account & reset credentials", rationale="legacy", status="pending"); db.add(r); db.flush()
    assert rt.decisions.approve(db, inc.id, r.id, "a", "analyst")["status"] == "approved" and db.get(Incident, inc.id).state == "RECEIVED"


def test_executor_simulates_every_action_idempotently(db):
    g, ex = Guardrails(Settings()), SimulationResponseExecutor(); inc = mk_incident(db, "ex1")
    ev(db, "login_failure", 0, host="ex1-host", user="ex1-user", src="45.33.32.111")
    cases = [("block_ip", "45.33.32.112", "blocklist"), ("disable_account", "ex1-user", "disabled_account"), ("revoke_session", "ex1-user", "revoked_session"), ("isolate_endpoint", "ex1-host", "isolated_host"),
             ("increase_monitoring", "ex1-user", "monitoring"), ("preserve_evidence", inc.id, "evidence_snapshot"), ("close_incident", inc.id, "incident_closed")]
    for action, target, kind in cases:
        rec = mk_rec(db, inc, action, target); res = ex.execute(db, inc, rec, g.validate_action(action, target), "tester")
        assert res["simulated"] and res["effect"] == kind and res["status"] == "applied"
        assert db.query(SimulatedEffect).filter(SimulatedEffect.kind == kind, SimulatedEffect.target == target).count() == 1
    snap = db.query(SimulatedEffect).filter(SimulatedEffect.kind == "evidence_snapshot", SimulatedEffect.incident_id == inc.id).one(); assert len(snap.detail["manifest_sha256"]) == 64
    again = ex.execute(db, inc, mk_rec(db, inc, "block_ip", "45.33.32.112"), g.validate_action("block_ip", "45.33.32.112"), "tester"); assert again["status"] == "already_active"
    assert inc.status == "closed"


def test_executor_has_no_real_side_effect_imports():
    src = (pathlib.Path(__file__).resolve().parents[1] / "app" / "agentic" / "executor.py").read_text(); mods = set()
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, ast.Import): mods |= {a.name.split(".")[0] for a in n.names}
        if isinstance(n, ast.ImportFrom) and n.level == 0: mods.add((n.module or "").split(".")[0])
    assert not mods & {"subprocess", "os", "socket", "shutil", "requests", "httpx", "urllib", "http", "asyncio", "ctypes", "paramiko", "pty"}, mods


# ---------------------------------------------------------------- schema / API / websocket
def test_migration_matches_models():
    insp = inspect(engine); tables = set(insp.get_table_names())
    for t in Base.metadata.sorted_tables:
        assert t.name in tables, t.name
        assert {c.name for c in t.columns} == {c["name"] for c in insp.get_columns(t.name)}, t.name


def test_rest_api_investigation_replay_and_approval_flow(db):
    from fastapi.testclient import TestClient
    from app.main import app
    from app.agentic import runtime as default_rt
    c = TestClient(app); r = play(default_rt.default, db, lone("api")); iid = r[0].incident_id
    v = c.get(f"/api/incidents/{iid}/investigation"); assert v.status_code == 200
    body = v.json(); assert {e["agent"] for e in body["runs"][-1]["executions"]} == set(AGENT_ORDER) and body["incident"]["state"] == "AWAITING_HUMAN_APPROVAL"
    assert all("tool_calls" in e and "findings" in e for e in body["runs"][-1]["executions"])
    rp = c.get(f"/api/incidents/{iid}/replay").json(); assert rp["count"] > 15
    assert c.get(f"/api/incidents/{iid}/timeline").status_code == 200 and c.get(f"/api/incidents/{iid}/findings").json()
    assert c.get("/api/incidents/missing/investigation").status_code == 404 and c.get("/api/agents/pipeline").json()["agents"] == AGENT_ORDER
    assert len(c.get("/api/tools").json()) == 11 and "actions" in c.get("/api/policy").json()
    inc = mk_incident(db, "api2"); rec = mk_rec(db, inc, "block_ip", "45.33.32.121"); rec2 = mk_rec(db, inc, "increase_monitoring", "api2-user"); db.commit()
    url = lambda v: f"/api/incidents/{inc.id}/{v}-response"
    d = c.post(url("approve"), json={"response_id": rec.id}, headers={"x-role": "analyst", "x-actor": "ann"}); assert d.status_code == 403 and d.json()["detail"]["code"] == "insufficient_role"
    assert c.post(url("approve"), json={}).status_code == 422
    assert c.post(f"/api/incidents/nope/approve-response", json={"response_id": rec.id}).status_code == 404
    ok = c.post(url("approve"), json={"response_id": rec.id, "comment": "ok"}, headers={"x-role": "senior_analyst", "x-actor": "sam"}); assert ok.status_code == 200 and ok.json()["status"] == "approved"
    assert c.post(url("approve"), json={"response_id": rec.id}, headers={"x-role": "admin"}).status_code == 409
    assert c.post(url("modify"), json={"response_id": rec2.id, "action": "format_disk"}, headers={"x-role": "admin"}).status_code == 403
    assert c.post(url("reject"), json={"response_id": rec2.id}, headers={"x-role": "analyst"}).json()["status"] == "rejected"
    assert "45.33.32.121" in [x["target"] for x in c.get("/api/simulation/state").json()["blocklist"]]
    legacy = mk_rec(db, mk_incident(db, "api3"), "increase_monitoring", "api3-user"); db.commit()
    assert c.post(f"/api/responses/{legacy.id}/approve", headers={"x-role": "analyst"}).json()["status"] == "approved"


def test_websocket_streams_agent_activity_during_a_simulation():
    """Most environment-sensitive test (threads + event loop). Reads until the simulation-complete message, so it cannot hang."""
    from fastapi.testclient import TestClient
    from app.main import app
    seen = []
    with TestClient(app) as c:
        with c.websocket_connect("/ws") as ws:
            assert c.post("/api/simulations/start", json={"scenario": "privilege_escalation"}).status_code == 200
            for _ in range(1000):
                m = ws.receive_json(); seen.append(m)
                if m["type"] == "simulation" and m["data"].get("status") in ("completed", "failed"): break
    kinds = {m["type"] for m in seen}; assert {"agent_update", "incident_state", "incident"} <= kinds
    det = [m["data"]["status"] for m in seen if m["type"] == "agent_update" and m["data"]["agent"] == "DetectionAgent"]; assert "RUNNING" in det and "COMPLETED" in det
    assert any(m["type"] == "agent_update" and m["data"]["status"] == "WAITING" for m in seen)
