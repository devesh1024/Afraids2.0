"""The reasoning seam.

Agents gather evidence ONLY through the ToolRegistry and hand it to a `Reasoner` for judgment. Today `DeterministicReasoner` applies
fixed policies. A future `GeminiReasoner` implements the same four methods (JSON in -> JSON out) and nothing else changes:
tools, guardrails (validate_action / authorize), the verifier and the approval workflow still constrain whatever the model proposes.
"""
from __future__ import annotations
import ipaddress
from dataclasses import dataclass, field, asdict
from typing import Protocol
from ..chain import CAUSAL, LABEL
from .config import Settings
from .guardrails import ACTION_POLICIES, Guardrails, PolicyViolation, risk_rank
from .risk import SEV_RANK
from .util import is_public_ip, real_name

ESTABLISHED_LOGINS = 3   # >= this many prior successful logins from an IP => the IP is "established" for the user


@dataclass
class TriageDecision: investigate: bool; reason: str


@dataclass
class FindingDraft:
    description: str; evidence: list; severity: str; confidence: float; source: str
    contradicts: bool = False; evidence_ids: list = field(default_factory=list)


@dataclass
class LoopState:
    iteration: int; max_iterations: int; needs_more_evidence: bool; new_event_count: int; budget_ok: bool


@dataclass
class LoopDecision: action: str; reason: str      # action: "continue" | "stop"


@dataclass
class ResponseDraft:
    action: str; target: str; reason: str; expected_impact: str; confidence: float; approval_level: str
    destructive: bool; params: dict = field(default_factory=dict); evidence_ids: list = field(default_factory=list)


@dataclass
class ResponsePlan:
    actions: list = field(default_factory=list); withheld: list = field(default_factory=list); rejected_by_policy: list = field(default_factory=list)

    def to_dict(self) -> dict: return dict(actions=[asdict(a) for a in self.actions], withheld=self.withheld, rejected_by_policy=self.rejected_by_policy)


class Reasoner(Protocol):
    def should_investigate(self, detection: dict) -> TriageDecision: ...
    def analyze(self, bundle: dict) -> list: ...                 # -> list[FindingDraft]
    def next_step(self, state: LoopState) -> LoopDecision: ...
    def plan_responses(self, case: dict) -> ResponsePlan: ...


def _sev_from_rep(rep: int) -> str: return "critical" if rep >= 90 else "high" if rep >= 70 else "medium"


def _ext_ip(ip) -> bool: return bool(ip) and ip != "n/a" and not str(ip).startswith("10.")


class DeterministicReasoner:
    """Fixed, auditable policies. See analyze() for the evidence-bundle schema."""
    CERTAINTY = {"preserve_evidence": 1.0, "increase_monitoring": 1.0, "block_ip": 0.95, "revoke_session": 0.9, "disable_account": 0.85, "isolate_endpoint": 0.8, "close_incident": 0.7}
    IP_RULES = {"R001", "R002", "R003", "R005", "R008"}          # rules whose *source* IP is the attacker
    USER_RULES = {"R002", "R003", "R004", "R006", "R007"}        # rules implicating an account
    HOST_RULES = {"R004", "R005", "R006", "R007"}                # rules implicating an endpoint

    def __init__(self, settings: Settings | None = None, guard: Guardrails | None = None):
        self.s = settings or Settings(); self.guard = guard or Guardrails(self.s)

    # ---- 1. triage
    def should_investigate(self, detection: dict) -> TriageDecision:
        hits = detection.get("hits", [])
        if not hits: return TriageDecision(False, "no rule or anomaly signal")
        return TriageDecision(True, "detections: " + ", ".join(h["rule_id"] for h in hits))

    # ---- 2. evidence -> findings
    def analyze(self, b: dict) -> list:
        """bundle = {alerts, events (sorted dicts), user, host, user_history, host_history, prior_logins_by_ip (dict|None),
        ti {ip: indicator}, techniques [{id,name,tactic,weight,uncertain}], related [incident dicts], incident_start}"""
        out: list = []; alerts, events = b.get("alerts", []), b.get("events", []); user = b.get("user")
        seen_rules: set = set()
        for a in reversed(alerts):
            if a["rule_id"] in seen_rules: continue
            seen_rules.add(a["rule_id"]); ev = (a.get("evidence") or [])[:3]
            out.append(FindingDraft(f"{a['rule_id']} {a['name']}: {ev[0] if ev else 'rule matched'}", ev, a["severity"], a["confidence"],
                                    "ml" if a["rule_id"] == "ML001" else "rule", evidence_ids=[f"alert:{a['id']}"] + ([f"event:{a['event_id']}"] if a.get("event_id") else [])))
        scores = [a["anomaly_score"] for a in alerts if a.get("anomaly_score") is not None and a["rule_id"] != "ML001"]
        if scores:
            st = max(0.0, min(1.0, (max(scores) - 0.45) / 0.25))
            out.append(FindingDraft(f"ML anomaly corroborates rule detections (Isolation Forest score {max(scores)})", [f"score {max(scores)}"], "medium", round(0.5 + 0.3 * st, 2), "ml"))
        attacker_ips = self._attacker_ips(alerts, events)
        rel = [e for e in events if (real_name(user) and e["user"] == user) or e["src_ip"] in attacker_ips or (not real_name(user) and e["host"] == b.get("host"))]
        out += self._sequence(rel) + self._baseline(b, attacker_ips, alerts, events) + self._intel(b.get("ti", {})) + self._techniques(b.get("techniques", []))
        out += self._relationships(events, attacker_ips) + self._behavior(b)
        if b.get("related"):
            r = b["related"]; out.append(FindingDraft(f"{len(r)} related incident(s) share entities with this one", [f"{x['title']} ({', '.join(x['shared'])})" for x in r[:3]], "medium", 0.65, "related_incident",
                                                      evidence_ids=[f"incident:{x['id']}" for x in r[:3]]))
        seen, uniq = set(), []
        for f in out:
            k = (f.source, f.description)
            if k not in seen: seen.add(k); uniq.append(f)
        return uniq

    def _attacker_ips(self, alerts, events) -> list:
        by_id = {e["id"]: e for e in events}; ips: list = []
        for a in alerts:
            e = by_id.get(a.get("event_id"))
            if e and _ext_ip(e["src_ip"]) and e["src_ip"] not in ips: ips.append(e["src_ip"])
        return ips

    def _sequence(self, events) -> list:
        evs = sorted(events, key=lambda e: e["timestamp"]); stages: list = []
        for e in evs:
            if stages and stages[-1]["event_type"] == e["event_type"] and stages[-1]["host"] == e["host"]: stages[-1]["n"] += 1; continue
            stages.append(dict(event_type=e["event_type"], host=e["host"], user=e["user"], src_ip=e["src_ip"], n=1, id=e["id"]))
        links = sum(1 for p, c in zip(stages, stages[1:]) if (p["event_type"], c["event_type"]) in CAUSAL and (p["user"] == c["user"] or p["host"] == c["host"] or p["src_ip"] == c["src_ip"]))
        if links < 1: return []
        label = " → ".join(LABEL.get(s["event_type"], s["event_type"]) + (f" ×{s['n']}" if s["n"] > 1 else "") for s in stages)
        return [FindingDraft(f"Multi-stage attack sequence ({links} causal link{'s' if links > 1 else ''}): {label}", [label], "critical" if links >= 3 else "high" if links == 2 else "medium",
                             round(min(0.9, 0.6 + 0.1 * links), 2), "sequence", evidence_ids=[f"event:{stages[0]['id']}", f"event:{stages[-1]['id']}"])]

    def _baseline(self, b, attacker_ips, alerts, events) -> list:
        prior = b.get("prior_logins_by_ip"); user = b.get("user"); out: list = []
        if prior is None or not real_name(user): return out
        login_ips = {e["src_ip"] for e in events if e["user"] == user and e["event_type"] in ("login_success", "login_failure") and _ext_ip(e["src_ip"])}
        has_cred_alert = any(a["rule_id"] in ("R001", "R002") for a in alerts)
        for ip in sorted(login_ips):
            n = prior.get(ip, 0)
            if n == 0: out.append(FindingDraft(f"No successful login from {ip} for {user} in the prior 30 days (new source)", [f"prior successful logins: 0"], "medium", 0.7, "baseline"))
            elif n >= ESTABLISHED_LOGINS and has_cred_alert:
                out.append(FindingDraft(f"{ip} is an established source for {user} ({n} prior successful logins): activity may be a legitimate user mistyping a password",
                                        [f"prior successful logins: {n}"], "low", 0.7, "baseline", contradicts=True))
        return out

    def _intel(self, ti) -> list:
        out = []
        for ip, m in ti.items():
            rep = int(m.get("reputation", 0))
            if rep >= 50: out.append(FindingDraft(f"{ip} matches threat intelligence: {m.get('category')} (reputation {rep}, {m.get('source')})", [f"{ip}: {m.get('category')}"], _sev_from_rep(rep),
                                                  round(min(0.9, 0.5 + rep / 250), 2), "threat_intel", evidence_ids=[f"ioc:{ip}"]))
        return out

    def _techniques(self, techs) -> list:
        return [FindingDraft(f"ATT&CK {t['id']} {t['name']} ({t['tactic']})" + (" — uncertain mapping" if t.get("uncertain") else ""), [t["tactic"]],
                             "high" if t["weight"] >= 12 else "medium" if t["weight"] >= 8 else "low", 0.5 if t.get("uncertain") else 0.8, "attack_mapping", evidence_ids=[f"technique:{t['id']}"]) for t in techs]

    def _relationships(self, events, attacker_ips) -> list:
        out = []
        for ip in attacker_ips:
            ev = [e for e in events if e["src_ip"] == ip]; hosts = {e["host"] for e in ev}; users = {e["user"] for e in ev if real_name(e["user"])}
            if len(hosts) >= 2 or len(users) >= 2:
                out.append(FindingDraft(f"External IP {ip} touched {len(hosts)} host(s) and {len(users)} account(s)", [f"hosts: {sorted(hosts)}", f"users: {sorted(users)}"], "high", 0.7, "ip_relationship"))
        procs: dict = {}
        for e in sorted(events, key=lambda x: x["timestamp"]):
            if e["event_type"] in ("process_execution", "suspicious_process"): procs.setdefault(e["host"], []).append((e["meta"] or {}).get("process", "?"))
            elif e["event_type"] == "privilege_escalation" and procs.get(e["host"]):
                out.append(FindingDraft(f"Process '{procs[e['host']][-1]}' preceded privilege escalation ({(e['meta'] or {}).get('method', 'unknown')}) on {e['host']}", [f"host {e['host']}"], "high", 0.65, "process_relationship",
                                        evidence_ids=[f"event:{e['id']}"]))
        return out

    def _behavior(self, b) -> list:
        out = []; uh, hh = b.get("user_history") or {}, b.get("host_history") or {}
        if len(uh.get("hosts", [])) >= 3: out.append(FindingDraft(f"{b.get('user')} was active on {len(uh['hosts'])} hosts in the window", [f"hosts: {uh['hosts']}"], "medium", 0.55, "user_behavior"))
        if len(hh.get("users", [])) >= 3: out.append(FindingDraft(f"{len(hh['users'])} distinct accounts were active on {b.get('host')}", [f"users: {hh['users']}"], "medium", 0.55, "host_behavior"))
        return out

    # ---- 3. bounded loop decision (the supervisor ALSO enforces the hard bound)
    def next_step(self, st: LoopState) -> LoopDecision:
        if not st.needs_more_evidence: return LoopDecision("stop", "sufficient_evidence")
        if st.iteration >= st.max_iterations: return LoopDecision("stop", "max_iterations")
        if st.iteration > 1 and st.new_event_count == 0: return LoopDecision("stop", "no_new_evidence")
        if not st.budget_ok: return LoopDecision("stop", "tool_budget")
        return LoopDecision("continue", "evidence insufficient; widening the time window")

    # ---- 4. response planning
    def plan_responses(self, case: dict) -> ResponsePlan:
        """case = {incident_id, risk:{severity,risk_score,confidence}, needs_review, alerts, events, ti, contradictions, primary_user, primary_host}"""
        lvl = case["risk"]["severity"]; tier = risk_rank(lvl); conf = case["risk"]["confidence"]; plan = ResponsePlan()
        events = {e["id"]: e for e in case.get("events", [])}; ips, users, hosts, ev_ids = [], [], [], []
        def push(lst, v):
            if v and v not in lst: lst.append(v)
        for a in case.get("alerts", []):
            e = events.get(a.get("event_id")); rid = a["rule_id"]
            if not e: continue
            if rid in self.IP_RULES and is_public_ip(e["src_ip"]): push(ips, e["src_ip"])
            if rid == "R007" and is_public_ip(e["dst_ip"]): push(ips, e["dst_ip"])
            if rid in self.USER_RULES and real_name(e["user"]): push(users, e["user"])
            if rid in self.HOST_RULES: push(hosts, e["host"])
            push(ev_ids, f"alert:{a['id']}")
        cap = self.s.max_targets_per_action

        def add(action, target, reason):
            pol = ACTION_POLICIES[action]
            if risk_rank(pol.min_risk) > tier: return
            try: va = self.guard.validate_action(action, target)
            except PolicyViolation as pv: plan.rejected_by_policy.append(dict(action=action, target=target, code=pv.code, message=pv.message)); return
            if case.get("needs_review") and pol.destructive:
                plan.withheld.append(dict(action=action, target=va.target, reason="withheld: evidence is insufficient or contradictory; analyst review required first")); return
            plan.actions.append(ResponseDraft(action, va.target, reason, pol.expected_impact.format(target=va.target), round(min(0.98, conf * self.CERTAINTY[action]), 2),
                                              self.guard.required_level(action, lvl), pol.destructive, {}, list(ev_ids[:5])))

        add("preserve_evidence", case["incident_id"], f"Preserve evidence before any containment ({lvl} risk, score {case['risk'].get('risk_score')})")
        add("increase_monitoring", users[0] if users else (case.get("primary_user") if real_name(case.get("primary_user")) else case.get("primary_host")),
            "Elevated monitoring of the implicated entity regardless of containment decisions")
        for u in users[:cap]: add("revoke_session", u, f"Account '{u}' is implicated in credential misuse or insider activity")
        for ip in ips[:cap]:
            cat = (case.get("ti", {}).get(ip) or {}).get("category")
            add("block_ip", ip, f"{ip} is an attacker-controlled or malicious endpoint" + (f" (threat intel: {cat})" if cat else ""))
        for u in users[:cap]: add("disable_account", u, f"Account '{u}' shows signs of compromise; disable pending review")
        for h in hosts[:cap]: add("isolate_endpoint", h, f"Host '{h}' shows multi-stage compromise; isolate to stop spread/exfiltration")
        ml_only = bool(case.get("alerts")) and all(a["rule_id"] == "ML001" for a in case["alerts"])
        if lvl == "low" and (case.get("contradictions") or ml_only):
            add("close_incident", case["incident_id"], "Low risk with " + ("contradicting evidence" if case.get("contradictions") else "only an ML signal") + ": likely false positive")
        return plan
