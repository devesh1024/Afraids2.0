"""Deterministic rule engine + transparent hybrid scoring.

SCORING STRATEGY (all numbers configurable below):
  incident score = min(100, sum of: unique rule points + anomaly bonus + threat-intel bonus + multi-technique chain bonus)
  * rule points: each distinct rule ID in the incident counts once (RULES weights).
  * anomaly bonus: up to 15, ONLY if rules fired (ML corroborates, never creates a high score alone). ML-only alerts (ML001) are capped at 35.
  * threat-intel bonus: round(reputation*0.15) per matched IOC, max 15.   * chain bonus: +5 per extra distinct technique, max 15.
  Every contribution is returned as a labelled factor, so the score is fully explainable."""
import json
from dataclasses import dataclass, field
from datetime import timedelta
from .db import SecurityEvent, Alert
from .intel import technique_for
from .ml import ext

RULES = {  # id: (name, severity, points, kind)
 "R001": ("Repeated failed logins", "high", 20, "brute_force"), "R002": ("Successful login after brute force", "critical", 25, "valid_accounts"),
 "R003": ("Login from unusual IP", "medium", 15, "valid_accounts"), "R004": ("Privilege escalation", "critical", 25, "priv_esc"),
 "R005": ("Suspicious process execution", "high", 18, "susp_process"), "R006": ("Sensitive file access", "high", 18, "file_access"),
 "R007": ("Unusual outbound transfer", "critical", 25, "exfil"), "R008": ("Port scanning", "medium", 15, "port_scan")}
SCORING = dict(anomaly_bonus_max=15, anomaly_ml_only_cap=35, ti_factor=0.15, ti_bonus_max=15, chain_bonus_per_technique=5, chain_bonus_max=15,
               levels=[(85, "critical"), (60, "high"), (30, "medium"), (0, "low")])

@dataclass
class RuleHit:
    rule_id: str; name: str; severity: str; kind: str; points: int; confidence: float; evidence: list; technique: str; uncertain: bool

def anomaly_strength(s: float) -> float: return max(0.0, min(1.0, (s - 0.45) / 0.25))

def score_incident(alerts: list[dict], anomaly_score: float = 0.0, anomaly_flagged: bool = False, ti_hits: list[dict] | None = None, techniques: int = 0):
    """alerts: dicts with rule_id,name,points,evidence. Returns (score, level, factors)."""
    C, factors, seen = SCORING, [], set()
    for a in alerts:
        if a["rule_id"] in seen: continue
        seen.add(a["rule_id"]); factors.append(dict(kind="ml" if a["rule_id"] == "ML001" else "rule", label=a["name"], points=a["points"], evidence=a.get("evidence", "")))
    if anomaly_flagged and any(a["rule_id"] != "ML001" for a in alerts):
        factors.append(dict(kind="anomaly", label="ML anomaly corroboration", points=round(C["anomaly_bonus_max"] * anomaly_strength(anomaly_score)), evidence=f"score {anomaly_score}"))
    ti = [dict(kind="ti", label=f"Threat intel: {h['category']}", points=round(h["reputation"] * C["ti_factor"]), evidence=h["indicator"]) for h in (ti_hits or [])]
    left = C["ti_bonus_max"]
    for f in ti: f["points"] = min(f["points"], left); left -= f["points"]; factors.append(f)
    if techniques > 1: factors.append(dict(kind="chain", label="Multi-technique attack chain", points=min((techniques - 1) * C["chain_bonus_per_technique"], C["chain_bonus_max"]), evidence=f"{techniques} techniques"))
    score = min(100, sum(f["points"] for f in factors)); factors = [f for f in factors if f["points"] > 0]
    return score, next(l for t, l in C["levels"] if score >= t), factors

class RuleEngine:
    """Evaluates all rules for one event, using DB history windows. Returns RuleHit list (alert, severity, evidence, rule ID)."""
    def __init__(self, weights: dict | None = None): self.w = {k: v[2] for k, v in RULES.items()} | (weights or {})
    def _q(self, db, e, types, minutes, **f):
        q = db.query(SecurityEvent).filter(SecurityEvent.event_type.in_(types), SecurityEvent.timestamp >= e.timestamp - timedelta(minutes=minutes), SecurityEvent.timestamp <= e.timestamp)
        for k, v in f.items(): q = q.filter(getattr(SecurityEvent, k) == v)
        return q.all()
    def _dup(self, db, rid, token): return any(token in json.dumps(a.evidence) for a in db.query(Alert).filter(Alert.rule_id == rid).all())
    def _h(self, rid, ev, meta=None, conf=0.8) -> RuleHit:
        n, sev, _, kind = RULES[rid]; t, unc = technique_for(kind, meta); return RuleHit(rid, n, sev, kind, self.w[rid], conf, ev, t, unc)
    def evaluate(self, db, e) -> list[RuleHit]:
        out, t, m = [], e.event_type, e.meta or {}
        if t == "login_failure":
            n = len(self._q(db, e, ["login_failure"], 10, src_ip=e.src_ip))
            if n >= 5 and not self._dup(db, "R001", e.src_ip): out.append(self._h("R001", [f"{n} failed logins from {e.src_ip} within 10 min"], conf=0.85))
        if t == "login_success":
            n = len(self._q(db, e, ["login_failure"], 15, src_ip=e.src_ip))
            if n >= 5: out.append(self._h("R002", [f"Successful login for {e.user} from {e.src_ip} after {n} failed attempts"], conf=0.95))
            prior = db.query(SecurityEvent).filter(SecurityEvent.user == e.user, SecurityEvent.src_ip == e.src_ip, SecurityEvent.event_type == "login_success",
                                                   SecurityEvent.id != e.id, SecurityEvent.timestamp < e.timestamp).count()
            if ext(e.src_ip) and prior == 0: out.append(self._h("R003", [f"First successful login for {e.user} from external IP {e.src_ip}"], conf=0.7))
        if t == "privilege_escalation":
            after = bool(self._q(db, e, ["login_success"], 30, user=e.user))
            out.append(self._h("R004", [f"Privilege escalation ({m.get('method', 'unknown')}) by {e.user} on {e.host}", "after a recent login" if after else "no recent login observed in window"], m, 0.9 if after else 0.75))
        p = str(m.get("process", "")).lower()
        if t == "suspicious_process" or (t == "process_execution" and any(k in p for k in ("whoami", "mimikatz", "powershell", "nc "))):
            out.append(self._h("R005", [f"Suspicious process '{m.get('process')}' by {e.user} on {e.host}"], m, 0.8))
        if t == "file_access":
            tot = sum(int(x.meta.get("files", 0)) for x in self._q(db, e, ["file_access"], 15, user=e.user, host=e.host))
            if (tot >= 1000 or m.get("sensitive")) and not self._dup(db, "R006", f"{e.user} on {e.host}"): out.append(self._h("R006", [f"{tot} files accessed by {e.user} on {e.host} within 15 min"], conf=0.75))
        if t == "data_transfer" and m.get("bytes", 0) > 50_000_000 and ext(e.dst_ip):
            out.append(self._h("R007", [f"{m['bytes'] // 1_000_000} MB sent from {e.host} to external {e.dst_ip}"], conf=0.88))
        if t == "port_scan":
            n = len(self._q(db, e, ["port_scan"], 10, src_ip=e.src_ip))
            if n >= 3 and not self._dup(db, "R008", e.src_ip): out.append(self._h("R008", [f"{n} port scan events from {e.src_ip}"], conf=0.8))
        return out
