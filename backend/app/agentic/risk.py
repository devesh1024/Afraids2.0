"""Transparent risk engine (Phase 3).

score = sum(factor.points)   <- invariant: the factors ALWAYS add up to the reported score (tests enforce this).

Positive factors (max points):  severity 25 | rule_breadth 12 | correlated_events 15 | anomaly 12 | threat_intel 15 |
                                attack_technique 15 | sensitive_asset 10 | privilege_escalation 10
Adjustments (negative points):  cap (ML-only incidents <= 35, total <= 100) and confidence_adjustment
                                (score is scaled by 0.8 + 0.2 * evidence_confidence).
Confidence = weighted alert/finding confidence + corroboration bonus (independent signal families) - contradiction penalty.
Weights live in the constants below. Pure functions: no DB access except collect_inputs().
"""
from __future__ import annotations
from dataclasses import dataclass, field
from ..chain import incident_events
from ..db import InvestigationFinding
from ..intel import KB
from ..rules import SCORING, anomaly_strength

SEVERITY_POINTS = {"low": 4, "medium": 10, "high": 18, "critical": 25}
SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
TACTIC_WEIGHT = {"reconnaissance": 2, "resource development": 3, "initial access": 6, "execution": 6, "persistence": 8, "privilege escalation": 10,
                 "defense evasion": 7, "credential access": 10, "discovery": 3, "lateral movement": 10, "collection": 8,
                 "command and control": 9, "exfiltration": 14, "impact": 15}
DEFAULT_TACTIC_WEIGHT = 3
SENSITIVE_HOSTS = {"fileserver-01": (10, "File server holding sensitive data"), "app-srv-02": (7, "Application server"),
                   "web-srv-01": (5, "Internet-facing web server")}
SENSITIVE_PREFIXES = {"dc-": (10, "Domain controller"), "db-": (10, "Database server"), "fileserver": (10, "File server")}
PRIVILEGED_USERS = {"root": 8, "administrator": 8, "admin": 8}
# Evidence sources that count as *independent* corroboration (different kind of evidence than "a rule matched").
INDEPENDENT_SOURCES = frozenset({"rule", "ml", "threat_intel", "sequence", "baseline", "ip_relationship", "host_behavior", "user_behavior", "related_incident"})


def _round(x: float) -> int: return int(x + 0.5)


def tactic_names(tactic: str | None) -> list[str]:
    return [t.strip().lower().replace("-", " ") for t in (tactic or "").split(",") if t.strip()]


def technique_weight(tactic: str | None, uncertain: bool = False) -> float:
    w = max((TACTIC_WEIGHT.get(t, DEFAULT_TACTIC_WEIGHT) for t in tactic_names(tactic)), default=DEFAULT_TACTIC_WEIGHT)
    return w * 0.5 if uncertain else float(w)


def asset_weight(host: str | None) -> tuple[int, str] | None:
    h = (host or "").lower()
    if h in SENSITIVE_HOSTS: return SENSITIVE_HOSTS[h]
    for p, v in SENSITIVE_PREFIXES.items():
        if h.startswith(p): return v
    return None


def techniques_from_alerts(alerts) -> list[dict]:
    """Distinct ATT&CK techniques referenced by alerts (ORM objects or dicts)."""
    seen: dict = {}
    for a in alerts:
        g = (lambda k: a.get(k)) if isinstance(a, dict) else (lambda k: getattr(a, k, None))
        t = g("technique")
        if t and t in KB and t not in seen:
            seen[t] = dict(id=t, name=KB[t]["name"], tactic=KB[t]["tactic"], uncertain=bool(g("uncertain")))
    return list(seen.values())


def signal_families(alerts: list[dict], findings: list[dict]) -> set:
    fam = {("ml" if a["rule_id"] == "ML001" else "rule") for a in alerts}
    fam |= {f["source"] for f in findings if not f.get("contradicts") and f.get("source") in INDEPENDENT_SOURCES}
    return fam


def evidence_confidence(alert_conf: list[float], finding_conf: list[float], families: set, contradictions: int) -> float:
    if not alert_conf and not finding_conf: return 0.0
    ma = sum(alert_conf) / len(alert_conf) if alert_conf else None
    mf = sum(finding_conf) / len(finding_conf) if finding_conf else None
    base = ma if mf is None else (mf if ma is None else 0.7 * ma + 0.3 * mf)
    bonus = min(0.15, 0.05 * max(0, len(families) - 1)); penalty = 0.1 * contradictions
    return round(max(0.0, min(0.98, base + bonus - penalty)), 2)


@dataclass
class RiskInputs:
    alerts: list = field(default_factory=list)            # dicts: rule_id,name,severity,confidence,anomaly_score
    correlated_event_count: int = 0
    ti_hits: list = field(default_factory=list)           # dicts: indicator,reputation,category
    techniques: list = field(default_factory=list)        # dicts: id,name,tactic,uncertain
    assets: list = field(default_factory=list)            # dicts: name,weight,label
    sensitive_data: bool = False
    privilege_escalation: bool = False
    findings: list = field(default_factory=list)          # dicts: source,confidence,contradicts

    def summary(self) -> dict:
        return dict(alerts=len(self.alerts), correlated_events=self.correlated_event_count, ti_hits=len(self.ti_hits), techniques=len(self.techniques),
                    assets=[a["name"] for a in self.assets], sensitive_data=self.sensitive_data, privilege_escalation=self.privilege_escalation,
                    findings=len(self.findings), contradictions=sum(1 for f in self.findings if f.get("contradicts")))


@dataclass
class RiskResult:
    risk_score: int; severity: str; confidence: float; risk_factors: list


def compute_risk(inp: RiskInputs) -> RiskResult:
    f: list = []

    def add(kind, label, pts, mx, ev=""):
        if pts: f.append(dict(kind=kind, label=label, points=int(pts), max_points=mx, evidence=ev))

    alerts = inp.alerts
    if alerts:
        top = max(alerts, key=lambda a: SEV_RANK.get(a["severity"], 0))
        add("severity", f"Highest alert severity: {top['severity']}", SEVERITY_POINTS.get(top["severity"], 0), 25, f"{top['rule_id']} {top['name']}")
        rules = sorted({a["rule_id"] for a in alerts})
        add("rule_breadth", f"{len(rules)} distinct detection rules fired", min(12, 4 * (len(rules) - 1)) if len(rules) > 1 else 0, 12, ", ".join(rules))
    n = inp.correlated_event_count
    add("correlated_events", f"{n} correlated events", min(15, int(1.5 * (n - 1))) if n > 1 else 0, 15, "events sharing host, user or source IP")
    scores = [a["anomaly_score"] for a in alerts if a.get("anomaly_score") is not None]
    if scores: add("anomaly", "ML anomaly corroboration", _round(12 * anomaly_strength(max(scores))), 12, f"max Isolation Forest score {max(scores)}")
    left, seen = 15, set()
    for h in inp.ti_hits:
        if h["indicator"] in seen: continue
        seen.add(h["indicator"]); p = min(left, _round(h["reputation"] * SCORING["ti_factor"])); left -= p
        add("threat_intel", f"Threat intel: {h['category']}", p, 15, f"{h['indicator']} (reputation {h['reputation']})")
    if inp.techniques:
        base = max(technique_weight(t["tactic"], t.get("uncertain", False)) for t in inp.techniques)
        tactics = {x for t in inp.techniques for x in tactic_names(t["tactic"])}
        add("attack_technique", f"ATT&CK techniques across {len(tactics)} tactic(s)", min(15, _round(base + 3 * max(0, len(tactics) - 1))), 15,
            ", ".join(t["id"] + ("?" if t.get("uncertain") else "") for t in inp.techniques))
    pts, ev = 0, []
    if inp.assets:
        best = max(inp.assets, key=lambda a: a["weight"]); pts += best["weight"]; ev.append(f"{best['name']}: {best['label']}")
    if inp.sensitive_data: pts += 5; ev.append("sensitive data accessed")
    add("sensitive_asset", "Sensitive asset involvement", min(10, pts), 10, "; ".join(ev))
    add("privilege_escalation", "Privilege escalation observed", 10 if inp.privilege_escalation else 0, 10, "rule R004")

    total = sum(x["points"] for x in f)
    ml_only = bool(alerts) and all(a["rule_id"] == "ML001" for a in alerts); cap = SCORING["anomaly_ml_only_cap"]
    if ml_only and total > cap:
        f.append(dict(kind="cap", label="ML-only incidents are capped (ML alone cannot raise a high score)", points=cap - total, max_points=0, evidence=f"cap {cap}")); total = cap
    fam = signal_families(alerts, inp.findings)
    contradictions = sum(1 for x in inp.findings if x.get("contradicts"))
    conf = evidence_confidence([a["confidence"] for a in alerts], [x["confidence"] for x in inp.findings if not x.get("contradicts")], fam, contradictions)
    adj = _round(total * (0.8 + 0.2 * conf)) - total
    if adj < 0:
        add("confidence_adjustment", f"Evidence confidence {conf:.2f} scales the score", adj, 0, "score × (0.8 + 0.2 × confidence)"); total += adj
    if total > 100:
        f.append(dict(kind="cap", label="Score capped at 100", points=100 - total, max_points=0, evidence="")); total = 100
    score = max(0, total)
    return RiskResult(score, next(l for t, l in SCORING["levels"] if score >= t), conf, f)


def collect_inputs(db, inc, ti, run_id: str | None = None) -> RiskInputs:
    """Reads the incident's alerts/events/findings and builds RiskInputs (used by the calculate_risk tool)."""
    alerts = [dict(rule_id=a.rule_id, name=a.rule, severity=a.severity, confidence=a.confidence or 0.0, technique=a.technique, uncertain=bool(a.uncertain),
                   anomaly_score=a.anomaly_score, event_id=a.event_id) for a in inc.alerts]
    events = incident_events(db, inc)
    ips = sorted({x for e in events for x in (e.src_ip, e.dst_ip) if x and x != "n/a"})
    hits = []
    for ip in ips:
        i = ti.lookup_ip(ip)
        if i: hits.append(dict(indicator=i.indicator, reputation=i.reputation, category=i.category))
    assets, seen = [], set()
    for h in sorted({e.host for e in events} | {inc.key.split("|", 1)[0]}):
        w = asset_weight(h)
        if w and h not in seen: seen.add(h); assets.append(dict(name=h, weight=w[0], label=w[1]))
    for u in sorted({e.user for e in events if e.user}):
        if u.lower() in PRIVILEGED_USERS and u not in seen: seen.add(u); assets.append(dict(name=u, weight=PRIVILEGED_USERS[u.lower()], label="Privileged account"))
    findings: list = []
    if run_id:
        rows = db.query(InvestigationFinding).filter(InvestigationFinding.incident_id == inc.id, InvestigationFinding.run_id == run_id).all()
        if rows:
            last = max((r.iteration or 0) for r in rows)   # only the final iteration's findings are the effective set
            findings = [dict(source=r.source, confidence=r.confidence or 0.0, contradicts=bool(r.contradicts)) for r in rows if (r.iteration or 0) == last]
    return RiskInputs(alerts=alerts, correlated_event_count=len(events), ti_hits=hits, techniques=techniques_from_alerts(alerts), assets=assets,
                      sensitive_data=any(a["rule_id"] == "R006" for a in alerts) or any((e.meta or {}).get("sensitive") for e in events),
                      privilege_escalation=any(a["rule_id"] == "R004" for a in alerts), findings=findings)
