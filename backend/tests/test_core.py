import numpy as np
from tests.conftest import ev
from app.ml import AnomalyDetectionService, FEATURES
from app.rules import RuleEngine, score_incident, RULES
from app.intel import KB, technique_for, LocalThreatIntel
from app.chain import reconstruct_chain, build_graph, incident_events, to_networkx
from app.agents import SupervisorAgent
from app.db import Incident, SecurityEvent
from app.simulator import SCENARIOS

NORMAL = dict(login_frequency=2, failed_logins=0, login_hour=13, geo_change=0, files_accessed=10, privilege_changes=0, outbound_connections=1, connection_frequency=4, unusual_processes=0)
BAD = dict(NORMAL, failed_logins=30, privilege_changes=3, outbound_connections=40, files_accessed=900, unusual_processes=4)

def test_anomaly_normal_vs_extreme(tmp_path):
    s = AnomalyDetectionService(str(tmp_path / "m.joblib"))
    assert not s.predict(NORMAL)["is_anomaly"]
    r = s.predict(BAD); assert r["is_anomaly"] and "failed_logins" in [c["feature"] for c in r["contributing_features"]]
    assert set(r) >= {"anomaly_score", "is_anomaly", "contributing_features", "model_version"}

def test_anomaly_persistence(tmp_path):
    p = str(tmp_path / "m.joblib"); a = AnomalyDetectionService(p); b = AnomalyDetectionService(p)
    assert a.version == b.version and a.predict(BAD)["anomaly_score"] == b.predict(BAD)["anomaly_score"]

def test_rules_bruteforce_then_success(db):
    for i in range(5): e = ev(db, "login_failure", i, src="185.220.101.7")
    ids = [h.rule_id for h in RuleEngine().evaluate(db, e)]; assert ids == ["R001"]
    s = ev(db, "login_success", 6, src="185.220.101.7"); ids = [h.rule_id for h in RuleEngine().evaluate(db, s)]
    assert "R002" in ids and "R003" in ids

def test_rules_scan_and_no_false_positive(db):
    for i in range(3): e = ev(db, "port_scan", i, user="n/a", host="fw", src="103.77.192.9")
    assert [h.rule_id for h in RuleEngine().evaluate(db, e)] == ["R008"]
    assert RuleEngine().evaluate(db, ev(db, "login_success", 0, user="quiet", host="hq")) == []

def test_rules_exfil_and_priv(db):
    h = RuleEngine().evaluate(db, ev(db, "data_transfer", 0, dst="45.155.205.233", bytes=480_000_000))[0]
    assert h.rule_id == "R007" and h.uncertain and h.technique == "T1041"
    assert RuleEngine().evaluate(db, ev(db, "privilege_escalation", 1, method="sudo_abuse"))[0].technique == "T1548.003"

def test_mitre_mapping_valid_and_uncertain():
    cases = [("brute_force", {}), ("valid_accounts", {}), ("priv_esc", {"method": "token_theft"}), ("priv_esc", {}), ("susp_process", {"process": "powershell -enc"}),
             ("susp_process", {"process": "nc.exe"}), ("susp_process", {}), ("port_scan", {}), ("file_access", {}), ("exfil", {}), ("malware", {})]
    for k, m in cases: assert technique_for(k, m)[0] in KB
    assert technique_for("brute_force") == ("T1110", False) and technique_for("susp_process", {"process": "powershell"}) == ("T1059.001", False)
    assert technique_for("priv_esc", {"method": "?"})[1] is True and KB["T1110"]["tactic"] == "Credential Access"

def test_threat_intel():
    t = LocalThreatIntel(); i = t.lookup_ip("45.155.205.233")
    assert i.reputation == 95 and i.category == "Botnet C2" and t.lookup_ip("10.0.0.1") is None
    assert t.lookup_domain("EVIL-updates.example") and t.lookup_hash("deadbeef" * 8) and t.lookup_hash("0") is None

def test_risk_scoring_deterministic():
    al = [dict(rule_id="R001", name="a", points=20), dict(rule_id="R001", name="dup", points=20), dict(rule_id="R004", name="b", points=25)]
    sc, lvl, f = score_incident(al, 0.7, True, [dict(indicator="x", reputation=100, category="c")], 3)
    assert [x["kind"] for x in f] == ["rule", "rule", "anomaly", "ti", "chain"] and sc == 20 + 25 + 15 + 15 + 10 and lvl == "critical"
    assert score_incident([dict(rule_id="ML001", name="m", points=30)], 0.9, True)[0] == 30
    assert score_incident(al * 5 + [dict(rule_id=k, name=k, points=25) for k in RULES], 0.9, True, [], 9)[0] == 100

def run(db, scenario):
    sup = SupervisorAgent()
    for _, kw in SCENARIOS[scenario](): e = SecurityEvent(**kw); db.add(e); db.flush(); sup.process(db, e)
    return db.query(Incident).order_by(Incident.created_at.desc()).first()

def test_chain_and_graph_from_exfil(db):
    inc = run(db, "exfiltration"); evs = incident_events(db, inc)
    steps = reconstruct_chain(evs); assert [s["type"] for s in steps] == ["suspicious_process", "file_access", "data_transfer"]
    assert [s["link"] for s in steps] == [None, "causal", "causal"]
    g = build_graph(db, inc); types = {n["type"] for n in g["nodes"]}; assert {"user", "host", "process", "file", "external_ip", "incident", "technique"} <= types
    G = to_networkx(g); assert G.number_of_edges() == len(g["edges"]) and any(e["label"].startswith("sent 480") for e in g["edges"])

def test_chain_collapses_repeats(db):
    for i in range(4): ev(db, "login_failure", i, user="a", host="x", src="185.220.101.7")
    ev(db, "login_success", 5, user="a", host="x", src="185.220.101.7"); ev(db, "privilege_escalation", 6, user="a", host="x")
    s = reconstruct_chain(db.query(SecurityEvent).filter(SecurityEvent.host == "x").all())
    assert [(x["label"], x["count"]) for x in s] == [("Failed login", 4), ("Successful login", 1), ("Privilege escalation", 1)] and s[2]["link"] == "causal"

def test_end_to_end_bruteforce(db):
    inc = run(db, "brute_force"); assert inc.risk_level in ("high", "critical") and inc.risk_score >= 60
    kinds = {f["kind"] for f in inc.risk_factors}; assert {"rule", "ti"} <= kinds
    assert {t["id"] for t in inc.techniques} >= {"T1110", "T1078"} and all(f["points"] > 0 for f in inc.risk_factors)

def test_alembic_migration_and_full_attack_kb(tmp_path):
    import subprocess, sys, os, sqlite3
    env = dict(os.environ, DATABASE_URL=f"sqlite:///{tmp_path}/mig.db")
    subprocess.run([sys.executable, "-c", "from app.db import init_db; init_db()"], check=True, env=env, cwd=os.path.join(os.path.dirname(__file__), ".."))
    t = {r[0] for r in sqlite3.connect(tmp_path / "mig.db").execute("select name from sqlite_master")}
    assert {"security_events", "incidents", "risk_assessments", "alembic_version"} <= t
    assert len(KB) > 500 and KB["T1059.001"]["name"] == "PowerShell"
