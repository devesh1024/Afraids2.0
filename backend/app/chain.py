"""Attack-chain reconstruction and dynamic attack-graph construction from real incident events."""
import networkx as nx
from .db import SecurityEvent
from .ml import ext

LABEL = {"login_failure": "Failed login", "login_success": "Successful login", "privilege_escalation": "Privilege escalation", "process_execution": "Process execution",
         "suspicious_process": "Suspicious process", "file_access": "File access", "data_transfer": "Outbound transfer", "port_scan": "Port scan",
         "network_connection": "Network connection", "malware_detection": "Malware detected"}
CAUSAL = {("login_failure", "login_success"), ("login_success", "privilege_escalation"), ("login_success", "process_execution"), ("login_success", "suspicious_process"),
          ("process_execution", "privilege_escalation"), ("privilege_escalation", "file_access"), ("privilege_escalation", "data_transfer"), ("suspicious_process", "file_access"),
          ("suspicious_process", "data_transfer"), ("file_access", "file_access"), ("file_access", "data_transfer"), ("port_scan", "suspicious_process"), ("process_execution", "file_access")}

def incident_events(db, inc) -> list[SecurityEvent]:
    """Events tied to an incident: same host, same user, or from the same external source IP."""
    host, user = inc.key.split("|"); q = db.query(SecurityEvent).filter(SecurityEvent.host == host)
    evs = {e.id: e for e in q.all()}
    if user != "n/a": evs.update({e.id: e for e in db.query(SecurityEvent).filter(SecurityEvent.user == user).all()})
    for ip in {e.src_ip for e in evs.values() if ext(e.src_ip)}: evs.update({e.id: e for e in db.query(SecurityEvent).filter(SecurityEvent.src_ip == ip).all()})
    return sorted(evs.values(), key=lambda e: e.timestamp)

def reconstruct_chain(events: list[SecurityEvent], gap_minutes: int = 30) -> list[dict]:
    """Group by temporal proximity + shared user/host/IP, order chronologically, mark causal links, collapse repeats."""
    segs: list[list] = []
    for e in sorted(events, key=lambda e: e.timestamp):
        if segs and (e.timestamp - segs[-1][-1].timestamp).total_seconds() <= gap_minutes * 60: segs[-1].append(e)
        else: segs.append([e])
    best = max(segs, key=len, default=[]); toks, keep = set(), []
    for e in best:
        mine = {f"u:{e.user}", f"h:{e.host}", f"i:{e.src_ip}"} - {"u:n/a"}
        if not toks or toks & mine or f"i:{e.dst_ip}" in toks: keep.append(e); toks |= mine | {f"i:{e.dst_ip}"}
    steps: list[dict] = []
    for e in keep:
        prev = steps[-1] if steps else None
        if prev and prev["type"] == e.event_type and prev["host"] == e.host: prev["count"] += 1; prev["last_time"] = e.timestamp.isoformat(); continue
        share = prev and (prev["user"] == e.user or prev["host"] == e.host or prev["src_ip"] == e.src_ip)
        link = None if not prev else ("causal" if (prev["type"], e.event_type) in CAUSAL and share else "temporal")
        steps.append(dict(order=len(steps) + 1, event_id=e.id, type=e.event_type, label=LABEL.get(e.event_type, e.event_type), time=e.timestamp.isoformat(), last_time=e.timestamp.isoformat(),
                          count=1, user=e.user, host=e.host, src_ip=e.src_ip, dst_ip=e.dst_ip, severity=e.severity, link=link))
    return steps

def build_graph(db, inc) -> dict:
    """Nodes/edges: attacker IP -> user -> host -> process -> file -> external IP, plus incident -> ATT&CK techniques."""
    N, E = {}, {}
    def node(i, t, l): N.setdefault(i, dict(id=i, type=t, label=l)); return i
    def edge(a, b, l): E.setdefault((a, b, l), dict(source=a, target=b, label=l))
    last_proc: dict[str, str] = {}
    for e in incident_events(db, inc):
        m, h = e.meta or {}, node(f"host:{e.host}", "host", e.host); u = node(f"user:{e.user}", "user", e.user) if e.user != "n/a" else None
        ip = node(f"ip:{e.src_ip}", "attacker_ip", e.src_ip) if ext(e.src_ip) else None
        if u: edge(u, h, "on host")
        if e.event_type in ("login_success", "login_failure") and ip and u: edge(ip, u, "login" if e.event_type == "login_success" else "failed login")
        if e.event_type == "port_scan" and ip: edge(ip, h, "scanned")
        if e.event_type in ("process_execution", "suspicious_process", "privilege_escalation"):
            name = m.get("process") or f"privesc:{m.get('method', '?')}"; p = node(f"proc:{e.host}:{name}", "process", name[:24]); edge(h, p, "executed"); last_proc[e.host] = p
        if e.event_type == "file_access":
            f = node(f"file:{e.host}", "file", "sensitive files"); edge(last_proc.get(e.host, h), f, "accessed")
        if e.event_type == "data_transfer" and ext(e.dst_ip):
            d = node(f"ip:{e.dst_ip}", "external_ip", e.dst_ip); edge(f"file:{e.host}" if f"file:{e.host}" in N else last_proc.get(e.host, h), d, f"sent {m.get('bytes', 0) // 1_000_000} MB")
    i = node(f"inc:{inc.id}", "incident", "Incident")
    for t in inc.techniques or []: edge(i, node(f"tech:{t['id']}", "technique", t["id"]), "uses" + (" (uncertain)" if t.get("uncertain") else ""))
    for h in [n for n in N.values() if n["type"] == "host"]: edge(i, h["id"], "affects")
    return dict(nodes=list(N.values()), edges=list(E.values()))

def to_networkx(g: dict) -> nx.DiGraph:
    G = nx.DiGraph(); [G.add_node(n["id"], **n) for n in g["nodes"]]; [G.add_edge(e["source"], e["target"], label=e["label"]) for e in g["edges"]]; return G
