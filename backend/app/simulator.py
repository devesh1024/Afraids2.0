"""Synthetic-only attack scenario generators. Yields (delay_seconds, event_kwargs)."""
import random
ATT = ["185.220.101.7", "45.155.205.233", "103.77.192.9"]
def _e(t, sev, user, host, src, dst, **m): return dict(source="sim", event_type=t, severity=sev, user=user, host=host, src_ip=src, dst_ip=dst, meta=m)
def brute_force():
    ip = random.choice(ATT); u, h = "jsmith", "web-srv-01"
    for _ in range(6): yield 0.4, _e("login_failure", "low", u, h, ip, "10.0.0.5")
    yield 0.6, _e("login_success", "high", u, h, ip, "10.0.0.5")
    yield 0.6, _e("process_execution", "medium", u, h, ip, "10.0.0.5", process="whoami.exe")
def port_scan():
    ip = ATT[2]
    for p in (22, 80, 445, 3389): yield 0.4, _e("port_scan", "medium", "n/a", "dmz-fw-01", ip, "10.0.1.20", port=p)
    yield 0.8, _e("suspicious_process", "high", "svc_web", "app-srv-02", ip, "10.0.1.20", process="nc.exe -e cmd")
def privilege_escalation():
    yield 0.5, _e("process_execution", "low", "akumar", "ws-114", "10.0.2.14", "10.0.2.14", process="cmd.exe")
    yield 0.8, _e("privilege_escalation", "critical", "akumar", "ws-114", "10.0.2.14", "10.0.2.14", method="token_theft")
def exfiltration():
    yield 0.5, _e("suspicious_process", "high", "mlee", "ws-207", "10.0.2.77", "10.0.2.77", process="powershell -enc ...")
    yield 0.8, _e("file_access", "medium", "mlee", "ws-207", "10.0.2.77", "10.0.2.77", files=1200)
    yield 0.8, _e("data_transfer", "critical", "mlee", "ws-207", "10.0.2.77", ATT[1], bytes=480_000_000)
def insider_threat():
    for _ in range(3): yield 0.5, _e("file_access", "medium", "rpatel", "fileserver-01", "10.0.3.9", "10.0.3.2", files=500)
    yield 0.8, _e("privilege_escalation", "high", "rpatel", "fileserver-01", "10.0.3.9", "10.0.3.2", method="sudo_abuse")
    yield 0.8, _e("data_transfer", "critical", "rpatel", "fileserver-01", "10.0.3.9", ATT[0], bytes=900_000_000)
SCENARIOS = {"brute_force": brute_force, "port_scan": port_scan, "privilege_escalation": privilege_escalation,
             "exfiltration": exfiltration, "insider_threat": insider_threat}
