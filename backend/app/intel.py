"""MITRE ATT&CK knowledge base, event->technique mapping, and threat-intelligence service abstraction."""
import json, os
from abc import ABC, abstractmethod
from dataclasses import dataclass

_RAW = {  # id: (name, tactic, description, detection guidance, related). Curated subset; load_stix() can extend from enterprise-attack.json.
 "T1110": ("Brute Force", "Credential Access", "Repeated credential guessing to gain access.", "Alert on many failed authentications from one source in a short window.", ["T1078"]),
 "T1078": ("Valid Accounts", "Defense Evasion, Persistence, Privilege Escalation, Initial Access", "Use of legitimate credentials to gain or keep access.", "Baseline per-user source IPs and hours; flag new origins, especially after failures.", ["T1110"]),
 "T1059": ("Command and Scripting Interpreter", "Execution", "Abuse of interpreters to run commands.", "Monitor interpreter launches with unusual arguments or parents.", ["T1059.001", "T1059.003"]),
 "T1059.001": ("PowerShell", "Execution", "Abuse of PowerShell to run commands and scripts.", "Log script blocks; flag encoded commands.", ["T1059"]),
 "T1059.003": ("Windows Command Shell", "Execution", "Abuse of cmd.exe to run commands.", "Monitor cmd.exe process trees.", ["T1059"]),
 "T1033": ("System Owner/User Discovery", "Discovery", "Identifying the current user of a system.", "Flag whoami-style commands after new logins.", []),
 "T1046": ("Network Service Discovery", "Discovery", "Scanning hosts for open services.", "Alert on one source touching many ports or hosts.", []),
 "T1068": ("Exploitation for Privilege Escalation", "Privilege Escalation", "Exploiting software flaws to gain higher privileges.", "Monitor for unexpected privilege changes.", ["T1134", "T1548.003"]),
 "T1134": ("Access Token Manipulation", "Defense Evasion, Privilege Escalation", "Stealing or forging access tokens to act as another principal.", "Monitor token duplication and impersonation.", ["T1068"]),
 "T1548.003": ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation, Defense Evasion", "Abusing sudo to run commands with elevated rights.", "Audit sudo usage outside normal duties.", ["T1068"]),
 "T1005": ("Data from Local System", "Collection", "Collecting data from the local file system.", "Flag bulk reads of sensitive files.", []),
 "T1041": ("Exfiltration Over C2 Channel", "Exfiltration", "Sending stolen data over an existing command-and-control channel.", "Alert on large outbound transfers to rare destinations.", ["T1048"]),
 "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration", "Exfiltrating over a protocol other than the C2 channel.", "Baseline egress protocols and volumes.", ["T1041"]),
 "T1095": ("Non-Application Layer Protocol", "Command and Control", "Communicating over non-application-layer protocols (e.g. raw sockets).", "Flag netcat-like tools and odd raw connections.", []),
 "T1204": ("User Execution", "Execution", "Relying on a user to run malicious content.", "Correlate malware detections with recent user actions.", []),
}
_CURATED = {k: dict(id=k, name=v[0], tactic=v[1], description=v[2], detection=v[3], related=v[4]) for k, v in _RAW.items()}
_FULL = os.path.join(os.path.dirname(__file__), "..", "data", "attack_techniques.json")  # built from MITRE enterprise-attack STIX (see README)
KB = json.load(open(_FULL)) if os.path.exists(_FULL) else {}
KB.update(_CURATED)  # hand-written entries override for the techniques our detections map to

def load_stix(path: str) -> int:
    """Extend KB from a MITRE enterprise-attack STIX bundle (optional, offline file). Returns techniques added."""
    n = 0
    for o in json.load(open(path)).get("objects", []):
        if o.get("type") != "attack-pattern" or o.get("revoked"): continue
        ref = next((r["external_id"] for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if ref and ref not in KB:
            KB[ref] = dict(id=ref, name=o["name"], tactic=", ".join(p["phase_name"] for p in o.get("kill_chain_phases", [])),
                           description=o.get("description", "")[:300], detection=o.get("x_mitre_detection", "")[:300], related=[]); n += 1
    return n

def technique_for(kind: str, meta: dict | None = None) -> tuple[str, bool]:
    """Map a detection kind (+event metadata) to (ATT&CK ID, uncertain). Uncertain = best-effort, not definitive."""
    m = meta or {}; p = str(m.get("process", "")).lower()
    if kind == "brute_force": return "T1110", False
    if kind == "valid_accounts": return "T1078", False
    if kind == "priv_esc": return {"token_theft": ("T1134", False), "sudo_abuse": ("T1548.003", False)}.get(m.get("method"), ("T1068", True))
    if kind == "susp_process":
        if "powershell" in p: return "T1059.001", False
        if "cmd" in p: return "T1059.003", False
        if "whoami" in p: return "T1033", False
        if p.startswith("nc"): return "T1095", True
        return "T1059", True
    if kind == "port_scan": return "T1046", False
    if kind == "file_access": return "T1005", False
    if kind == "exfil": return "T1041", True   # channel type unknown from volume alone
    if kind == "malware": return "T1204", True
    raise ValueError(f"unknown kind {kind}")

@dataclass
class Indicator:
    indicator: str; type: str; reputation: int; category: str; first_seen: str; last_seen: str; source: str

class ThreatIntelligenceService(ABC):
    """Lookup abstraction. Return None when the indicator is unknown."""
    @abstractmethod
    def lookup_ip(self, ip: str) -> Indicator | None: ...
    @abstractmethod
    def lookup_domain(self, domain: str) -> Indicator | None: ...
    @abstractmethod
    def lookup_hash(self, h: str) -> Indicator | None: ...

class LocalThreatIntel(ThreatIntelligenceService):
    """Synthetic offline feed (fictional data; reputation 0-100, higher = worse)."""
    DATA = [Indicator("185.220.101.7", "ip", 70, "Tor exit node", "2025-01-10", "2026-09-30", "synthetic-feed"),
            Indicator("45.155.205.233", "ip", 95, "Botnet C2", "2025-03-02", "2026-10-01", "synthetic-feed"),
            Indicator("103.77.192.9", "ip", 60, "Mass scanner", "2025-06-18", "2026-09-28", "synthetic-feed"),
            Indicator("evil-updates.example", "domain", 90, "Malware delivery", "2025-04-04", "2026-09-15", "synthetic-feed"),
            Indicator("deadbeef" * 8, "hash", 100, "Ransomware sample", "2025-07-21", "2026-08-30", "synthetic-feed")]
    def __init__(self): self.db = {(i.type, i.indicator.lower()): i for i in self.DATA}
    def _get(self, t, v): return self.db.get((t, (v or "").lower()))
    def lookup_ip(self, ip): return self._get("ip", ip)
    def lookup_domain(self, domain): return self._get("domain", domain)
    def lookup_hash(self, h): return self._get("hash", h)

class PublicApiAdapter(ThreatIntelligenceService):
    """Interface stub for a public TI API (needs a key; not used in v1). Subclass and implement the three lookups."""
    def __init__(self, api_key: str | None = None): self.api_key = api_key
    def _na(self): raise NotImplementedError("Public TI adapter not implemented in v1")
    def lookup_ip(self, ip): self._na()
    def lookup_domain(self, domain): self._na()
    def lookup_hash(self, h): self._na()
