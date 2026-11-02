"""Controlled tool registry. Agents reach data ONLY through these tools.

Every call: checks the agent's permission and the tool-call budget, validates input (pydantic), returns a structured ToolResult
(never raises), and is recorded in the tool_calls table. Tools are read-only / computational: none mutates incident state.
"""
from __future__ import annotations
import ipaddress, logging, re, time
from collections import Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Callable, Literal
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator
from sqlalchemy import or_
from ..agents import ANOMALY, TI, RULES
from ..chain import build_graph, incident_events, reconstruct_chain, to_networkx
from ..db import SecurityEvent, Incident, ToolCall, uid
from ..intel import KB
from ..ml import FEATURES, ext
from .guardrails import KNOWN_EVENT_TYPES, Guardrails, PolicyViolation
from .risk import collect_inputs, compute_risk, tactic_names, technique_weight, techniques_from_alerts
from .util import jsonable, utcnow

log = logging.getLogger("agentic.tools")


class ToolError(Exception):
    def __init__(self, code: str, message: str): super().__init__(message); self.code = code


class ToolBudgetExceeded(ToolError):
    def __init__(self, message: str): super().__init__("budget_exceeded", message)


class ToolBudget:
    """Per-run cap on tool calls. `reserved` calls are kept for the Graph/Risk/Response agents so a greedy investigation cannot starve them."""
    RESERVED_AGENTS = frozenset({"AttackGraphAgent", "RiskAssessmentAgent", "ResponseAgent"})

    def __init__(self, total: int, reserved: int = 0, per_agent: int = 30):
        self.total, self.reserved, self.per_agent = total, min(reserved, total), per_agent
        self.used = 0; self.by_execution: dict = {}

    def limit_for(self, agent: str) -> int: return self.total if agent in self.RESERVED_AGENTS else self.total - self.reserved

    def remaining_for(self, agent: str) -> int: return max(0, self.limit_for(agent) - self.used)

    def can_continue_investigation(self, needed: int = 10) -> bool: return self.remaining_for("InvestigationAgent") >= needed

    def consume(self, agent: str, execution_id: str | None = None) -> None:
        if self.used >= self.limit_for(agent): raise ToolBudgetExceeded(f"tool-call budget exhausted for {agent} ({self.used}/{self.limit_for(agent)})")
        if execution_id and self.by_execution.get(execution_id, 0) >= self.per_agent:
            raise ToolBudgetExceeded(f"{agent} reached its per-execution tool-call cap ({self.per_agent})")
        self.used += 1
        if execution_id: self.by_execution[execution_id] = self.by_execution.get(execution_id, 0) + 1


@dataclass
class ToolServices:
    anomaly: object = ANOMALY; ti: object = TI; rules: object = RULES


@dataclass
class ToolContext:
    db: object; guard: Guardrails; budget: ToolBudget; agent: str; services: ToolServices
    incident_id: str | None = None; execution_id: str | None = None; run_id: str | None = None


@dataclass
class ToolResult:
    ok: bool; tool: str; data: dict | None = None; error: str | None = None; code: str | None = None
    summary: str = ""; duration_ms: float = 0.0; call_id: str | None = None


@dataclass(frozen=True)
class ToolSpec:
    name: str; description: str; input_model: type; handler: Callable; read_only: bool = True


class ToolRegistry:
    def __init__(self): self._tools: dict = {}

    def register(self, spec: ToolSpec, replace: bool = False) -> None:
        if spec.name in self._tools and not replace: raise ValueError(f"tool {spec.name} already registered")
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None: return self._tools.get(name)

    def names(self) -> list: return sorted(self._tools)

    def describe(self) -> list:
        return [dict(name=s.name, description=s.description, read_only=s.read_only, input_schema=s.input_model.model_json_schema()) for s in self._tools.values()]

    def call(self, name: str, ctx: ToolContext, **kwargs) -> ToolResult:
        started, t0 = utcnow(), time.perf_counter(); ok, data, error, code = False, None, None, None
        try:
            spec = self._tools.get(name)
            if spec is None: raise ToolError("unknown_tool", f"unknown tool {name!r}")
            ctx.guard.check_tool_allowed(ctx.agent, name)
            ctx.budget.consume(ctx.agent, ctx.execution_id)
            try: args = spec.input_model.model_validate(kwargs)
            except ValidationError as ve:
                raise ToolError("invalid_input", "; ".join(f"{'.'.join(map(str, e['loc'])) or 'input'}: {e['msg']}" for e in ve.errors()))
            data = spec.handler(ctx, args); ok = True
        except ToolError as e: code, error = e.code, str(e)
        except PolicyViolation as pv: code, error = pv.code, pv.message
        except Exception as e:
            log.exception("tool %s crashed", name); code, error = "tool_exception", f"{type(e).__name__}: {e}"
        dur = round((time.perf_counter() - t0) * 1000, 2)
        summary = str((data or {}).get("summary", "")) if ok and isinstance(data, dict) else ""
        call_id = uid()
        try:
            ctx.db.add(ToolCall(id=call_id, incident_id=ctx.incident_id, execution_id=ctx.execution_id, run_id=ctx.run_id, agent=ctx.agent, tool=str(name)[:64],
                                input=jsonable(kwargs), output_summary=(summary if ok else (error or ""))[:500], status="ok" if ok else "error", error=error,
                                duration_ms=dur, started_at=started))
        except Exception: log.exception("could not record tool call")
        return ToolResult(ok, str(name), data if ok else None, error, code, summary, dur, call_id)


class BoundTools:
    """A registry bound to one agent execution (this is what agents hold)."""
    def __init__(self, registry: ToolRegistry, ctx: ToolContext):
        self.registry, self.ctx = registry, ctx; self.calls: list = []

    def call(self, name: str, **kwargs) -> ToolResult:
        r = self.registry.call(name, self.ctx, **kwargs); self.calls.append(r); return r

    def success_ratio(self) -> float: return (sum(1 for c in self.calls if c.ok) / len(self.calls)) if self.calls else 1.0

    def used(self) -> list:
        return [dict(tool=c.tool, ok=c.ok, duration_ms=c.duration_ms, summary=c.summary or c.error or "", error=c.error, call_id=c.call_id) for c in self.calls]


# ------------------------------------------------------------------ input models
def _naive(dt):
    if dt is not None and dt.tzinfo is not None: dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


_S = dict(min_length=1, max_length=128)


class SearchEventsIn(BaseModel):
    host: str | None = Field(None, **_S); user: str | None = Field(None, **_S); ip: str | None = Field(None, min_length=1, max_length=64)
    event_type: str | None = Field(None, min_length=1, max_length=64); start: datetime | None = None; end: datetime | None = None
    window_minutes: int = Field(60, ge=1, le=43200); limit: int = Field(100, ge=1, le=500)

    @model_validator(mode="after")
    def _check(self):
        if not any([self.host, self.user, self.ip, self.event_type]): raise ValueError("at least one of host, user, ip, event_type is required")
        if self.ip: ipaddress.ip_address(self.ip)
        if self.event_type and self.event_type not in KNOWN_EVENT_TYPES: raise ValueError(f"unknown event_type {self.event_type!r}")
        self.start, self.end = _naive(self.start), _naive(self.end); return self


class HistoryIn(BaseModel):
    user: str | None = Field(None, **_S); host: str | None = Field(None, **_S)
    end: datetime | None = None; window_minutes: int = Field(1440, ge=1, le=43200)

    @field_validator("end")
    @classmethod
    def _n(cls, v): return _naive(v)


class UserHistoryIn(HistoryIn):
    user: str = Field(..., **_S)


class HostHistoryIn(HistoryIn):
    host: str = Field(..., **_S)


class IpIn(BaseModel):
    ip: str

    @field_validator("ip")
    @classmethod
    def _ip(cls, v): ipaddress.ip_address(v); return v


_LABEL = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?$")


class DomainIn(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253)

    @field_validator("domain")
    @classmethod
    def _d(cls, v):
        labels = v.strip().lower().rstrip(".").split(".")
        if len(labels) < 2 or not all(_LABEL.match(x) for x in labels): raise ValueError("not a valid domain name")
        return ".".join(labels)


class HashIn(BaseModel):
    hash: str

    @field_validator("hash")
    @classmethod
    def _h(cls, v):
        if not re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", v): raise ValueError("expected an MD5, SHA-1 or SHA-256 hex digest")
        return v.lower()


class TechniqueIn(BaseModel):
    technique_id: str

    @field_validator("technique_id")
    @classmethod
    def _t(cls, v):
        if not re.fullmatch(r"T\d{4}(\.\d{3})?", v): raise ValueError("expected an ATT&CK id like T1059 or T1059.001")
        return v


class IncidentIn(BaseModel): incident_id: str = Field(..., min_length=1, max_length=64)


class RiskIn(IncidentIn): run_id: str | None = Field(None, max_length=64)


class RelatedIn(IncidentIn): limit: int = Field(10, ge=1, le=50)


class BaselineIn(BaseModel):
    kind: Literal["user", "host"]; value: str = Field(..., **_S)


# ------------------------------------------------------------------ handlers
def _ev(e) -> dict:
    return dict(id=e.id, timestamp=e.timestamp.isoformat(), event_type=e.event_type, user=e.user, host=e.host, src_ip=e.src_ip, dst_ip=e.dst_ip, severity=e.severity, meta=e.meta or {})


def _window(a) -> tuple:
    end = a.end or utcnow(); start = a.start or end - timedelta(minutes=a.window_minutes)
    if start > end: raise ToolError("invalid_input", "start must not be after end")
    return start, end


def h_search(ctx: ToolContext, a: SearchEventsIn) -> dict:
    start, end = _window(a); q = ctx.db.query(SecurityEvent).filter(SecurityEvent.timestamp >= start, SecurityEvent.timestamp <= end)
    if a.host: q = q.filter(SecurityEvent.host == a.host)
    if a.user: q = q.filter(SecurityEvent.user == a.user)
    if a.ip: q = q.filter(or_(SecurityEvent.src_ip == a.ip, SecurityEvent.dst_ip == a.ip))
    if a.event_type: q = q.filter(SecurityEvent.event_type == a.event_type)
    rows = q.order_by(SecurityEvent.timestamp.asc()).limit(a.limit + 1).all(); trunc = len(rows) > a.limit; rows = rows[:a.limit]
    return dict(count=len(rows), truncated=trunc, events=[_ev(e) for e in rows], window=dict(start=start.isoformat(), end=end.isoformat()),
                summary=f"{len(rows)} event(s)" + (" (truncated)" if trunc else "") + f" in {int((end - start).total_seconds() // 60)} min window")


def _ip_table(rows) -> list:
    t: dict = {}
    for e in rows:
        if not e.src_ip: continue
        d = t.setdefault(e.src_ip, dict(ip=e.src_ip, count=0, first_seen=e.timestamp, last_seen=e.timestamp, external=ext(e.src_ip)))
        d["count"] += 1; d["first_seen"] = min(d["first_seen"], e.timestamp); d["last_seen"] = max(d["last_seen"], e.timestamp)
    return [dict(d, first_seen=d["first_seen"].isoformat(), last_seen=d["last_seen"].isoformat()) for d in sorted(t.values(), key=lambda x: -x["count"])]


def h_user_history(ctx: ToolContext, a: UserHistoryIn) -> dict:
    if a.user == "n/a": return dict(applicable=False, user=a.user, summary="no user context")
    end = a.end or utcnow(); start = end - timedelta(minutes=a.window_minutes)
    rows = ctx.db.query(SecurityEvent).filter(SecurityEvent.user == a.user, SecurityEvent.timestamp >= start, SecurityEvent.timestamp <= end).order_by(SecurityEvent.timestamp).all()
    by = Counter(e.event_type for e in rows); ips = _ip_table(rows)
    prior = ctx.db.query(Incident).filter(Incident.key.endswith("|" + a.user, autoescape=True)).count()
    return dict(applicable=True, user=a.user, window_minutes=a.window_minutes, total_events=len(rows), by_type=dict(by), hosts=sorted({e.host for e in rows}), src_ips=ips,
                external_ips=[i["ip"] for i in ips if i["external"]], failed_logins=by.get("login_failure", 0), successful_logins=by.get("login_success", 0),
                login_hours=sorted({e.timestamp.hour for e in rows if e.event_type == "login_success"}), prior_incidents=prior,
                first_seen=rows[0].timestamp.isoformat() if rows else None, last_seen=rows[-1].timestamp.isoformat() if rows else None,
                summary=f"{a.user}: {len(rows)} event(s), {len(ips)} source IP(s), {prior} incident(s) on record")


def h_host_history(ctx: ToolContext, a: HostHistoryIn) -> dict:
    end = a.end or utcnow(); start = end - timedelta(minutes=a.window_minutes)
    rows = ctx.db.query(SecurityEvent).filter(SecurityEvent.host == a.host, SecurityEvent.timestamp >= start, SecurityEvent.timestamp <= end).order_by(SecurityEvent.timestamp).all()
    by = Counter(e.event_type for e in rows); prior = ctx.db.query(Incident).filter(Incident.key.startswith(a.host + "|", autoescape=True)).count()
    procs = sorted({str((e.meta or {}).get("process")) for e in rows if (e.meta or {}).get("process")})
    return dict(host=a.host, window_minutes=a.window_minutes, total_events=len(rows), by_type=dict(by), users=sorted({e.user for e in rows if e.user and e.user != "n/a"}),
                external_sources=sorted({e.src_ip for e in rows if ext(e.src_ip)}), external_destinations=sorted({e.dst_ip for e in rows if ext(e.dst_ip)}), processes=procs,
                prior_incidents=prior, summary=f"{a.host}: {len(rows)} event(s), {len(procs)} process(es), {prior} incident(s) on record")


def _ind(i):
    return asdict(i) if i else None


def h_ip(ctx: ToolContext, a: IpIn) -> dict:
    i = ctx.services.ti.lookup_ip(a.ip); priv = not ipaddress.ip_address(a.ip).is_global
    return dict(ip=a.ip, found=i is not None, indicator=_ind(i), private=priv, reputation=i.reputation if i else 0,
                summary=f"{a.ip}: {i.category} (reputation {i.reputation})" if i else f"{a.ip}: no intel match" + (" (private address)" if priv else ""))


def h_domain(ctx: ToolContext, a: DomainIn) -> dict:
    i = ctx.services.ti.lookup_domain(a.domain)
    return dict(domain=a.domain, found=i is not None, indicator=_ind(i), reputation=i.reputation if i else 0, summary=f"{a.domain}: {i.category} (reputation {i.reputation})" if i else f"{a.domain}: no intel match")


def h_hash(ctx: ToolContext, a: HashIn) -> dict:
    i = ctx.services.ti.lookup_hash(a.hash)
    return dict(hash=a.hash, found=i is not None, indicator=_ind(i), reputation=i.reputation if i else 0, summary=f"{a.hash[:12]}…: {i.category} (reputation {i.reputation})" if i else f"{a.hash[:12]}…: no intel match")


def h_technique(ctx: ToolContext, a: TechniqueIn) -> dict:
    t = KB.get(a.technique_id)
    if not t: return dict(found=False, id=a.technique_id, summary=f"{a.technique_id}: not in knowledge base")
    w = technique_weight(t["tactic"])
    return dict(found=True, id=a.technique_id, name=t["name"], tactic=t["tactic"], tactics=tactic_names(t["tactic"]), severity_weight=w, description=(t.get("description") or "")[:300],
                detection=(t.get("detection") or "")[:300], related=t.get("related", []), summary=f"{a.technique_id} {t['name']} ({t['tactic']}), severity weight {w:g}")


def _incident(ctx, iid) -> Incident:
    inc = ctx.db.get(Incident, iid)
    if not inc: raise ToolError("not_found", f"incident {iid} not found")
    return inc


def h_graph(ctx: ToolContext, a: IncidentIn) -> dict:
    inc = _incident(ctx, a.incident_id); techs = techniques_from_alerts(inc.alerts)
    g = build_graph(ctx.db, SimpleNamespace(id=inc.id, key=inc.key, techniques=techs)); chain = reconstruct_chain(incident_events(ctx.db, inc)); G = to_networkx(g)
    labels = [s["label"] + (f" ×{s['count']}" if s["count"] > 1 else "") for s in chain]
    return dict(node_count=G.number_of_nodes(), edge_count=G.number_of_edges(), graph=g, chain=chain, chain_labels=labels, techniques=techs,
                summary=f"{G.number_of_nodes()} nodes, {G.number_of_edges()} edges, {len(chain)} chain step(s)")


def h_risk(ctx: ToolContext, a: RiskIn) -> dict:
    inc = _incident(ctx, a.incident_id); inp = collect_inputs(ctx.db, inc, ctx.services.ti, a.run_id); res = compute_risk(inp)
    return dict(risk=asdict(res), inputs=inp.summary(), summary=f"risk {res.risk_score} ({res.severity}), confidence {res.confidence}")


def h_related(ctx: ToolContext, a: RelatedIn) -> dict:
    inc = _incident(ctx, a.incident_id); host, user = inc.key.split("|", 1)
    ips = {e.src_ip for e in incident_events(ctx.db, inc) if ext(e.src_ip)}; via_ip: dict = {}
    if ips:
        for e in ctx.db.query(SecurityEvent).filter(SecurityEvent.src_ip.in_(ips)).limit(1000).all():
            k = f"{e.host}|{e.user}"
            if k != inc.key: via_ip.setdefault(k, set()).add(e.src_ip)
    out = []
    for o in ctx.db.query(Incident).filter(Incident.id != inc.id).order_by(Incident.updated_at.desc()).limit(500).all():
        oh, ou = o.key.split("|", 1); shared = []
        if oh == host: shared.append(f"host:{host}")
        if user != "n/a" and ou == user: shared.append(f"user:{user}")
        shared += [f"ip:{ip}" for ip in sorted(via_ip.get(o.key, []))]
        if shared: out.append(dict(id=o.id, title=o.title, risk_level=o.risk_level, risk_score=o.risk_score, status=o.status, state=o.state, shared=shared))
    out.sort(key=lambda x: -(x["risk_score"] or 0)); out = out[:a.limit]
    return dict(count=len(out), incidents=out, summary=f"{len(out)} related incident(s)")


def h_baseline(ctx: ToolContext, a: BaselineIn) -> dict:
    an = ctx.services.anomaly; model = {f: dict(mean=round(float(m), 3), std=round(float(s), 3)) for f, m, s in zip(FEATURES, an.mean, an.std)}
    end = utcnow(); q = ctx.db.query(SecurityEvent).filter(SecurityEvent.timestamp >= end - timedelta(days=30))
    rows = (q.filter(SecurityEvent.user == a.value) if a.kind == "user" else q.filter(SecurityEvent.host == a.value)).all()
    obs = dict(events_30d=len(rows), distinct_src_ips=len({e.src_ip for e in rows}), login_hours=sorted({e.timestamp.hour for e in rows if e.event_type == "login_success"}))
    return dict(kind=a.kind, value=a.value, model_baseline=model, model_version=an.version, observed=obs,
                note="Model baseline is synthetic (heuristic); 'observed' is the last 30 days of ingested events.", summary=f"baseline for {a.kind} {a.value}: {len(rows)} event(s) in 30 days")


def build_default_registry() -> ToolRegistry:
    r = ToolRegistry()
    for name, desc, model, fn in [
        ("search_security_events", "Search ingested security events by host/user/IP/type within a time window.", SearchEventsIn, h_search),
        ("get_user_history", "Behavioural history of a user (hosts, source IPs, logins, prior incidents).", UserHistoryIn, h_user_history),
        ("get_host_history", "Behavioural history of a host (users, external peers, processes, prior incidents).", HostHistoryIn, h_host_history),
        ("lookup_ip_reputation", "Threat-intelligence reputation of an IP address.", IpIn, h_ip),
        ("lookup_domain_reputation", "Threat-intelligence reputation of a domain.", DomainIn, h_domain),
        ("lookup_hash_reputation", "Threat-intelligence reputation of a file hash.", HashIn, h_hash),
        ("query_attack_technique", "Look up a MITRE ATT&CK technique (tactic, detection guidance, severity weight).", TechniqueIn, h_technique),
        ("build_attack_graph", "Build the attack graph and reconstruct the attack chain for an incident.", IncidentIn, h_graph),
        ("calculate_risk", "Compute the explainable risk score for an incident.", RiskIn, h_risk),
        ("get_related_incidents", "Find other incidents sharing hosts, users or IPs with this one.", RelatedIn, h_related),
        ("get_security_baseline", "Normal-behaviour baseline (synthetic model baseline + observed 30-day stats) for a user or host.", BaselineIn, h_baseline)]:
        r.register(ToolSpec(name, desc, model, fn))
    return r
