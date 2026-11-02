"""AI guardrails: allowed-action policy, input validation, iteration/tool budgets, authorization.

Everything an agent (deterministic today, LLM later) wants to *do* is checked here. Anything outside policy raises PolicyViolation.
"""
from __future__ import annotations
import ipaddress, json, re
from dataclasses import dataclass
from ..chain import LABEL
from .config import Settings

KNOWN_EVENT_TYPES = frozenset(LABEL)
ROLE_RANK = {"viewer": 0, "analyst": 1, "senior_analyst": 2, "admin": 3}
RISK_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def risk_rank(level: str | None) -> int: return RISK_RANK.get(level or "low", 0)


class PolicyViolation(Exception):
    """code: machine-readable reason; status: suggested HTTP status (403 = not permitted, 422 = invalid input)."""
    def __init__(self, code: str, message: str, status: int = 403):
        super().__init__(message); self.code, self.message, self.status = code, message, status


@dataclass(frozen=True)
class ActionPolicy:
    name: str; description: str; target_kind: str; destructive: bool
    approval_level: str          # minimum role that may approve
    min_risk: str                # lowest risk level at which recommending this action is proportionate
    expected_impact: str         # template, {target} is substituted


_POLICIES = [
    ActionPolicy("preserve_evidence", "Snapshot related events/alerts into a (simulated) evidence manifest", "incident", False, "analyst", "medium",
                 "A read-only evidence manifest is created for incident {target}; no impact on users or systems."),
    ActionPolicy("increase_monitoring", "Add the entity to an elevated-monitoring watchlist", "entity", False, "analyst", "low",
                 "{target} is added to a heightened-monitoring watchlist; no user-visible impact."),
    ActionPolicy("revoke_session", "Invalidate active sessions/tokens of an account", "session", True, "analyst", "medium",
                 "Active sessions for {target} are terminated; the user must sign in again."),
    ActionPolicy("block_ip", "Add an external IP to the (simulated) firewall blocklist", "ip", True, "senior_analyst", "high",
                 "Traffic to/from {target} would be dropped; legitimate users behind that address would lose access."),
    ActionPolicy("disable_account", "Disable a user account pending review", "account", True, "senior_analyst", "high",
                 "{target} cannot sign in until re-enabled; business disruption for that user."),
    ActionPolicy("isolate_endpoint", "Network-isolate a host", "host", True, "admin", "critical",
                 "{target} loses network connectivity except the management plane; services on it become unavailable."),
    ActionPolicy("close_incident", "Close the incident", "incident", False, "analyst", "low",
                 "Incident {target} is closed and removed from the active queue."),
]
ACTION_POLICIES = {p.name: p for p in _POLICIES}
CONTAINMENT_ACTIONS = frozenset({"block_ip", "disable_account", "revoke_session", "isolate_endpoint"})

# Which tools each agent may call (least privilege). Supervisor calls none: it orchestrates, it does not gather evidence.
TOOL_PERMISSIONS = {
    "SupervisorAgent": frozenset(),
    "DetectionAgent": frozenset({"get_security_baseline"}),
    "LogAnalysisAgent": frozenset({"search_security_events", "get_host_history", "get_user_history"}),
    "ThreatIntelligenceAgent": frozenset({"lookup_ip_reputation", "lookup_domain_reputation", "lookup_hash_reputation"}),
    "InvestigationAgent": frozenset({"search_security_events", "get_user_history", "get_host_history", "get_related_incidents",
                                     "query_attack_technique", "get_security_baseline", "lookup_ip_reputation"}),
    "AttackGraphAgent": frozenset({"build_attack_graph"}),
    "RiskAssessmentAgent": frozenset({"calculate_risk"}),
    "ResponseAgent": frozenset({"get_related_incidents"}),
}

_USER_RE = re.compile(r"^[A-Za-z0-9_.\-@$]{1,64}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,128}$")


@dataclass(frozen=True)
class ValidatedAction:
    action: str; target: str | None; params: dict; policy: ActionPolicy


class Guardrails:
    def __init__(self, settings: Settings | None = None): self.settings = settings or Settings()

    # ---------- input validation
    def validate_event(self, e) -> None:
        if e.event_type not in KNOWN_EVENT_TYPES:
            raise PolicyViolation("invalid_event", f"unknown event type {e.event_type!r}", 422)
        for f in ("user", "host"):
            v = getattr(e, f, None)
            if not isinstance(v, str) or not v or len(v) > 128 or any(ord(c) < 32 for c in v):
                raise PolicyViolation("invalid_event", f"event field {f!r} is missing or malformed", 422)
        for f in ("src_ip", "dst_ip"):
            v = getattr(e, f, None)
            if v in (None, "", "n/a"): continue
            try: ipaddress.ip_address(v)
            except ValueError: raise PolicyViolation("invalid_event", f"event field {f!r} is not a valid IP address", 422)
        if len(json.dumps(e.meta or {}, default=str)) > 10_000:
            raise PolicyViolation("invalid_event", "event metadata too large", 422)

    # ---------- agent/tool/iteration limits
    def check_tool_allowed(self, agent: str, tool: str) -> None:
        if tool not in TOOL_PERMISSIONS.get(agent, frozenset()):
            raise PolicyViolation("tool_not_permitted", f"{agent} is not permitted to call tool {tool!r}", 403)

    def check_iteration(self, iteration: int) -> None:
        if iteration > self.settings.effective_max_iterations:
            raise PolicyViolation("max_iterations", f"investigation iteration {iteration} exceeds the limit of {self.settings.effective_max_iterations}", 403)

    # ---------- response policy
    def required_level(self, action: str, risk_level: str | None = None) -> str:
        pol = ACTION_POLICIES.get(action)
        if pol is None: raise PolicyViolation("action_not_allowed", f"action {action!r} is not in the allowed-action policy", 403)
        if action == "close_incident" and risk_rank(risk_level) >= 2: return "admin"   # closing a high/critical incident needs an admin
        return pol.approval_level

    def normalize_role(self, role: str | None) -> str:
        r = (role or "analyst").strip().lower()
        if r not in ROLE_RANK: raise PolicyViolation("unknown_role", f"unknown role {role!r}", 403)
        return r

    def authorize(self, role: str | None, action: str, risk_level: str | None = None) -> str:
        r = self.normalize_role(role); need = self.required_level(action, risk_level)
        if ROLE_RANK[r] < ROLE_RANK[need]:
            raise PolicyViolation("insufficient_role", f"role '{r}' may not approve '{action}' (requires '{need}')", 403)
        return need

    def authorize_reject(self, role: str | None) -> str:
        r = self.normalize_role(role)
        if ROLE_RANK[r] < ROLE_RANK["analyst"]: raise PolicyViolation("insufficient_role", f"role '{r}' may not reject responses", 403)
        return r

    def validate_action(self, action: str, target: str | None = None, params: dict | None = None) -> ValidatedAction:
        pol = ACTION_POLICIES.get(action)
        if pol is None: raise PolicyViolation("action_not_allowed", f"action {action!r} is not in the allowed-action policy", 403)
        params = params or {}
        if not isinstance(params, dict) or len(json.dumps(params, default=str)) > 2000:
            raise PolicyViolation("invalid_params", "params must be a small JSON object", 422)
        kind, t = pol.target_kind, (target.strip() if isinstance(target, str) else target)
        if kind == "ip":
            try: ip = ipaddress.ip_address(t or "")
            except ValueError: raise PolicyViolation("invalid_target", f"{t!r} is not a valid IP address", 422)
            if not ip.is_global: raise PolicyViolation("protected_target", f"refusing to block non-public address {ip}", 403)
            t = str(ip)
        elif kind in ("account", "session"):
            if not t or not _USER_RE.match(t) or t == "n/a": raise PolicyViolation("invalid_target", f"{t!r} is not a valid account name", 422)
            if t.lower() in self.settings.protected_accounts: raise PolicyViolation("protected_target", f"account '{t}' is protected by policy", 403)
        elif kind == "host":
            if not t or not _HOST_RE.match(t): raise PolicyViolation("invalid_target", f"{t!r} is not a valid host name", 422)
            if t.lower() in self.settings.protected_hosts: raise PolicyViolation("protected_target", f"host '{t}' is protected by policy", 403)
        elif kind == "entity":
            if not t or not (_USER_RE.match(t) or _HOST_RE.match(t)) or t == "n/a": raise PolicyViolation("invalid_target", f"{t!r} is not a valid user or host", 422)
        else:  # incident-scoped
            if not t or len(str(t)) > 64: raise PolicyViolation("invalid_target", "an incident id target is required", 422)
        return ValidatedAction(action, t, params, pol)

    def policy_snapshot(self) -> dict:
        s = self.settings
        return {"actions": [dict(name=p.name, description=p.description, target_kind=p.target_kind, destructive=p.destructive,
                                 approval_level=p.approval_level, min_risk=p.min_risk) for p in _POLICIES],
                "roles": list(ROLE_RANK), "tool_permissions": {k: sorted(v) for k, v in TOOL_PERMISSIONS.items()},
                "limits": {"max_iterations": s.effective_max_iterations, "max_tool_calls": s.max_tool_calls, "confidence_threshold": s.confidence_threshold,
                           "min_independent_signals": s.min_independent_signals},
                "protected_accounts": sorted(s.protected_accounts), "protected_hosts": sorted(s.protected_hosts)}
