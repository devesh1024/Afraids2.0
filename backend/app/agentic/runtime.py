"""Wiring: builds settings, guardrails, tools, reasoner, supervisor and decision service. `default` is the app-wide runtime."""
from __future__ import annotations
from dataclasses import dataclass
from .agents import AgentDeps
from .approvals import ResponseDecisionService
from .config import Settings
from .events import EventPublisher
from .executor import SimulationResponseExecutor
from .guardrails import Guardrails
from .reasoning import DeterministicReasoner
from .states import StateMachine
from .supervisor import SupervisorAgent
from .tools import ToolRegistry, ToolServices, build_default_registry
from .verification import Verifier


@dataclass
class Runtime:
    settings: Settings; guard: Guardrails; registry: ToolRegistry; publisher: EventPublisher; reasoner: object
    supervisor: SupervisorAgent; decisions: ResponseDecisionService; executor: SimulationResponseExecutor; machine: StateMachine


def build_runtime(settings: Settings | None = None, publisher: EventPublisher | None = None, registry: ToolRegistry | None = None, reasoner=None, services: ToolServices | None = None) -> Runtime:
    s = settings or Settings.from_env(); guard = Guardrails(s); pub = publisher or EventPublisher(); reg = registry or build_default_registry()
    rs = reasoner or DeterministicReasoner(s, guard); deps = AgentDeps(s, guard, reg, rs, pub, services or ToolServices()); machine = StateMachine(pub); ex = SimulationResponseExecutor()
    return Runtime(s, guard, reg, pub, rs, SupervisorAgent(deps, machine, Verifier(s)), ResponseDecisionService(guard, ex, machine, pub), ex, machine)


default = build_runtime()
LOOP = None   # the running asyncio loop; set by main.py so worker threads can stream over the WebSocket
