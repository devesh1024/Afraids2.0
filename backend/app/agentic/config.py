"""Phase 3 configuration: bounded loops, tool budgets, thresholds. Env-driven; hard ceilings cannot be raised by config."""
from __future__ import annotations
import os
from dataclasses import dataclass

HARD_MAX_ITERATIONS = 10     # no configuration can raise the investigation loop above this
HARD_MAX_TOOL_CALLS = 500


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try: v = int(os.getenv(name, str(default)))
    except ValueError: v = default
    return max(lo, min(hi, v))


def _env_float(name: str, default: float, lo: float, hi: float) -> float:
    try: v = float(os.getenv(name, str(default)))
    except ValueError: v = default
    return max(lo, min(hi, v))


@dataclass(frozen=True)
class Settings:
    max_iterations: int = 3                 # AGENT_MAX_ITERATIONS
    max_tool_calls: int = 80                # AGENT_MAX_TOOL_CALLS (per investigation run)
    reserved_tool_calls: int = 10           # kept back so Graph/Risk/Response agents can always run
    max_tool_calls_per_agent: int = 30      # per single agent execution
    confidence_threshold: float = 0.6       # AGENT_CONFIDENCE_THRESHOLD
    min_independent_signals: int = 2
    min_correlated_events: int = 2
    strong_single_alert_confidence: float = 0.85
    iteration_windows: tuple = (30, 180, 1440)   # minutes of history per investigation iteration (widening)
    step_delay_ms: int = 0                  # AGENT_STEP_DELAY_MS: pause after an agent starts (visible RUNNING in the UI demo)
    max_targets_per_action: int = 3
    max_ti_lookups: int = 6
    protected_accounts: frozenset = frozenset({"root", "administrator", "admin", "system", "krbtgt"})
    protected_hosts: frozenset = frozenset({"dc-01", "dc-02", "domain-controller", "backup-01"})

    @property
    def effective_max_iterations(self) -> int:
        return min(max(1, self.max_iterations), HARD_MAX_ITERATIONS)

    def window_for(self, iteration: int) -> int:
        i = min(max(iteration, 1) - 1, len(self.iteration_windows) - 1)
        return self.iteration_windows[i]

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(max_iterations=_env_int("AGENT_MAX_ITERATIONS", 3, 1, HARD_MAX_ITERATIONS),
                   max_tool_calls=_env_int("AGENT_MAX_TOOL_CALLS", 80, 15, HARD_MAX_TOOL_CALLS),
                   confidence_threshold=_env_float("AGENT_CONFIDENCE_THRESHOLD", 0.6, 0.0, 1.0),
                   step_delay_ms=_env_int("AGENT_STEP_DELAY_MS", 0, 0, 5000))
