# Phase 3 — Autonomous multi-agent investigation workflow

> **STATUS: UNVERIFIED.** All Phase 3 code, the migration, the tests and these docs were written **without being executed**.
> Run `cd backend && pytest` and `cd frontend && npm run build && npm test` and report failures. Gemini/LLM is **not** implemented.

## Pipeline

```
event → SupervisorAgent
          ├─ DetectionAgent            rules + Isolation Forest        (state DETECTED)
          │   └─ triage: investigate? → create/attach incident
          ├─ LogAnalysisAgent          host/user log context           (TRIAGING)
          ├─ ThreatIntelligenceAgent   IP/domain/hash reputation       (THREAT_INTEL_LOOKUP)
          ├─ InvestigationAgent  ⇄  correlation check                  (INVESTIGATING ⇄ CORRELATING)   ← bounded loop
          ├─ AttackGraphAgent          graph + attack chain            (ATTACK_RECONSTRUCTION)
          ├─ RiskAssessmentAgent       explainable 0–100 score         (RISK_ASSESSMENT)
          ├─ verification (self-reflection, no LLM)
          └─ ResponseAgent             PLANS responses only            (RESPONSE_PLANNING)
                → AWAITING_HUMAN_APPROVAL → (approve → simulated executor) → CONTAINED → RESOLVED      FAILED on error
```

Code lives in `backend/app/agentic/` (the Phase 1/2 `app/agents.py` is untouched; `AGENT_MODE=legacy` still runs it).

| Module | Responsibility |
|---|---|
| `states.py` | 13 explicit states, allowed-transition table, `StateMachine` (persists `incidents.state` + `incident_state_transitions`) |
| `supervisor.py` | orchestration, bounded loop, applying results, persisting the response plan, failure handling |
| `agents.py` | the 7 worker agents + `AgentExecution` bookkeeping |
| `tools.py` | `ToolRegistry`, 11 tools, `ToolBudget`, per-call recording in `tool_calls` |
| `reasoning.py` | **`Reasoner` interface + `DeterministicReasoner`** (the Gemini seam) |
| `risk.py` / `verification.py` | transparent risk engine / deterministic self-reflection |
| `guardrails.py` | allowed-action policy, validation, authorization, tool permissions, iteration limit |
| `approvals.py` / `executor.py` | approve/reject/modify service / `SimulationResponseExecutor` |
| `queries.py` / `api.py` | investigation + replay read-models / REST routes |

## AgentExecution record
Every agent run stores: incident id, run id, agent, start/end, status (`RUNNING/COMPLETED/FAILED`), input summary, output summary, tools used
(name, ok, duration, result), evidence ids (`event:`, `alert:`, `ioc:`, `technique:`…), confidence, error. Findings (`description, evidence, severity,
confidence, source`) are in `investigation_findings`. `WAITING` is derived in the UI (agent has no execution in the run yet) and streamed as a message.

## Tools (all read-only/computational; each validates input, returns a structured `ToolResult`, never raises, and is recorded)
`search_security_events, get_user_history, get_host_history, lookup_ip_reputation, lookup_domain_reputation, lookup_hash_reputation,
query_attack_technique, build_attack_graph, calculate_risk, get_related_incidents, get_security_baseline`.
Each agent may only call its allow-listed tools (`guardrails.TOOL_PERMISSIONS`; Supervisor: none). `GET /api/tools` lists schemas.

## Risk (explainable)
`score = Σ factor.points` (invariant, tested). Factors (max): severity 25, rule breadth 12, correlated events 15, ML anomaly 12, threat intel 15,
ATT&CK technique severity 15 (tactic-weighted, uncertain mappings halved), sensitive asset 10, privilege escalation 10. Adjustments: ML-only cap 35,
cap 100, and a confidence adjustment (`score × (0.8 + 0.2·confidence)`). Confidence = alert/finding confidence + corroboration bonus (independent
signal families) − contradiction penalty. Levels: ≥85 critical, ≥60 high, ≥30 medium.

## Self-reflection → NEEDS_REVIEW
Checks: sufficient evidence (≥2 correlated events or one strong alert), ≥2 **independent** signal families (rule, ML, threat intel, sequence,
baseline, IP relationship, related incident…), no contradictions (e.g. an "attacker" IP with ≥3 prior legitimate logins), confidence ≥ threshold,
response proportional to risk. If a blocking check fails the incident gets `verdict=needs_review`, `needs_review=1`, destructive actions are
**withheld** (only preserve-evidence / monitoring are proposed) and the UI shows NEEDS_REVIEW. A final check re-verifies the plan: destructive actions
are stripped if verification fails, even if a (future) reasoner proposed them.

## Bounded loops and budgets
`AGENT_MAX_ITERATIONS` (default 3, hard ceiling 10) is enforced by the supervisor's `for` loop independent of the reasoner. The loop also stops on
sufficient evidence, **no new evidence** (window widened 30 → 180 → 1440 min), or tool-budget exhaustion. `AGENT_MAX_TOOL_CALLS` (default 80) caps tool
calls per investigation; 10 are reserved for Graph/Risk/Response agents; 30 per single agent execution.

## Human-in-the-loop
Responses are stored `pending`. API (headers `X-Role`, `X-Actor`; roles `viewer < analyst < senior_analyst < admin` — **simulated identity, not real auth**):

```
POST /api/incidents/{id}/approve-response   {"response_id": "...", "comment": "..."}
POST /api/incidents/{id}/reject-response    {"response_id": "...", "comment": "..."}
POST /api/incidents/{id}/modify-response    {"response_id": "...", "action": "...", "target": "..."}   # stays pending; must then be approved
```
Approval levels: preserve_evidence/increase_monitoring/revoke_session/close_incident → analyst (close of a high/critical incident → admin);
block_ip/disable_account → senior_analyst; isolate_endpoint → admin. Errors: 403 (role/policy), 404, 409 (already decided / investigation running), 422.
Every decision, denial and simulated execution is written to `audit_log` and the incident timeline.

## Simulation only
`SimulationResponseExecutor` writes to `simulated_effects` (blocklist, disabled accounts, …), the timeline and the audit log. Its module imports nothing
capable of touching a real system (enforced by a test). `GET /api/simulation/state` shows the simulated enforcement state.

## Real-time stream
WebSocket `/ws` additionally carries: `agent_update` (WAITING/RUNNING/COMPLETED/FAILED per agent), `run_started`, `incident_state`,
`incident_assessed`, `response_decision`. Investigations run in a worker thread so updates are pushed while the pipeline executes.
Set `AGENT_STEP_DELAY_MS=300` to make RUNNING visible during demos.

## Frontend
* **Agent Activity** – 8-agent pipeline with status, duration, tools, findings, confidence, evidence; live stream; run selector; final assessment.
* **Investigation Replay** – chronological steps (state changes, agent runs, decisions) with play/pause/scrub.
* **Response Center** – approve / reject / modify with role selector (sidebar) and the simulated enforcement state.

## Replacing the deterministic reasoner with Gemini later
Implement `reasoning.Reasoner` (`should_investigate`, `analyze`, `next_step`, `plan_responses`: JSON in → drafts out) and pass it to
`build_runtime(reasoner=...)`. Agents, tools, guardrails, verifier, approvals and UI are unchanged; the model can only *propose* — `validate_action`,
`authorize`, tool permissions, budgets, the hard iteration bound and the post-hoc verification still constrain it.

## New endpoints
`GET /api/incidents/{id}/investigation | replay | timeline | findings`, `GET /api/agents/pipeline`, `/api/tools`, `/api/policy`, `/api/simulation/state`,
and the three POST routes above. `/api/agents/executions` accepts `incident_id` and `run_id`. `/api/responses/{id}/{approve|reject}` is kept and now uses the same guarded path.

## Known limitations
No real authentication (role header is simulated); the intel feed and ATT&CK-based baselines are synthetic; per-event re-investigation means a noisy incident
re-runs the pipeline for each new detection; SQLite + worker threads can briefly lock under heavy concurrent writes (use Postgres for production).
