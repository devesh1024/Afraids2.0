# AFRAIDS v1 (backend core)
Run: `cd backend && pip install -r requirements.txt && uvicorn app.main:app --reload` → docs at http://localhost:8000/docs
Start a simulation: `curl -X POST localhost:8000/api/simulations/start -H 'content-type: application/json' -d '{"scenario":"brute_force"}'`
Scenarios: brute_force, port_scan, privilege_escalation, exfiltration, insider_threat. WebSocket: ws://localhost:8000/ws

## Frontend
`cd frontend && npm install && npm run dev` → http://localhost:5173 (set `VITE_API_URL` if the API isn't on :8000).
Or everything at once: `docker compose up --build`.

## Phase 2: intelligence layer
- **Hybrid detection** (`rules.py`): score = min(100, unique rule points + anomaly bonus (≤15, only if rules fired) + threat-intel bonus (rep×0.15, ≤15) + chain bonus (+5 per extra technique, ≤15)). ML-only alerts (ML001) are capped at 35. Every contribution is returned as a labelled risk factor; weights live in `RULES` / `SCORING`.
- **ML** (`ml.py`): Isolation Forest on 9 behavioural features, trained on *synthetic* baselines; saved to `backend/models/` and auto-loaded. Heuristic only. `is_anomaly` also needs a feature ≥3σ above baseline. Off-hours runs can raise the login-hour feature.
- **ATT&CK** (`intel.py`): curated 15-technique subset (extend with `load_stix(path)`); best-effort mappings are flagged `uncertain`.
- **Threat intel**: offline synthetic feed; `PublicApiAdapter` is an interface stub only.
- **APIs**: `/api/incidents/{id}/graph`, `/chain`, `/api/ml/{status,train,predict}`, `/api/ti/{ip|domain|hash}/{value}`, `/api/attack/techniques`.
- **Tests**: `cd backend && python -m pytest -q` (11 tests). Delete `afraids.db` when upgrading from v1 (schema changed; no migrations yet).

## Final v1/v2 notes
- **Migrations**: Alembic (`backend/alembic`); `init_db()` runs `upgrade head` on startup and stamps pre-migration DBs. New migration: `cd backend && alembic revision --autogenerate -m "msg"`.
- **ATT&CK**: `backend/data/attack_techniques.json` (697 techniques) was built from MITRE's enterprise-attack STIX bundle (© MITRE, used under the ATT&CK terms of use); curated entries override detection guidance for mapped techniques.
- **Graph**: React Flow. **Tests**: `cd backend && python -m pytest -q` (12) and `cd frontend && npm test` (3).
- **Known limits**: a lone medium-weight rule (e.g. one privilege escalation, 25 pts) scores "low" by design; tune `RULES`/`SCORING`. Docker Compose files are written but were not run in the build sandbox. Copy `.env.example` to `.env`.

## Phase 3: autonomous multi-agent investigation (UNVERIFIED — written without being run)
Supervisor → Detection → LogAnalysis → ThreatIntelligence → Investigation (bounded loop) → AttackGraph → RiskAssessment → Response, with an explicit
state machine, tool registry, guardrails, deterministic self-reflection (`NEEDS_REVIEW`), human approval API and a simulation-only executor.
No LLM yet; the reasoning layer is behind `agentic/reasoning.py` so Gemini can replace it. Full documentation: [`docs/PHASE3.md`](docs/PHASE3.md).
Configure with `AGENT_*` variables in `.env.example`; `AGENT_MODE=legacy` runs the Phase 1/2 pipeline. Run `cd backend && pytest` and
`cd frontend && npm run build && npm test`.
