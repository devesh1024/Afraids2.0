// Pure helpers/types for the Phase 3 agent UI (unit-tested in agent.test.tsx). UNVERIFIED: written without running the build.
export const PIPELINE = ["SupervisorAgent", "DetectionAgent", "LogAnalysisAgent", "ThreatIntelligenceAgent", "InvestigationAgent", "AttackGraphAgent", "RiskAssessmentAgent", "ResponseAgent"] as const;
export type AgentStatus = "WAITING" | "RUNNING" | "COMPLETED" | "FAILED";

export interface ToolUsed { tool: string; ok: boolean; duration_ms: number; summary: string; error?: string | null }
export interface Finding { id?: string; description: string; severity: string; confidence: number; source: string; contradicts?: number | boolean; evidence: string[] }
export interface Exec {
  id: string; agent: string; status: string; confidence: number | null; started_at: string | null; finished_at: string | null; duration_ms: number | null;
  run_id: string | null; sequence: number | null; iteration: number | null; input_summary: string | null; output_summary: string | null;
  tools_used: ToolUsed[]; evidence: string[]; evidence_ids: string[]; findings: Finding[]; error: string | null;
}
export interface Run { run_id: string; started_at: string | null; finished_at: string | null; status: string; iterations: number; executions: Exec[]; transitions: { from_state: string; to_state: string; reason: string; timestamp: string }[] }
export interface InvView {
  incident: { id: string; title: string; state: string | null; status: string; risk_score: number; risk_level: string; confidence: number | null; needs_review: number | null; verdict: string | null; assessment: any; iterations: number | null };
  pipeline: string[]; runs: Run[]; responses: any[]; timeline: { timestamp: string; kind: string; message: string }[];
}
export type FeedMsg = { type: string; data: any };
export interface ReplayStep {
  index: number; ts: string | null; kind: "state" | "agent" | "decision"; run_id: string | null; title: string; detail: string; agent?: string; status?: string; duration_ms?: number | null;
  confidence?: number | null; input_summary?: string | null; output_summary?: string | null; tools?: ToolUsed[]; findings?: Finding[]; evidence_ids?: string[]; error?: string | null;
}

export function normStatus(s?: string | null): AgentStatus {
  const u = (s || "").toUpperCase();
  if (u === "COMPLETED" || u === "SUCCESS") return "COMPLETED";
  if (u === "FAILED" || u === "ERROR") return "FAILED";
  if (u === "RUNNING") return "RUNNING";
  return "WAITING";
}

/** Latest execution per pipeline agent (highest sequence wins); agents with no execution in the run are WAITING. */
export function agentStatuses(execs: Exec[]): Record<string, { status: AgentStatus; exec?: Exec; count: number }> {
  const out: Record<string, { status: AgentStatus; exec?: Exec; count: number }> = {};
  for (const a of PIPELINE) {
    const mine = execs.filter(e => e.agent === a);
    const last = mine.reduce<Exec | undefined>((best, e) => (!best || (e.sequence ?? 0) >= (best.sequence ?? 0) ? e : best), undefined);
    out[a] = { status: last ? normStatus(last.status) : "WAITING", exec: last, count: mine.length };
  }
  return out;
}

export const fmtDuration = (ms: number | null | undefined): string => ms == null ? "–" : ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(1)} s`;
export const agentLabel = (name: string): string => name.replace(/([a-z])([A-Z])/g, "$1 $2");
export const feedLine = (m: FeedMsg): string => m.type === "agent_update" ? `${agentLabel(m.data.agent)} → ${m.data.status}` : m.type === "incident_state" ? `Incident ${m.data.from} → ${m.data.to}` : m.type === "incident_assessed" ? `Assessment ready: risk ${m.data.risk_score} (${m.data.risk_level}), verdict ${m.data.verdict}` : m.type === "response_decision" ? `Response ${m.data.action} ${m.data.status} by ${m.data.actor}` : m.type;
export const replayWindow = (steps: ReplayStep[], pos: number): ReplayStep[] => steps.slice(0, Math.max(0, Math.min(pos, steps.length - 1)) + 1);

export const STATUS_CLASS: Record<AgentStatus, string> = {
  WAITING: "bg-slate-700 text-slate-300", RUNNING: "bg-cyan-600 text-white animate-pulse", COMPLETED: "bg-green-700 text-white", FAILED: "bg-red-700 text-white",
};
export const STATE_CLASS: Record<string, string> = {
  AWAITING_HUMAN_APPROVAL: "bg-yellow-600", CONTAINED: "bg-green-700", RESOLVED: "bg-slate-600", FAILED: "bg-red-700",
};
