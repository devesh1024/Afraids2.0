import { useState } from "react";
import { useApi } from "./api";
import { Card, Badge, Table } from "./ui";
import { PIPELINE, AgentStatus, Exec, FeedMsg, InvView, STATE_CLASS, STATUS_CLASS, agentLabel, agentStatuses, feedLine, fmtDuration } from "./agentView";

type Statuses = ReturnType<typeof agentStatuses>;

export const StatusBadge = ({ status }: { status: AgentStatus }) =>
  <span className={`rounded px-2 py-0.5 text-xs font-bold ${STATUS_CLASS[status]}`}>{status}</span>;

/** The 8-agent pipeline strip. Presentational only (tested without network). */
export function PipelineStrip({ statuses, selected, onSelect }: { statuses: Statuses; selected: string; onSelect: (a: string) => void }) {
  return <div className="grid grid-cols-4 gap-3">{PIPELINE.map(a => {
    const s = statuses[a]; const e = s.exec;
    return <button key={a} data-testid={`agent-${a}`} onClick={() => onSelect(a)}
      className={`rounded-lg border p-3 text-left ${selected === a ? "border-cyan-400 bg-slate-800" : "border-slate-800 bg-slate-900 hover:bg-slate-800"}`}>
      <div className="mb-1 flex items-center justify-between"><span className="text-sm font-semibold text-white">{agentLabel(a)}</span><StatusBadge status={s.status} /></div>
      <div className="text-xs text-slate-400">{e ? <>
        <div>duration {fmtDuration(e.duration_ms)}{s.count > 1 ? ` · ran ${s.count}×` : ""}</div>
        <div>tools {e.tools_used?.length ?? 0} · findings {e.findings?.length ?? 0} · confidence {e.confidence ?? "–"}</div>
        <div className="truncate" title={e.output_summary || ""}>{e.output_summary || ""}</div></> : <div>waiting for upstream agents…</div>}</div>
    </button>;
  })}</div>;
}

export function AgentDetail({ exec }: { exec?: Exec }) {
  if (!exec) return <p className="text-slate-500">This agent has not run yet in the selected investigation.</p>;
  return <div className="space-y-3 text-sm">
    <div className="grid grid-cols-2 gap-4"><div><div className="text-xs uppercase text-slate-500">Input</div>{exec.input_summary || "–"}</div>
      <div><div className="text-xs uppercase text-slate-500">Output</div>{exec.output_summary || "–"}</div></div>
    {exec.error && <div className="rounded bg-red-950 p-2 text-red-300">Error: {exec.error}</div>}
    <div><div className="mb-1 text-xs uppercase text-slate-500">Tools called ({exec.tools_used?.length ?? 0})</div>
      {exec.tools_used?.length ? <Table head={["Tool", "OK", "Time", "Result"]} rows={exec.tools_used.map(t => [t.tool, t.ok ? "✓" : "✗", fmtDuration(t.duration_ms), t.summary || t.error || ""])} /> : <p className="text-slate-500">none</p>}</div>
    <div><div className="mb-1 text-xs uppercase text-slate-500">Findings ({exec.findings?.length ?? 0})</div>
      {exec.findings?.map((f, i) => <div key={i} className="mb-1"><Badge level={f.severity} /> {f.description} <span className="text-xs text-slate-400">· {f.source} · confidence {f.confidence}{f.contradicts ? " · CONTRADICTS" : ""}</span></div>)}
      {!exec.findings?.length && <p className="text-slate-500">none</p>}</div>
    <div><div className="mb-1 text-xs uppercase text-slate-500">Evidence</div>
      <ul className="list-disc pl-5 text-xs">{(exec.evidence || []).map((x, i) => <li key={i}>{x}</li>)}</ul>
      <div className="mt-1 break-all font-mono text-xs text-slate-500">{(exec.evidence_ids || []).slice(0, 12).join("  ")}</div></div>
  </div>;
}

export function AgentActivity({ tick, sel, setSel, feed }: { tick: number; sel: string; setSel: (s: string) => void; feed: FeedMsg[] }) {
  const incs = useApi<{ id: string; title: string; state?: string }[]>("/api/incidents", [], tick);
  const id = sel || incs[0]?.id || "";
  const raw = useApi<InvView | null>(id ? `/api/incidents/${id}/investigation` : "/api/health", null, tick);
  const view = raw && (raw as InvView).runs ? (raw as InvView) : null;
  const [runSel, setRunSel] = useState(""); const [agent, setAgent] = useState<string>("InvestigationAgent");
  const runs = view?.runs ?? []; const run = runs.find(r => r.run_id === runSel) || runs[runs.length - 1];
  const statuses = agentStatuses(run?.executions ?? []); const inc = view?.incident;
  const lines = feed.filter(m => !id || !m.data?.incident_id || m.data.incident_id === id).slice(0, 14);
  return <>
    <div className="flex flex-wrap items-center gap-3">
      <select className="rounded bg-slate-800 p-2 text-sm" value={id} onChange={e => { setSel(e.target.value); setRunSel(""); }}>{incs.map(i => <option key={i.id} value={i.id}>{i.title}</option>)}</select>
      {runs.length > 1 && <select className="rounded bg-slate-800 p-2 text-sm" value={run?.run_id || ""} onChange={e => setRunSel(e.target.value)}>{runs.map((r, i) => <option key={r.run_id} value={r.run_id}>Run {i + 1} · {r.status}</option>)}</select>}
      {inc && <><span className={`rounded px-2 py-1 text-xs font-bold text-white ${STATE_CLASS[inc.state || ""] || "bg-cyan-800"}`}>{inc.state || "–"}</span>
        <Badge level={inc.risk_level} /> <span className="text-sm text-slate-300">risk {inc.risk_score} · confidence {inc.confidence ?? "–"}</span>
        {inc.needs_review ? <span className="rounded bg-yellow-600 px-2 py-1 text-xs font-bold text-black">NEEDS_REVIEW</span> : null}</>}
    </div>
    {!view && <Card><p className="text-slate-500">No investigation yet. Start a scenario in Attack Simulator — the agents will appear here live.</p></Card>}
    {view && <>
      {inc?.assessment?.summary && <Card title="Final assessment"><div className="text-sm">{inc.assessment.summary}</div>
        <div className="mt-1 text-xs text-slate-400">stop reason: {inc.assessment.stop_reason} · iterations: {inc.assessment.iterations} · failed checks: {(inc.assessment.verification?.checks || []).filter((c: any) => !c.passed).map((c: any) => c.name).join(", ") || "none"}</div></Card>}
      <PipelineStrip statuses={statuses} selected={agent} onSelect={setAgent} />
      <div className="grid grid-cols-3 gap-4">
        <div className="col-span-2"><Card title={`${agentLabel(agent)} — detail`}><AgentDetail exec={statuses[agent]?.exec} /></Card></div>
        <Card title="Live agent stream"><div className="h-72 overflow-auto font-mono text-xs">{lines.map((m, i) => <div key={i} className="mb-0.5">{feedLine(m)}</div>)}{!lines.length && <p className="text-slate-500">Waiting for activity…</p>}</div></Card>
      </div></>}
  </>;
}
