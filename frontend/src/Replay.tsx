import { useEffect, useState } from "react";
import { useApi } from "./api";
import { Card, Badge, Table } from "./ui";
import { ReplayStep, agentLabel, fmtDuration, normStatus, replayWindow } from "./agentView";
import { StatusBadge } from "./AgentActivity";

const KIND_STYLE: Record<string, string> = { state: "border-purple-500", agent: "border-cyan-500", decision: "border-yellow-500" };

export function StepCard({ s }: { s: ReplayStep }) {
  return <div className={`mb-2 rounded border-l-4 bg-slate-900 p-3 text-sm ${KIND_STYLE[s.kind] || "border-slate-600"}`}>
    <div className="flex items-center justify-between"><b>{s.kind === "agent" ? agentLabel(s.agent || "") : s.title}</b>
      <span className="text-xs text-slate-500">#{s.index + 1} · {s.ts ? new Date(s.ts + "Z").toLocaleTimeString() : ""}</span></div>
    {s.kind === "agent" && <div className="mt-1 space-y-1">
      <div className="flex items-center gap-2"><StatusBadge status={normStatus(s.status)} /><span className="text-xs text-slate-400">{fmtDuration(s.duration_ms)} · confidence {s.confidence ?? "–"}</span></div>
      <div className="text-slate-300">{s.output_summary || s.detail}</div>
      {s.error && <div className="text-red-400">{s.error}</div>}
      {!!s.tools?.length && <div className="text-xs text-slate-400">tools: {s.tools.map(t => `${t.tool}${t.ok ? "" : " ✗"}`).join(", ")}</div>}
      {s.findings?.map((f, i) => <div key={i} className="text-xs"><Badge level={f.severity} /> {f.description}</div>)}</div>}
    {s.kind !== "agent" && s.detail && <div className="text-xs text-slate-400">{s.detail}</div>}
  </div>;
}

export function Replay({ tick, sel, setSel }: { tick: number; sel: string; setSel: (s: string) => void }) {
  const incs = useApi<{ id: string; title: string }[]>("/api/incidents", [], tick); const id = sel || incs[0]?.id || "";
  const [run, setRun] = useState(""); const rp = id ? `/api/incidents/${id}/replay${run ? `?run_id=${run}` : ""}` : "/api/health";
  const data = useApi<{ steps: ReplayStep[] } | null>(rp, null, tick); const steps = data?.steps ?? [];
  const inv = useApi<any>(id ? `/api/incidents/${id}/investigation` : "/api/health", null, tick); const runs: any[] = inv?.runs ?? [];
  const [pos, setPos] = useState(0); const [play, setPlay] = useState(false);
  useEffect(() => { setPos(steps.length ? steps.length - 1 : 0); }, [id, run, steps.length]);
  useEffect(() => {
    if (!play) return; const t = setInterval(() => setPos(p => { if (p >= steps.length - 1) { setPlay(false); return p; } return p + 1; }), 700);
    return () => clearInterval(t);
  }, [play, steps.length]);
  const shown = replayWindow(steps, pos); const states = shown.filter(s => s.kind === "state");
  return <>
    <div className="flex flex-wrap items-center gap-3">
      <select className="rounded bg-slate-800 p-2 text-sm" value={id} onChange={e => { setSel(e.target.value); setRun(""); }}>{incs.map(i => <option key={i.id} value={i.id}>{i.title}</option>)}</select>
      <select className="rounded bg-slate-800 p-2 text-sm" value={run} onChange={e => setRun(e.target.value)}><option value="">All runs</option>{runs.map((r, i) => <option key={r.run_id} value={r.run_id}>Run {i + 1}</option>)}</select>
      <button className="rounded bg-cyan-700 px-3 py-1 text-sm" onClick={() => { setPos(0); setPlay(true); }}>▶ Replay</button>
      <button className="rounded bg-slate-700 px-3 py-1 text-sm" onClick={() => setPlay(false)}>Pause</button>
      <input type="range" min={0} max={Math.max(0, steps.length - 1)} value={pos} onChange={e => { setPlay(false); setPos(Number(e.target.value)); }} className="w-64" />
      <span className="text-xs text-slate-400">step {steps.length ? pos + 1 : 0} / {steps.length}</span>
    </div>
    <Card title="State progression"><div className="flex flex-wrap gap-1 text-xs">{states.map(s => <span key={s.index} className="rounded bg-purple-900 px-2 py-0.5">{s.title}</span>)}{!states.length && <span className="text-slate-500">–</span>}</div></Card>
    <Card title="Investigation replay">{shown.length ? [...shown].reverse().map(s => <StepCard key={s.index} s={s} />) : <p className="text-slate-500">No investigation recorded for this incident yet.</p>}</Card>
    {!!shown.length && <Card title="Raw sequence"><Table head={["#", "Kind", "Event"]} rows={shown.map(s => [s.index + 1, s.kind, s.title])} /></Card>}
  </>;
}
