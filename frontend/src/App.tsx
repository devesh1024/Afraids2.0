import { useState } from "react";
import { PieChart, Pie, Cell, Tooltip } from "recharts";
import { api, identity, useApi, useLive, WsMsg } from "./api";
import { Card, Badge, Stat, Table, COLORS } from "./ui";
import { Investigation, Graph } from "./Investigation";
import { AgentActivity } from "./AgentActivity";
import { Replay } from "./Replay";
import { ResponseCenter } from "./Responses";
import { FeedMsg } from "./agentView";

type Inc = { id: string; title: string; risk_score: number; risk_level: string; status: string; techniques: { id: string; name: string }[]; updated_at: string };
type Ev = { id: string; timestamp: string; event_type: string; user: string; host: string; src_ip: string; dst_ip: string; severity: string };
type Rec = { id: string; incident_title: string; action: string; rationale: string; status: string };
type Exe = { id: string; agent: string; status: string; confidence: number | null; started_at: string; output: any; evidence: string[] };
type Sims = { available: string[]; runs: { id: string; scenario: string; status: string; events: number }[] };
const NAV = ["Dashboard", "Incidents", "Investigation", "Agent Activity", "Investigation Replay", "Threat Intelligence", "Attack Graph", "Response Center", "Attack Simulator"];

export default function App() {
  const [page, setPage] = useState("Dashboard"); const [sel, setSel] = useState<string>(""); const [tick, setTick] = useState(0);
  const [stream, setStream] = useState<Ev[]>([]); const [feed, setFeed] = useState<FeedMsg[]>([]); const [role, setRole] = useState(identity.role);
  const up = useLive((m: WsMsg) => { if (m.type === "event") setStream(s => [m.data, ...s].slice(0, 50)); if (["agent_update", "incident_state", "incident_assessed", "response_decision"].includes(m.type)) setFeed(f => [m, ...f].slice(0, 100)); setTick(t => t + 1); });
  const open = (id: string) => { setSel(id); setPage("Investigation"); };
  const P = { tick, sel, setSel, open, stream };
  return <div className="flex min-h-screen">
    <nav className="w-56 shrink-0 border-r border-slate-800 bg-slate-900 p-4">
      <div className="mb-6 text-lg font-bold text-cyan-400">AFRAIDS <span className="text-xs text-slate-500">SOC</span></div>
      {NAV.map(n => <button key={n} onClick={() => setPage(n)} className={`mb-1 block w-full rounded px-3 py-2 text-left text-sm ${page === n ? "bg-cyan-900 text-white" : "text-slate-400 hover:bg-slate-800"}`}>{n}</button>)}
      <div className="mt-6 text-xs text-slate-400">Role (simulated auth)<select className="mt-1 block w-full rounded bg-slate-800 p-1" value={role} onChange={e => { identity.role = e.target.value; setRole(e.target.value); }}>{["viewer", "analyst", "senior_analyst", "admin"].map(r => <option key={r}>{r}</option>)}</select></div>
      <div className="mt-4 text-xs">WebSocket: <span className={up ? "text-green-400" : "text-red-400"}>{up ? "live" : "disconnected"}</span></div>
    </nav>
    <main className="flex-1 space-y-4 p-6"><h1 className="text-xl font-semibold text-white">{page}</h1>
      {page === "Dashboard" && <Dashboard {...P} up={up} />}{page === "Incidents" && <Incidents {...P} />}
      {page === "Investigation" && <Investigation {...P} />}{page === "Agent Activity" && <AgentActivity tick={tick} sel={sel} setSel={setSel} feed={feed} />}{page === "Investigation Replay" && <Replay tick={tick} sel={sel} setSel={setSel} />}
      {page === "Threat Intelligence" && <Intel {...P} />}{page === "Attack Graph" && <Graph {...P} />}
      {page === "Response Center" && <ResponseCenter tick={tick} />}{page === "Attack Simulator" && <Simulator {...P} />}
    </main></div>;
}
type PP = { tick: number; sel: string; setSel: (s: string) => void; open: (s: string) => void; stream: Ev[] };

function Dashboard({ tick, open, stream, up }: PP & { up: boolean }) {
  const s = useApi<any>("/api/stats", { events: 0, alerts: 0, incidents: 0, risk_distribution: {} }, tick);
  const inc = useApi<Inc[]>("/api/incidents", [], tick); const d = s.risk_distribution || {};
  const pie = Object.entries(d).map(([k, v]) => ({ name: k, value: v as number })).filter(x => x.value > 0);
  return <>
    <div className="grid grid-cols-5 gap-4"><Stat label="Total events" value={s.events} /><Stat label="Active alerts" value={s.alerts} />
      <Stat label="Critical incidents" value={d.critical || 0} /><Stat label="High-risk incidents" value={d.high || 0} /><Stat label="System health" value={up ? "Healthy" : "Degraded"} /></div>
    <div className="grid grid-cols-3 gap-4">
      <Card title="Risk distribution">{pie.length ? <PieChart width={260} height={200}><Pie data={pie} dataKey="value" nameKey="name" outerRadius={80} label>{pie.map(p => <Cell key={p.name} fill={COLORS[p.name]} />)}</Pie><Tooltip /></PieChart> : <p className="text-slate-500">No incidents yet. Run a simulation.</p>}</Card>
      <Card title="Recent incidents"><Table head={["Incident", "Risk"]} rows={inc.slice(0, 6).map(i => [<a className="cursor-pointer text-cyan-400" onClick={() => open(i.id)}>{i.title}</a>, <Badge level={i.risk_level} />])} /></Card>
      <Card title="Live event stream"><div className="h-52 overflow-auto font-mono text-xs">{stream.map(e => <div key={e.id}><Badge level={e.severity} /> {e.event_type} {e.host} {e.src_ip}</div>)}{!stream.length && <p className="text-slate-500">Waiting for events…</p>}</div></Card></div></>;
}
function Incidents({ tick, open }: PP) {
  const inc = useApi<Inc[]>("/api/incidents", [], tick);
  return <Card><Table head={["Title", "Risk", "Score", "Techniques", "Status"]} rows={inc.map(i => [<a className="cursor-pointer text-cyan-400" onClick={() => open(i.id)}>{i.title}</a>, <Badge level={i.risk_level} />, i.risk_score, i.techniques.map(t => t.id).join(", "), i.status])} /></Card>;
}
function Intel({ tick }: PP) {
  const x = useApi<Exe[]>("/api/agents/executions", [], tick);
  const hits = new Map<string, string>(); x.filter(e => e.agent === "ThreatIntelligenceAgent").forEach(e => Object.entries(e.output?.matches || {}).forEach(([k, v]) => hits.set(k, (v as any).category + " · reputation " + (v as any).reputation + " · " + (v as any).source)));
  return <Card title="Matched indicators of compromise (offline feed)"><Table head={["IOC (IP)", "Intel"]} rows={[...hits].map(([k, v]) => [k, v])} />{!hits.size && <p className="text-slate-500">No matches yet.</p>}</Card>;
}
function Simulator({ tick }: PP) {
  const s = useApi<Sims>("/api/simulations", { available: [], runs: [] }, tick);
  return <><Card title="Launch synthetic scenario (sandboxed, no real attacks)"><div className="flex flex-wrap gap-2">{s.available.map(a =>
    <button key={a} className="rounded bg-cyan-700 px-3 py-2 text-sm hover:bg-cyan-600" onClick={() => api("/api/simulations/start", "POST", { scenario: a })}>{a.replace("_", " ")}</button>)}</div></Card>
    <Card title="Runs"><Table head={["Scenario", "Status", "Events"]} rows={s.runs.slice().reverse().map(r => [r.scenario, r.status, r.events])} /></Card></>;
}
