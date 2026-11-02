import { useApi } from "./api";
import { Card, Badge, Table } from "./ui";
import { ReactFlow, Background, Controls } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { layoutGraph, NC } from "./graphLayout";
type P = { tick: number; sel: string; setSel: (s: string) => void };
export function GraphView({ graph }: { graph: { nodes: any[]; edges: any[] } | null }) {
  if (!graph?.nodes?.length) return <p className="text-slate-500">No graph.</p>;
  const { nodes, edges, cols } = layoutGraph(graph);
  return <div><div style={{ height: Math.max(260, Math.max(...nodes.map(n => n.position.y)) + 140) }} className="rounded border border-slate-800">
    <ReactFlow nodes={nodes} edges={edges} fitView colorMode="dark" nodesDraggable proOptions={{ hideAttribution: true }}><Background /><Controls showInteractive={false} /></ReactFlow></div>
    <div className="mt-1 flex flex-wrap gap-3 text-xs">{cols.map(c => <span key={c}><span style={{ color: NC[c] }}>●</span> {c}</span>)}</div></div>;
}

export function Investigation({ tick, sel, setSel }: P) {
  const inc = useApi<{ id: string; title: string }[]>("/api/incidents", [], tick);
  const d = useApi<any>(sel ? `/api/incidents/${sel}` : "/api/health", null, tick);
  const g = useApi<any>(sel ? `/api/incidents/${sel}/graph` : "/api/health", null, tick);
  const c = useApi<any>(sel ? `/api/incidents/${sel}/chain` : "/api/health", null, tick);
  const ok = sel && d?.alerts; const F: any[] = ok ? d.risk_factors || [] : [];
  return <>
    <select className="rounded bg-slate-800 p-2 text-sm" value={sel} onChange={e => setSel(e.target.value)}><option value="">Select incident…</option>{inc.map(i => <option key={i.id} value={i.id}>{i.title}</option>)}</select>
    {ok && <>
      <div className="grid grid-cols-4 gap-4">
        <Card title="Risk score"><div className="text-3xl font-bold">{d.risk_score}</div><Badge level={d.risk_level} /></Card>
        <Card title="ML anomaly score"><div className="text-3xl font-bold">{d.anomaly_score ? d.anomaly_score.toFixed(3) : "–"}</div><div className="text-xs text-slate-400">Isolation Forest (synthetic baseline; heuristic)</div></Card>
        <Card title="Alerts"><div className="text-3xl font-bold">{d.alerts.length}</div></Card>
        <Card title="Techniques"><div className="text-3xl font-bold">{(d.techniques || []).length}</div></Card></div>
      <div className="grid grid-cols-2 gap-4">
        <Card title="Risk factors (why this score)">{F.map((f, i) => <div key={i} className="mb-2 text-sm"><div className="flex justify-between"><span>{f.label} <span className="text-xs text-slate-500">[{f.kind}]</span></span><b>+{f.points}</b></div>
          <div className="h-1.5 rounded bg-slate-800"><div className="h-1.5 rounded bg-cyan-500" style={{ width: `${Math.min(100, f.points * 4)}%` }} /></div><div className="text-xs text-slate-500">{f.evidence}</div></div>)}</Card>
        <Card title="Attack timeline">{(c?.steps || []).map((s: any) => <div key={s.order} className="mb-1 text-sm">{s.link && <span className={s.link === "causal" ? "text-red-400" : "text-slate-500"}>↳ {s.link} </span>}
          <b>{s.label}{s.count > 1 ? ` ×${s.count}` : ""}</b> <span className="text-xs text-slate-400">{new Date(s.time + "Z").toLocaleTimeString()} · {s.user}@{s.host} · {s.src_ip}→{s.dst_ip}</span></div>)}</Card></div>
      <Card title="Detection rules & evidence"><Table head={["Rule", "Name", "Sev", "ATT&CK", "Pts", "Conf", "Evidence"]} rows={d.alerts.map((a: any) => [a.rule_id, a.rule, <Badge level={a.severity} />,
        a.technique ? <span>{a.technique}{a.uncertain ? <span className="ml-1 text-yellow-400" title="Mapping is best-effort">(uncertain)</span> : ""}</span> : "–", a.points, a.confidence, <ul className="list-disc pl-4 text-xs">{a.evidence.map((x: string, i: number) => <li key={i}>{x}</li>)}</ul>])} /></Card>
      <div className="grid grid-cols-2 gap-4">
        <Card title="MITRE ATT&CK techniques">{(d.techniques || []).map((t: any) => <div key={t.id} className="text-sm"><b className="text-cyan-400">{t.id}</b> {t.name} <span className="text-xs text-slate-400">· {t.tactic}</span>{t.uncertain && <span className="ml-1 text-xs text-yellow-400">uncertain</span>}</div>)}</Card>
        <Card title="Threat intelligence">{F.filter(f => f.kind === "ti").map((f, i) => <div key={i} className="text-sm">{f.evidence} — {f.label} (+{f.points})</div>)}{!F.some(f => f.kind === "ti") && <p className="text-slate-500">No IOC matches.</p>}</Card></div>
      <Card title="Attack graph"><GraphView graph={g} /></Card>
      <Card title="Recommended responses (approval in Response Center)">{d.recommendations.map((r: any) => <div key={r.id} className="text-sm"><b>{r.action}</b> — {r.status}<span className="text-slate-400"> · {r.rationale}</span></div>)}</Card></>}</>;
}

export function Graph({ tick, sel, setSel }: P) {
  const inc = useApi<{ id: string; title: string }[]>("/api/incidents", [], tick); const id = sel || inc[0]?.id || "";
  const g = useApi<any>(id ? `/api/incidents/${id}/graph` : "/api/health", null, tick);
  return <><select className="rounded bg-slate-800 p-2 text-sm" value={id} onChange={e => setSel(e.target.value)}>{inc.map(i => <option key={i.id} value={i.id}>{i.title}</option>)}</select>
    <Card title="Attack graph (built from incident events)">{id ? <GraphView graph={g} /> : <p className="text-slate-500">No incidents yet.</p>}</Card></>;
}
