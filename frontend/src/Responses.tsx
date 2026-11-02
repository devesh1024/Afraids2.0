import { useState } from "react";
import { api, errMsg, identity, useApi } from "./api";
import { Card, Table } from "./ui";

type Rec = { id: string; incident_id: string; incident_title: string; action: string; target: string | null; rationale: string; expected_impact: string | null; confidence: number | null;
  approval_level: string | null; destructive: number | null; status: string; decided_by: string | null; modified: number | null; execution_result: any };
type Policy = { actions: { name: string; approval_level: string; destructive: boolean }[]; roles: string[] };
type Sim = Record<string, any>;
const NONE: Policy = { actions: [], roles: [] };

export function ResponseCenter({ tick }: { tick: number }) {
  const [n, setN] = useState(0); const [msg, setMsg] = useState<{ id: string; text: string; ok: boolean } | null>(null);
  const recs = useApi<Rec[]>("/api/responses", [], tick + n); const pol = useApi<Policy>("/api/policy", NONE, 0); const sim = useApi<Sim>("/api/simulation/state", {} as Sim, tick + n);
  const [edit, setEdit] = useState<{ id: string; action: string; target: string } | null>(null);
  const call = (r: Rec, verb: string, extra: object = {}) => api<any>(`/api/incidents/${r.incident_id}/${verb}-response`, "POST", { response_id: r.id, ...extra })
    .then(() => { setMsg({ id: r.id, text: `${verb} OK (simulated)`, ok: true }); setEdit(null); setN(x => x + 1); }).catch(e => setMsg({ id: r.id, text: errMsg(e), ok: false }));
  return <>
    <Card title={`Human approval required — acting as ${identity.actor} (${identity.role}); all actions are simulated`}>
      <Table head={["Incident", "Action → target", "Reason / impact", "Conf", "Needs", "Status", ""]} rows={recs.map(r => [r.incident_title,
        <div><b>{r.action}</b> → {r.target ?? "–"}{r.modified ? <span className="ml-1 text-xs text-yellow-400">(modified)</span> : null}{r.destructive ? <span className="ml-1 text-xs text-red-400">destructive</span> : null}</div>,
        <div className="text-xs"><div>{r.rationale}</div><div className="text-slate-500">Impact: {r.expected_impact ?? "–"}</div></div>, r.confidence ?? "–", r.approval_level ?? "legacy",
        <div>{r.status}{r.decided_by ? <div className="text-xs text-slate-500">by {r.decided_by}</div> : null}</div>,
        r.status === "pending" ? <div><div className="flex gap-1">
          <button className="rounded bg-green-700 px-2 py-1" onClick={() => call(r, "approve")}>Approve</button>
          <button className="rounded bg-red-700 px-2 py-1" onClick={() => call(r, "reject")}>Reject</button>
          {r.approval_level && <button className="rounded bg-slate-600 px-2 py-1" onClick={() => setEdit({ id: r.id, action: r.action, target: r.target || "" })}>Modify</button>}</div>
          {edit?.id === r.id && <div className="mt-2 flex gap-1"><select className="rounded bg-slate-800 p-1 text-xs" value={edit.action} onChange={e => setEdit({ ...edit, action: e.target.value })}>{pol.actions.map(a => <option key={a.name}>{a.name}</option>)}</select>
            <input className="w-32 rounded bg-slate-800 p-1 text-xs" value={edit.target} onChange={e => setEdit({ ...edit, target: e.target.value })} />
            <button className="rounded bg-cyan-700 px-2 py-1 text-xs" onClick={() => call(r, "modify", { action: edit.action, target: edit.target })}>Save</button></div>}
          {msg?.id === r.id && <div className={`mt-1 text-xs ${msg.ok ? "text-green-400" : "text-red-400"}`}>{msg.text}</div>}</div>
          : <span className="text-xs text-slate-500">{r.execution_result?.message || ""}</span>])} />
      {!recs.length && <p className="text-slate-500">No recommendations yet.</p>}
    </Card>
    <Card title="Simulated enforcement state (not a real firewall / directory / endpoint)"><div className="grid grid-cols-4 gap-4 text-sm">
      {[["blocklist", "Blocked IPs"], ["disabled_accounts", "Disabled accounts"], ["revoked_sessions", "Revoked sessions"], ["isolated_hosts", "Isolated hosts"], ["monitoring", "Monitoring"], ["evidence_snapshots", "Evidence snapshots"], ["closed_incidents", "Closed incidents"]].map(([k, l]) =>
        <div key={k}><div className="text-xs uppercase text-slate-500">{l}</div>{(sim[k] || []).map((x: { target: string }, i: number) => <div key={i} className="truncate">{x.target}</div>)}{!(sim[k] || []).length && <span className="text-slate-600">–</span>}</div>)}
    </div></Card></>;
}
