import { ReactNode } from "react";
export const COLORS: Record<string, string> = { low: "#22c55e", medium: "#eab308", high: "#f97316", critical: "#ef4444" };
export const Card = ({ title, children }: { title?: string; children: ReactNode }) =>
  <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">{title && <h3 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">{title}</h3>}{children}</div>;
export const Badge = ({ level }: { level: string }) =>
  <span className="rounded px-2 py-0.5 text-xs font-bold text-black" style={{ background: COLORS[level] || "#64748b" }}>{level}</span>;
export const Stat = ({ label, value }: { label: string; value: number | string }) =>
  <Card><div className="text-3xl font-bold text-white">{value}</div><div className="text-xs text-slate-400">{label}</div></Card>;
export const Table = ({ head, rows }: { head: string[]; rows: ReactNode[][] }) =>
  <table className="w-full text-left text-sm"><thead className="text-slate-400"><tr>{head.map(h => <th key={h} className="pb-2">{h}</th>)}</tr></thead>
    <tbody>{rows.map((r, i) => <tr key={i} className="border-t border-slate-800">{r.map((c, j) => <td key={j} className="py-1.5 pr-3">{c}</td>)}</tr>)}</tbody></table>;
