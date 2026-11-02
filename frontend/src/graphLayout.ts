export type GNode = { id: string; type: string; label: string }; export type GEdge = { source: string; target: string; label: string };
export const COLS = ["attacker_ip", "user", "host", "process", "file", "external_ip", "incident", "technique"];
export const NC: Record<string, string> = { attacker_ip: "#ef4444", user: "#38bdf8", host: "#a78bfa", process: "#f97316", file: "#eab308", external_ip: "#ef4444", incident: "#22d3ee", technique: "#22c55e" };
/** Column layout by entity type (attacker → user → host → process → file → external IP → incident → technique). */
export function layoutGraph(g: { nodes: GNode[]; edges: GEdge[] }) {
  const cols = COLS.filter(c => g.nodes.some(n => n.type === c));
  const nodes = cols.flatMap((c, ci) => g.nodes.filter(n => n.type === c).map((n, ri) => ({
    id: n.id, position: { x: ci * 190, y: ri * 80 }, data: { label: n.label },
    style: { background: "#0f172a", color: "#e2e8f0", border: `2px solid ${NC[n.type]}`, borderRadius: 8, fontSize: 11, padding: 6, width: 150 } })));
  const ids = new Set(nodes.map(n => n.id));
  const edges = g.edges.filter(e => ids.has(e.source) && ids.has(e.target)).map((e, i) => ({ id: `e${i}`, source: e.source, target: e.target, label: e.label, animated: e.label.startsWith("sent"),
    style: { stroke: "#64748b" }, labelStyle: { fill: "#94a3b8", fontSize: 10 }, labelBgStyle: { fill: "#0f172a" } }));
  return { nodes, edges, cols };
}
