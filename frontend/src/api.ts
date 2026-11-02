import { useEffect, useState, useCallback } from "react";
const HOST = (import.meta as any).env?.VITE_API_URL || "http://localhost:8000";
/** Simulated identity sent with every request (X-Role / X-Actor). NOT real authentication: it demonstrates the backend's role-based approval checks. */
export const identity = { actor: "analyst", role: "senior_analyst" };
/** Turns an `api()` error ("403 {"detail":{"code":..,"message":..}}") into a readable message. */
export const errMsg = (e: unknown): string => {
  const raw = e instanceof Error ? e.message : String(e); const i = raw.indexOf("{");
  if (i < 0) return raw;
  try { const d = JSON.parse(raw.slice(i)).detail; return typeof d === "string" ? d : d?.message || raw; } catch { return raw; }
};
export const api = async <T,>(path: string, method = "GET", body?: unknown): Promise<T> => {
  const r = await fetch(HOST + path, { method, headers: { "content-type": "application/json", "x-role": identity.role, "x-actor": identity.actor }, body: body ? JSON.stringify(body) : undefined });
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`); return r.json();
};
export type WsMsg = { type: string; data: any };
/** Subscribes to backend WebSocket; calls onMsg for every pushed message. */
export function useLive(onMsg: (m: WsMsg) => void) {
  const [up, setUp] = useState(false);
  useEffect(() => {
    let ws: WebSocket, stop = false;
    const connect = () => { ws = new WebSocket(HOST.replace("http", "ws") + "/ws");
      ws.onopen = () => setUp(true); ws.onclose = () => { setUp(false); if (!stop) setTimeout(connect, 2000); };
      ws.onmessage = e => onMsg(JSON.parse(e.data)); };
    connect(); return () => { stop = true; ws.close(); };
  }, []);
  return up;
}
/** Fetches a path and refetches whenever a live message arrives. */
export function useApi<T>(path: string, init: T, tick: number) {
  const [d, setD] = useState<T>(init);
  const load = useCallback(() => api<T>(path).then(setD).catch(console.error), [path]);
  useEffect(() => { load(); }, [load, tick]); return d;
}
