import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { PIPELINE, Exec, ReplayStep, agentStatuses, feedLine, fmtDuration, normStatus, replayWindow, agentLabel } from "./agentView";
import { PipelineStrip, AgentDetail } from "./AgentActivity";
import { StepCard } from "./Replay";
import { errMsg } from "./api";

const ex = (agent: string, status: string, seq: number, extra: Partial<Exec> = {}): Exec => ({
  id: `${agent}${seq}`, agent, status, confidence: 0.8, started_at: null, finished_at: null, duration_ms: 1500, run_id: "r1", sequence: seq, iteration: null,
  input_summary: "in", output_summary: `${agent} done`, tools_used: [{ tool: "lookup_ip_reputation", ok: true, duration_ms: 3, summary: "found" }], evidence: ["e1"], evidence_ids: ["event:1"], findings: [], error: null, ...extra });

describe("agent status helpers", () => {
  it("normalises legacy and new statuses", () => {
    expect(normStatus("success")).toBe("COMPLETED"); expect(normStatus("COMPLETED")).toBe("COMPLETED"); expect(normStatus("failed")).toBe("FAILED");
    expect(normStatus("RUNNING")).toBe("RUNNING"); expect(normStatus(undefined)).toBe("WAITING");
  });
  it("marks agents without an execution as WAITING and uses the latest execution otherwise", () => {
    const st = agentStatuses([ex("DetectionAgent", "COMPLETED", 1), ex("LogAnalysisAgent", "RUNNING", 2), ex("InvestigationAgent", "COMPLETED", 3), ex("InvestigationAgent", "RUNNING", 5)]);
    expect(st.DetectionAgent.status).toBe("COMPLETED"); expect(st.LogAnalysisAgent.status).toBe("RUNNING"); expect(st.ThreatIntelligenceAgent.status).toBe("WAITING");
    expect(st.InvestigationAgent.status).toBe("RUNNING"); expect(st.InvestigationAgent.count).toBe(2); expect(Object.keys(st)).toEqual([...PIPELINE]);
  });
  it("formats durations, labels and live feed lines", () => {
    expect(fmtDuration(null)).toBe("–"); expect(fmtDuration(250)).toBe("250 ms"); expect(fmtDuration(2500)).toBe("2.5 s");
    expect(agentLabel("ThreatIntelligenceAgent")).toBe("Threat Intelligence Agent");
    expect(feedLine({ type: "agent_update", data: { agent: "DetectionAgent", status: "COMPLETED" } })).toBe("Detection Agent → COMPLETED");
  });
  it("windows replay steps", () => {
    const steps = [0, 1, 2, 3].map(i => ({ index: i, ts: null, kind: "state", run_id: null, title: `s${i}`, detail: "" }) as ReplayStep);
    expect(replayWindow(steps, 1).map(s => s.title)).toEqual(["s0", "s1"]); expect(replayWindow(steps, 99)).toHaveLength(4); expect(replayWindow([], 3)).toHaveLength(0);
  });
  it("extracts readable API errors", () => {
    expect(errMsg(new Error('403 {"detail":{"code":"insufficient_role","message":"role analyst may not approve block_ip"}}'))).toBe("role analyst may not approve block_ip");
    expect(errMsg(new Error("boom"))).toBe("boom");
  });
});

describe("agent components", () => {
  it("renders all 8 agents with their status and reacts to selection", () => {
    const st = agentStatuses([ex("DetectionAgent", "COMPLETED", 1), ex("LogAnalysisAgent", "RUNNING", 2), ex("ResponseAgent", "FAILED", 3)]); const pick = vi.fn();
    render(<PipelineStrip statuses={st} selected="DetectionAgent" onSelect={pick} />);
    for (const a of PIPELINE) expect(screen.getByTestId(`agent-${a}`)).toBeTruthy();
    expect(screen.getAllByText("WAITING").length).toBe(5); expect(screen.getByText("RUNNING")).toBeTruthy(); expect(screen.getByText("FAILED")).toBeTruthy();
    fireEvent.click(screen.getByTestId("agent-ResponseAgent")); expect(pick).toHaveBeenCalledWith("ResponseAgent");
  });
  it("shows tools, findings and errors in the detail panel", () => {
    render(<AgentDetail exec={ex("InvestigationAgent", "FAILED", 4, { error: "kaboom", findings: [{ description: "Multi-stage sequence", severity: "high", confidence: 0.8, source: "sequence", evidence: [] }] })} />);
    expect(screen.getByText("lookup_ip_reputation")).toBeTruthy(); expect(screen.getByText(/Multi-stage sequence/)).toBeTruthy(); expect(screen.getByText(/kaboom/)).toBeTruthy();
  });
  it("renders a replay step for an agent", () => {
    render(<StepCard s={{ index: 0, ts: "2026-01-01T12:00:00", kind: "agent", run_id: "r", title: "x", detail: "", agent: "RiskAssessmentAgent", status: "COMPLETED", duration_ms: 12, confidence: 0.9, output_summary: "risk 80 (high)" }} />);
    expect(screen.getByText("Risk Assessment Agent")).toBeTruthy(); expect(screen.getByText("risk 80 (high)")).toBeTruthy();
  });
});
