import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { Badge, Stat, Table } from "./ui";
import { layoutGraph } from "./graphLayout";

const G = { nodes: [{ id: "ip:1", type: "attacker_ip", label: "1.1.1.1" }, { id: "user:a", type: "user", label: "a" }, { id: "host:h", type: "host", label: "h" }, { id: "x", type: "host", label: "h2" }],
  edges: [{ source: "ip:1", target: "user:a", label: "login" }, { source: "user:a", target: "host:h", label: "on host" }, { source: "ghost", target: "host:h", label: "bad" }, { source: "host:h", target: "x", label: "sent 5 MB" }] };

describe("ui components", () => {
  it("renders badge, stat and table", () => {
    render(<><Badge level="critical" /><Stat label="Events" value={42} /><Table head={["A"]} rows={[["row1"]]} /></>);
    expect(screen.getByText("critical")).toBeTruthy(); expect(screen.getByText("42")).toBeTruthy(); expect(screen.getByText("row1")).toBeTruthy();
  });
});
describe("layoutGraph", () => {
  it("places nodes in type columns left-to-right and stacks same-type nodes", () => {
    const { nodes, cols } = layoutGraph(G); const x = (id: string) => nodes.find(n => n.id === id)!.position;
    expect(cols).toEqual(["attacker_ip", "user", "host"]); expect(x("ip:1").x).toBeLessThan(x("user:a").x); expect(x("user:a").x).toBeLessThan(x("host:h").x); expect(x("x").y).toBeGreaterThan(x("host:h").y);
  });
  it("drops edges with missing endpoints and animates transfers", () => {
    const { edges } = layoutGraph(G); expect(edges).toHaveLength(3); expect(edges.find(e => e.label === "sent 5 MB")!.animated).toBe(true);
  });
});
