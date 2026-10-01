import dagre from "@dagrejs/dagre";
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { AlertOctagon, Globe, KeyRound, Laptop, Server } from "lucide-react";
import { memo, useEffect, useMemo, useRef, useState } from "react";

import { riskColor } from "@/lib/format";
import type { GraphData, GraphNode } from "@/lib/types";
import { cn } from "@/lib/utils";

type Change = "resolved" | "new" | "improved" | "worse" | null;

type InfraNodeData = {
  node: GraphNode;
  change: Change;
  previousRisk?: string;
  dimmed: boolean;
  selected: boolean;
};

const NODE_W = { client: 170, server: 210, crypto: 200, weakness: 240, domain: 170 } as const;
const NODE_H = 58;

const ICON = { client: Laptop, server: Server, crypto: KeyRound, weakness: AlertOctagon, domain: Globe };

const RISK_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, quantum: 4, info: 5, ok: 6 };

function metricLine(n: GraphNode): string {
  const m = n.metrics as Record<string, number | string | Record<string, number>>;
  switch (n.type) {
    case "client":
      return `${m.sessions} session${m.sessions === 1 ? "" : "s"}${Number(m.cleartext) ? ` · ${m.cleartext} cleartext` : ""}`;
    case "server": {
      const protocols = Object.keys((m.protocols as Record<string, number>) ?? {}).join("/");
      return `${protocols} · ${m.sessions} sess · ${m.clients} client${m.clients === 1 ? "" : "s"}`;
    }
    case "crypto":
      return `${n.sub} · ${m.sessions} sess`;
    case "weakness":
      return `${String(m.severity ?? "").toLowerCase()} · ${m.findings} finding${m.findings === 1 ? "" : "s"}`;
    default:
      return n.sub ?? "";
  }
}

const InfraNode = memo(function InfraNode({ data }: NodeProps<Node<InfraNodeData>>) {
  const { node, change, previousRisk, dimmed, selected } = data;
  const Icon = ICON[node.type];
  const color = change === "resolved" ? "hsl(var(--sev-ok))" : riskColor(node.risk);
  const width = NODE_W[node.type];

  return (
    <div
      className={cn(
        "relative rounded-lg border bg-card text-card-foreground shadow-sm transition-all duration-500",
        dimmed && "opacity-25",
        selected && "ring-2 ring-primary ring-offset-2 ring-offset-background",
        change === "resolved" && "border-dashed opacity-60",
      )}
      style={{ width, height: NODE_H, borderLeft: `3px solid ${color}` }}
    >
      <Handle type="target" position={Position.Left} className="!size-1.5 !border-0 !bg-muted-foreground/40" />
      <div className="flex h-full items-center gap-2.5 px-2.5">
        <div className="grid size-7 shrink-0 place-items-center rounded-md" style={{ background: `color-mix(in srgb, ${color} 14%, transparent)`, color }}>
          <Icon className="size-3.5" />
        </div>
        <div className="min-w-0 flex-1 leading-tight">
          <div className={cn("truncate text-[12.5px] font-medium", node.type !== "weakness" && "font-mono", change === "resolved" && "line-through")}>
            {node.label}
          </div>
          <div className="truncate text-[11px] text-muted-foreground">{metricLine(node)}</div>
        </div>
      </div>
      {change && (
        <span
          className="absolute -top-2 right-2 rounded px-1.5 text-[9.5px] font-semibold uppercase tracking-wide text-white"
          style={{
            background:
              change === "resolved" || change === "improved"
                ? "hsl(var(--sev-ok))"
                : change === "new"
                  ? "hsl(var(--primary))"
                  : "hsl(var(--sev-critical))",
          }}
          title={previousRisk ? `was ${previousRisk}` : undefined}
        >
          {change}
          {previousRisk && change === "improved" ? ` · was ${previousRisk}` : ""}
        </span>
      )}
      <Handle type="source" position={Position.Right} className="!size-1.5 !border-0 !bg-muted-foreground/40" />
    </div>
  );
});

const nodeTypes = { infra: InfraNode };

/** Layout on the union of graphs so before/after views share positions. */
function layout(nodes: GraphNode[], edges: GraphData["edges"]) {
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: "LR", nodesep: 14, ranksep: 90, marginx: 10, marginy: 10 });
  g.setDefaultEdgeLabel(() => ({}));
  for (const n of nodes) g.setNode(n.id, { width: NODE_W[n.type], height: NODE_H });
  for (const e of edges) {
    if (!g.hasNode(e.source) || !g.hasNode(e.target)) continue;
    // Weaknesses sit to the right of the servers they affect, beyond the crypto column.
    if (e.type === "affects") g.setEdge(e.target, e.source, { minlen: 2 });
    else g.setEdge(e.source, e.target);
  }
  dagre.layout(g);
  const pos: Record<string, { x: number; y: number }> = {};
  for (const n of nodes) {
    const p = g.node(n.id);
    if (p) pos[n.id] = { x: p.x - NODE_W[n.type] / 2, y: p.y - NODE_H / 2 };
  }
  return pos;
}

export interface TopologyProps {
  graph: GraphData;
  /** When set, `graph` is shown as the state after a change and `compare` as before. */
  compare?: GraphData;
  height?: number | string;
  selectedId?: string | null;
  onSelect?: (node: GraphNode | null) => void;
  className?: string;
}

function TopologyInner({ graph, compare, height = 520, selectedId, onSelect, className }: TopologyProps) {
  const [hover, setHover] = useState<string | null>(null);
  const flow = useReactFlow();

  const { nodes, edges } = useMemo(() => {
    const before = new Map((compare?.nodes ?? []).map((n) => [n.id, n]));
    const after = new Map(graph.nodes.map((n) => [n.id, n]));
    const union: GraphNode[] = [...graph.nodes];
    if (compare) for (const n of compare.nodes) if (!after.has(n.id)) union.push(n);

    const allEdges = [...graph.edges];
    if (compare) {
      const seen = new Set(graph.edges.map((e) => `${e.source}|${e.target}|${e.type}`));
      for (const e of compare.edges) if (!seen.has(`${e.source}|${e.target}|${e.type}`)) allEdges.push({ ...e, weight: -1 });
    }
    const pos = layout(union, allEdges);

    const neighbours = new Set<string>();
    const focus = hover ?? selectedId ?? null;
    if (focus) {
      neighbours.add(focus);
      for (const e of allEdges) {
        if (e.source === focus) neighbours.add(e.target);
        if (e.target === focus) neighbours.add(e.source);
      }
    }

    const rfNodes: Node<InfraNodeData>[] = union.map((n) => {
      let change: Change = null;
      let previousRisk: string | undefined;
      if (compare) {
        const prev = before.get(n.id);
        if (!after.has(n.id)) change = "resolved";
        else if (!prev) change = "new";
        else if (prev.risk !== n.risk) {
          change = (RISK_ORDER[n.risk] ?? 9) > (RISK_ORDER[prev.risk] ?? 9) ? "improved" : "worse";
          previousRisk = prev.risk;
        }
      }
      return {
        id: n.id,
        type: "infra",
        position: pos[n.id] ?? { x: 0, y: 0 },
        data: { node: n, change, previousRisk, dimmed: !!focus && !neighbours.has(n.id), selected: n.id === selectedId },
      };
    });

    const rfEdges: Edge[] = allEdges
      .filter((e) => pos[e.source] && pos[e.target])
      .map((e, i) => {
        const removed = e.weight === -1;
        const clear = (e.cleartext ?? 0) > 0 && !removed;
        const affects = e.type === "affects";
        const color = removed
          ? "hsl(var(--muted-foreground) / 0.25)"
          : affects
            ? "hsl(var(--sev-critical) / 0.55)"
            : clear
              ? "hsl(var(--sev-high))"
              : "hsl(var(--muted-foreground) / 0.4)";
        const dim = !!focus && !(neighbours.has(e.source) && neighbours.has(e.target) && (e.source === focus || e.target === focus));
        return {
          id: `${e.source}-${e.target}-${e.type}-${i}`,
          source: affects ? e.target : e.source,
          target: affects ? e.source : e.target,
          type: "default",
          animated: clear,
          style: {
            stroke: color,
            strokeWidth: Math.min(1 + Math.log2(1 + Math.max(e.weight, 0)), 4),
            strokeDasharray: affects || removed ? "4 4" : undefined,
            opacity: dim ? 0.12 : 1,
            transition: "opacity .3s, stroke .5s",
          },
          markerEnd: affects ? undefined : { type: MarkerType.ArrowClosed, color, width: 14, height: 14 },
        } satisfies Edge;
      });

    return { nodes: rfNodes, edges: rfEdges };
  }, [graph, compare, hover, selectedId]);

  const wrap = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const fit = () => flow.fitView({ padding: 0.14, maxZoom: 1.05, duration: 200 });
    const t = setTimeout(fit, 60);
    const ro = new ResizeObserver(() => fit());
    if (wrap.current) ro.observe(wrap.current);
    return () => {
      clearTimeout(t);
      ro.disconnect();
    };
  }, [graph.nodes.length, compare?.nodes.length, flow]);

  return (
    <div className={cn("overflow-hidden rounded-md border", className)}>
    <div ref={wrap} className="relative bg-muted/20" style={{ height }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.14, maxZoom: 1.05 }}
        minZoom={0.2}
        maxZoom={1.8}
        nodesDraggable={false}
        nodesConnectable={false}
        onNodeMouseEnter={(_, n) => setHover(n.id)}
        onNodeMouseLeave={() => setHover(null)}
        onNodeClick={(_, n) => onSelect?.((n.data as InfraNodeData).node)}
        onPaneClick={() => onSelect?.(null)}
        proOptions={{ hideAttribution: true }}
      >
        <Background gap={20} size={1} color="hsl(var(--muted-foreground) / 0.18)" />
        <Controls showInteractive={false} position="bottom-right" />
      </ReactFlow>
    </div>
      <Legend />
    </div>
  );
}

function Legend() {
  const items: [string, string][] = [
    ["critical", "Critical"],
    ["high", "High"],
    ["medium", "Medium"],
    ["quantum", "Quantum-vulnerable"],
    ["ok", "OK"],
  ];
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t bg-card px-3 py-2 text-[11px] text-muted-foreground">
      {["Clients", "Servers", "Crypto", "Weaknesses"].map((c, i) => (
        <span key={c} className="font-medium text-foreground/80">
          {i > 0 && <span className="mr-3 text-muted-foreground">→</span>}
          {c}
        </span>
      ))}
      <span className="mx-1 h-3 w-px bg-border" />
      {items.map(([k, label]) => (
        <span key={k} className="flex items-center gap-1">
          <span className="size-2 rounded-sm" style={{ background: riskColor(k) }} />
          {label}
        </span>
      ))}
      <span className="flex items-center gap-1">
        <span className="h-0.5 w-4 rounded" style={{ background: "hsl(var(--sev-high))" }} />
        cleartext flow
      </span>
    </div>
  );
}

export function Topology(props: TopologyProps) {
  return (
    <ReactFlowProvider>
      <TopologyInner {...props} />
    </ReactFlowProvider>
  );
}
