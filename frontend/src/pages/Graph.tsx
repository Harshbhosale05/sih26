import clsx from "clsx";
import { GitBranch, KeyRound, Mail, Server, ShieldAlert, Users } from "lucide-react";
import { useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { Card, Empty, ErrorState, Mono, PageHeader, Pill, SeverityBadge, Spinner, Stat, Tabs } from "../components/ui";
import { useApi } from "../lib/api";
import { fmtPct } from "../lib/format";
import type { BlastRadius, GraphData, GraphNode } from "../lib/types";

const COLUMN: Record<GraphNode["type"], number> = { client: 0, server: 1, crypto: 2, weakness: 3, domain: 3 };
const COLUMN_TITLES = ["Clients", "Mail servers", "Crypto primitives", "Weaknesses"];
const TYPE_COLOR: Record<string, string> = {
  client: "var(--s1)",
  server: "var(--s7)",
  crypto: "var(--s3)",
  domain: "var(--s4)",
};
const RISK_COLOR: Record<string, string> = {
  critical: "rgb(var(--crit))",
  high: "rgb(var(--serious))",
  medium: "rgb(var(--warn))",
  low: "rgb(var(--accent))",
  quantum: "rgb(var(--muted))",
  info: "rgb(var(--muted))",
};

type PlacedNode = GraphNode & { x: number; y: number };
const WIDTH = 1150;
const COL_X = [150, 420, 680, 935];
const ROW = 38;
const TOP = 50;

/**
 * Layered layout: one column per node type, evenly spaced rows, and each
 * column ordered by the mean position of its neighbours (a few barycentre
 * sweeps) so related nodes line up and edge crossings stay low.
 */
function layout(data: GraphData) {
  const columns: GraphNode[][] = [[], [], [], []];
  data.nodes.forEach((n) => columns[COLUMN[n.type]].push(n));
  const height = Math.max(360, Math.max(...columns.map((c) => c.length)) * ROW + TOP + 20);

  const adj = new Map<string, string[]>();
  for (const e of data.edges) {
    adj.set(e.source, [...(adj.get(e.source) ?? []), e.target]);
    adj.set(e.target, [...(adj.get(e.target) ?? []), e.source]);
  }

  const y = new Map<string, number>();
  const place = () =>
    columns.forEach((col) => {
      const offset = TOP + (height - TOP - col.length * ROW) / 2 + ROW / 2;
      col.forEach((n, i) => y.set(n.id, offset + i * ROW));
    });
  place();

  const order = [1, 2, 3, 0, 1, 2, 3, 0, 1];
  for (const c of order) {
    const mean = (id: string) => {
      const ys = (adj.get(id) ?? []).map((m) => y.get(m)).filter((v): v is number => v !== undefined);
      return ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : (y.get(id) ?? 0);
    };
    columns[c].sort((a, b) => mean(a.id) - mean(b.id));
    place();
  }

  const nodes = new Map<string, PlacedNode>();
  data.nodes.forEach((n) => nodes.set(n.id, { ...n, x: COL_X[COLUMN[n.type]], y: y.get(n.id) ?? 0 }));
  return { nodes, height };
}

function neighbourhood(data: GraphData, id: string): Set<string> {
  const adj = new Map<string, Set<string>>();
  for (const e of data.edges) {
    if (!adj.has(e.source)) adj.set(e.source, new Set());
    if (!adj.has(e.target)) adj.set(e.target, new Set());
    adj.get(e.source)!.add(e.target);
    adj.get(e.target)!.add(e.source);
  }
  const out = new Set([id]);
  const first = adj.get(id) ?? new Set();
  first.forEach((n) => {
    out.add(n);
    // Expand through servers: a weakness on a server reaches every client of it.
    // Other weaknesses on the same server are not part of this trace.
    if (n.startsWith("server:") || id.startsWith("server:"))
      adj.get(n)?.forEach((m) => (!m.startsWith("weakness:") || id.startsWith("server:")) && out.add(m));
  });
  return out;
}

function nodeIcon(type: string) {
  return { client: Users, server: Server, crypto: KeyRound, weakness: ShieldAlert, domain: Mail }[type] ?? Server;
}

function DependencyGraph({ data, selected, onSelect }: { data: GraphData; selected: string | null; onSelect: (id: string | null) => void }) {
  const { nodes, height } = useMemo(() => layout(data), [data]);
  const [hover, setHover] = useState<string | null>(null);
  const focus = selected ?? hover;
  const lit = useMemo(() => (focus ? neighbourhood(data, focus) : null), [data, focus]);
  const hovered = hover ? nodes.get(hover) : null;

  return (
    <div className="relative overflow-x-auto">
      <svg viewBox={`0 0 ${WIDTH} ${height}`} className="block min-w-[760px]" style={{ width: "100%" }} onClick={() => onSelect(null)}>
        {COLUMN_TITLES.map((t, i) => (
          <text key={t} x={COL_X[i]} y={20} textAnchor="middle" className="fill-current text-muted" style={{ fontSize: 11, fontWeight: 600, letterSpacing: 0.6 }}>
            {t.toUpperCase()}
          </text>
        ))}

        {data.edges.map((e) => {
          const s = nodes.get(e.source);
          const t = nodes.get(e.target);
          if (!s || !t) return null;
          const on = !lit || (lit.has(e.source) && lit.has(e.target));
          const mx = (s.x + t.x) / 2;
          const risky = e.type === "affects" || (e.cleartext ?? 0) > 0;
          return (
            <path
              key={`${e.source}-${e.target}-${e.type}`}
              d={`M${s.x},${s.y} C${mx},${s.y} ${mx},${t.y} ${t.x},${t.y}`}
              fill="none"
              stroke={risky ? "rgb(var(--crit))" : "rgb(var(--ink-2))"}
              strokeOpacity={on ? (risky ? 0.55 : 0.28) : 0.05}
              strokeWidth={Math.min(1 + Math.log2(e.weight + 1), 5)}
              strokeDasharray={e.type === "affects" ? "4 3" : undefined}
            />
          );
        })}

        {[...nodes.values()].map((n) => {
          const on = !lit || lit.has(n.id);
          const Icon = nodeIcon(n.type);
          const fill = n.type === "weakness" ? RISK_COLOR[n.risk] ?? RISK_COLOR.info : TYPE_COLOR[n.type];
          const ring = n.type !== "weakness" && n.risk !== "ok" ? RISK_COLOR[n.risk] : null;
          const anchorLeft = COLUMN[n.type] === 0;
          return (
            <g
              key={n.id}
              transform={`translate(${n.x},${n.y})`}
              opacity={on ? 1 : 0.18}
              className="cursor-pointer"
              onMouseEnter={() => setHover(n.id)}
              onMouseLeave={() => setHover(null)}
              onClick={(ev) => {
                ev.stopPropagation();
                onSelect(selected === n.id ? null : n.id);
              }}
            >
              <circle r={18} fill="transparent" />
              {ring && <circle r={13} fill="none" stroke={ring} strokeWidth={2.5} />}
              <circle r={10} fill={fill} stroke="rgb(var(--surface))" strokeWidth={2} />
              <Icon x={-6} y={-6} width={12} height={12} color="white" strokeWidth={2.4} />
              <text
                x={anchorLeft ? -18 : 18}
                y={4}
                textAnchor={anchorLeft ? "end" : "start"}
                className="fill-current text-ink"
                style={{ fontSize: 12.5, fontWeight: selected === n.id ? 700 : 500 }}
              >
                {n.label.length > 28 ? `${n.label.slice(0, 27)}…` : n.label}
              </text>
            </g>
          );
        })}
      </svg>

      {hovered && (
        <div className="pointer-events-none absolute right-3 top-8 w-64 rounded-lg border border-line bg-surface p-3 text-[12px] shadow-lg">
          <div className="font-semibold text-ink">{hovered.label}</div>
          <div className="mb-1.5 text-muted">
            {hovered.type}
            {hovered.sub ? ` · ${hovered.sub}` : ""}
          </div>
          {Object.entries(hovered.metrics)
            .filter(([, v]) => typeof v === "number" || typeof v === "string")
            .map(([k, v]) => (
              <div key={k} className="flex justify-between gap-3">
                <span className="text-ink2">{k.replace(/_/g, " ")}</span>
                <span className="tabular font-medium text-ink">{String(v)}</span>
              </div>
            ))}
        </div>
      )}
    </div>
  );
}

function RadiusRow({ r, active, onClick }: { r: BlastRadius; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={clsx(
        "w-full rounded-lg border p-3 text-left transition",
        active ? "border-accent bg-accent/5" : "border-line bg-surface hover:border-accent/40",
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="text-[13px] font-semibold leading-snug text-ink">{r.title}</div>
          <div className="mt-0.5 text-[11.5px] text-muted">{r.kind === "crypto" ? "crypto dependency" : r.finding_refs.slice(0, 3).join(", ")}</div>
        </div>
        <SeverityBadge severity={r.severity} compact />
      </div>
      <div className="mt-2.5 grid grid-cols-3 gap-2 text-center">
        <div className="rounded-md bg-raised py-1.5">
          <div className="tabular text-[15px] font-semibold text-ink">{r.direct_sessions}</div>
          <div className="text-[10.5px] text-muted">direct sessions</div>
        </div>
        <div className="rounded-md bg-raised py-1.5">
          <div className="tabular text-[15px] font-semibold text-ink">{r.dependent_clients}</div>
          <div className="text-[10.5px] text-muted">clients · {fmtPct(r.clients_pct)}</div>
        </div>
        <div className="rounded-md bg-raised py-1.5">
          <div className="tabular text-[15px] font-semibold text-ink">{r.servers.length}</div>
          <div className="text-[10.5px] text-muted">servers · {fmtPct(r.servers_pct)}</div>
        </div>
      </div>
      <div className="mt-2 flex items-center gap-2">
        <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-line/60">
          <div className="h-full rounded-full bg-accent" style={{ width: `${Math.min(100, r.blast_score)}%` }} />
        </div>
        <span className="tabular text-[11.5px] text-ink2">score {r.blast_score}</span>
      </div>
      {r.credentials_exposed > 0 && <div className="mt-1.5 text-[11.5px] font-medium text-crit">{r.credentials_exposed} session(s) exposed credentials</div>}
    </button>
  );
}

export function GraphPage() {
  const { captureId } = useParams();
  const res = useApi<GraphData>(`/api/captures/${captureId}/graph`);
  const [selected, setSelected] = useState<string | null>(null);
  const [kind, setKind] = useState<"finding" | "crypto">("finding");

  if (res.error) return <ErrorState error={res.error} onRetry={res.reload} />;
  if (!res.data) return <Spinner label="Building dependency graph…" />;
  const d = res.data;
  const radius = d.blast_radius.filter((r) => r.kind === kind);

  return (
    <>
      <PageHeader
        eyebrow="Exposure"
        title="Dependency graph & blast radius"
        description="Who depends on what. A weakness on a server reaches every client that sends mail through it, whether or not their own session tripped the rule. Select a weakness or any node to trace its reach."
      />

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Clients" value={d.totals.clients} icon={<Users size={16} />} />
        <Stat label="Mail servers" value={d.totals.servers} icon={<Server size={16} />} />
        <Stat label="Sessions" value={d.totals.sessions} icon={<GitBranch size={16} />} />
        <Stat label="Distinct weaknesses" value={d.totals.weaknesses} status={d.totals.weaknesses ? "serious" : "good"} icon={<ShieldAlert size={16} />} />
      </div>

      {d.nodes.length === 0 ? (
        <Empty title="No email sessions to graph" />
      ) : (
        <div className="grid gap-4 2xl:grid-cols-[1fr_380px]">
          <Card
            title="Cryptographic dependency graph"
            subtitle={selected ? `Tracing ${d.nodes.find((n) => n.id === selected)?.label ?? selected} — click empty space to clear` : "Hover for details · click to trace dependencies"}
            action={
              <div className="flex flex-wrap items-center gap-3 text-[11.5px] text-ink2">
                {[
                  ["Client", TYPE_COLOR.client],
                  ["Server", TYPE_COLOR.server],
                  ["Crypto", TYPE_COLOR.crypto],
                  ["Domain", TYPE_COLOR.domain],
                ].map(([l, c]) => (
                  <span key={l} className="flex items-center gap-1.5">
                    <span className="h-2.5 w-2.5 rounded-full" style={{ background: c }} />
                    {l}
                  </span>
                ))}
                <span className="flex items-center gap-1.5">
                  <span className="h-2.5 w-2.5 rounded-full ring-2 ring-crit" /> at risk
                </span>
              </div>
            }
            padded={false}
          >
            <div className="p-2">
              <DependencyGraph data={d} selected={selected} onSelect={setSelected} />
            </div>
            {d.totals.client_nodes_aggregated > 0 && (
              <div className="border-t border-line px-5 py-2 text-[12px] text-muted">
                {d.totals.client_nodes_aggregated} low-volume clients are grouped under “Other clients”.
              </div>
            )}
          </Card>

          <Card
            title="Blast radius"
            subtitle="Ranked by severity × reach"
            action={
              <Tabs
                value={kind}
                onChange={setKind}
                items={[
                  { value: "finding", label: "Findings" },
                  { value: "crypto", label: "Crypto" },
                ]}
              />
            }
          >
            {radius.length === 0 ? (
              <p className="text-[13px] text-ink2">Nothing to rank here.</p>
            ) : (
              <div className="grid max-h-[720px] gap-2 overflow-y-auto pr-1 sm:grid-cols-2 2xl:grid-cols-1">
                {radius.map((r) => (
                  <RadiusRow key={r.key} r={r} active={selected === r.node} onClick={() => setSelected(selected === r.node ? null : r.node)} />
                ))}
              </div>
            )}
            <p className="mt-4 text-[11.5px] leading-relaxed text-muted">{d.method}</p>
          </Card>
        </div>
      )}

      <Card className="mt-4" title="Most depended-upon servers" padded={false}>
        <div className="divide-y divide-line">
          {d.servers.slice(0, 8).map((s) => (
            <button key={s.node} onClick={() => setSelected(s.node)} className="flex w-full flex-wrap items-center gap-3 px-5 py-3 text-left hover:bg-raised/60">
              <Mono>{s.server}</Mono>
              <span className="text-[12.5px] text-ink2">
                {s.clients} client(s) · {s.sessions} session(s){s.cleartext ? ` · ${s.cleartext} cleartext` : ""}
              </span>
              <span className="ml-auto flex flex-wrap gap-1">
                {s.weaknesses.slice(0, 3).map((w) => (
                  <Pill key={w}>{w.replace(/_/g, " ")}</Pill>
                ))}
              </span>
            </button>
          ))}
        </div>
      </Card>
    </>
  );
}
