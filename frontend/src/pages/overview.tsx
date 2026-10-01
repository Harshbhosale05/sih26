import { ArrowRight } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import {
  ErrorState,
  Loading,
  Meter,
  Panel,
  Properties,
  RiskBadge,
  SeverityBadge,
  StatStrip,
  StateBadge,
  TierBadge,
} from "@/components/common";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { OutcomeFlow } from "@/components/viz/outcome-flow";
import { PostureDimensions } from "@/components/viz/posture-dimensions";
import { SessionTimeline } from "@/components/viz/timeline";
import { Topology } from "@/components/viz/topology";
import { useGraph, useOverview, usePosture, usePriorities, useRisk, useSessions, useSoftware } from "@/lib/api";
import { fmtPct, scoreLabel, sevColor } from "@/lib/format";
import type { GraphData, GraphNode } from "@/lib/types";

function NodeSheet({ node, graph, captureId, onClose }: { node: GraphNode | null; graph?: GraphData; captureId: string; onClose: () => void }) {
  const { data: software } = useSoftware(captureId);
  if (!node || !graph) return null;
  const m = node.metrics as Record<string, unknown>;
  const radius = graph.blast_radius.find((r) => r.node === node.id);
  const sw = node.type === "server" ? software?.find((s) => s.server === node.label) : undefined;
  const entry = graph.servers.find((s) => s.node === node.id);
  const typeLabel = { client: "Client", server: "Mail server", crypto: "Cryptographic primitive", weakness: "Weakness", domain: "Mail domain" }[node.type];

  return (
    <Sheet open={!!node} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-full sm:max-w-md">
        <SheetHeader>
          <SheetDescription>{typeLabel}</SheetDescription>
          <SheetTitle className={node.type === "weakness" ? "" : "font-mono"}>{node.label}</SheetTitle>
        </SheetHeader>
        <div className="mt-6 space-y-6">
          <Properties
            rows={[
              ...(sw ? ([["Software", `${sw.name}${sw.version ? ` ${sw.version}` : ""}`], ["Banner", <span className="font-mono text-xs">{sw.evidence}</span>]] as [string, React.ReactNode][]) : []),
              ...(node.sub && node.type !== "weakness" ? ([["Type", node.sub]] as [string, string][]) : []),
              ...Object.entries(m)
                .filter(([, v]) => typeof v === "number" || typeof v === "string")
                .map(([k, v]) => [k.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase()), String(v)] as [string, string]),
            ]}
          />
          {entry && entry.weaknesses.length > 0 && (
            <div className="space-y-2">
              <div className="text-xs font-medium text-muted-foreground">Weaknesses on this server</div>
              <ul className="space-y-1 text-sm">
                {entry.weaknesses.map((w) => (
                  <li key={w}>{w.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase())}</li>
                ))}
              </ul>
            </div>
          )}
          {radius && (
            <div className="space-y-3">
              <div className="text-xs font-medium text-muted-foreground">Extent of impact (observed environment)</div>
              {[
                ["Direct sessions", radius.direct_sessions, radius.direct_pct],
                ["Dependent clients", radius.dependent_clients, radius.clients_pct],
                ["Servers", radius.servers.length, radius.servers_pct],
              ].map(([label, n, pct]) => (
                <div key={label as string} className="space-y-1">
                  <div className="flex justify-between text-xs">
                    <span>{label}</span>
                    <span className="tabular text-muted-foreground">
                      {n} · {pct}%
                    </span>
                  </div>
                  <Meter value={pct as number} color={sevColor(radius.severity)} />
                </div>
              ))}
            </div>
          )}
          <div className="flex flex-wrap gap-2">
            {node.type === "server" && (
              <Button asChild size="sm" variant="outline">
                <Link to={`/c/${captureId}/sessions?server=${encodeURIComponent(node.label)}`}>View sessions</Link>
              </Button>
            )}
            {radius?.finding_refs.map((ref) => (
              <Button key={ref} asChild size="sm" variant="outline">
                <Link to={`/c/${captureId}/findings/${ref}`}>Open {ref}</Link>
              </Button>
            ))}
          </div>
        </div>
      </SheetContent>
    </Sheet>
  );
}

export function OverviewPage() {
  const { captureId } = useParams();
  const navigate = useNavigate();
  const overview = useOverview(captureId);
  const posture = usePosture(captureId);
  const graph = useGraph(captureId);
  const sessions = useSessions(captureId);
  const priorities = usePriorities(captureId);
  const risk = useRisk(captureId);
  const [selected, setSelected] = useState<GraphNode | null>(null);

  if (overview.error) return <ErrorState error={overview.error} />;
  if (!overview.data || !posture.data) return <Loading rows={4} />;

  const o = overview.data;
  const p = posture.data.posture;
  const pqc = posture.data.pqc_readiness;
  const sev = o.findings.by_severity;
  const critical = sev.CRITICAL ?? 0;
  const failing = (priorities.data ?? []).filter((f) => f.verdict === "FAIL");
  const actionable = Object.entries(sev).filter(([s]) => s !== "INFO").reduce((a, [, n]) => a + n, 0);

  return (
    <>
      <StatStrip
        items={[
          {
            label: "Posture score",
            value: (
              <span>
                <span>{p.overall ?? "—"}</span>
                <span className="text-sm font-normal text-muted-foreground"> / 100</span>
              </span>
            ),
            sub: critical ? `${scoreLabel(p.overall, critical)} · ${critical} critical` : scoreLabel(p.overall),
            info: p.note,
          },
          {
            label: "PQC readiness",
            value: (
              <span>
                {pqc.score ?? "—"}
                <span className="text-sm font-normal text-muted-foreground"> / 100</span>
              </span>
            ),
            sub: `${pqc.level_label ?? "Not assessable"} · ${pqc.hndl_exposed_pct ?? 0}% HNDL-exposed`,
            info: pqc.framing,
          },
          {
            label: "Encrypted sessions",
            value: `${o.sessions.protected} / ${o.sessions.total}`,
            sub: `${fmtPct(o.sessions.total ? (100 * o.sessions.protected) / o.sessions.total : null, 1)} · ${o.sessions.cleartext} cleartext`,
          },
          {
            label: "Findings",
            value: actionable,
            sub: `${critical} critical · ${sev.HIGH ?? 0} high · ${sev.MEDIUM ?? 0} medium`,
            accent: critical ? "hsl(var(--sev-critical))" : undefined,
          },
          {
            label: "Risk index",
            value: risk.data?.index ? Math.round(risk.data.index.index) : "—",
            sub: risk.data?.index ? `${risk.data.index.distribution.critical} critical · ${risk.data.index.distribution.high} high sessions` : "Model unavailable",
            info: "Session risk classifier (gradient-boosted trees). 0.6 × mean of the riskiest 10% of sessions + 0.4 × mean of all sessions.",
          },
          {
            label: "Certificate coverage",
            value: fmtPct(o.coverage.certificate_coverage_pct),
            sub: `${o.coverage.certificate_observable} of ${o.coverage.tls_sessions} TLS sessions`,
            info: o.coverage.note,
          },
        ]}
      />

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_340px]">
        <Panel title="Infrastructure" info="Clients, mail servers, negotiated cryptographic primitives and weaknesses observed in the capture. Select a node for detail." flush>
          {graph.data ? (
            <Topology graph={graph.data} height={430} selectedId={selected?.id} onSelect={setSelected} className="rounded-none border-0" />
          ) : (
            <Loading rows={1} className="p-4" />
          )}
        </Panel>
        <Panel title="Posture breakdown" info={`${p.calculation.formula}. Severe findings cap their dimension.`}>
          <PostureDimensions dimensions={p.dimensions} />
        </Panel>
      </div>

      <div className="grid gap-5 xl:grid-cols-2">
        <Panel
          title="Priority findings"
          flush
          actions={
            <Button asChild variant="ghost" size="sm" className="h-7 text-xs">
              <Link to={`/c/${captureId}/findings`}>
                View all <ArrowRight className="size-3" />
              </Link>
            </Button>
          }
        >
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="h-9 w-20 pl-4 text-xs">Priority</TableHead>
                <TableHead className="h-9 w-28 text-xs">Severity</TableHead>
                <TableHead className="h-9 text-xs">Finding</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {failing.slice(0, 6).map((f) => (
                <TableRow key={f.ref} className="cursor-pointer" onClick={() => navigate(`/c/${captureId}/findings/${f.ref}`)}>
                  <TableCell className="pl-4">
                    <TierBadge tier={f.tier} score={f.priority} />
                  </TableCell>
                  <TableCell>
                    <SeverityBadge severity={f.severity} />
                  </TableCell>
                  <TableCell>
                    <div className="truncate font-medium">{f.title}</div>
                    <div className="font-mono text-[11px] text-muted-foreground">
                      {f.ref}
                      {f.session_ref ? ` · ${f.session_ref}` : ""}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
              {!failing.length && (
                <TableRow className="hover:bg-transparent">
                  <TableCell colSpan={3} className="h-20 text-center text-sm text-muted-foreground">
                    No findings require action.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </Panel>

        <Panel title="Traffic">
          <Tabs defaultValue="timeline">
            <TabsList className="h-8">
              <TabsTrigger value="timeline" className="text-xs">
                Timeline
              </TabsTrigger>
              <TabsTrigger value="flow" className="text-xs">
                Encryption outcome
              </TabsTrigger>
            </TabsList>
            <TabsContent value="timeline" className="mt-4">
              {sessions.data ? <SessionTimeline captureId={captureId!} sessions={sessions.data} /> : <Loading rows={1} />}
            </TabsContent>
            <TabsContent value="flow" className="mt-4">
              {sessions.data ? <OutcomeFlow sessions={sessions.data} height={260} /> : <Loading rows={1} />}
            </TabsContent>
          </Tabs>
        </Panel>
      </div>

      {risk.data && risk.data.sessions.length > 0 && (
        <Panel
          title="Highest-risk sessions"
          info="Classified by the SecureMailScope risk model. Principal factors are Shapley attributions in severity levels above the session's healthy baseline."
          flush
          actions={
            <Button asChild variant="ghost" size="sm" className="h-7 text-xs">
              <Link to={`/c/${captureId}/sessions`}>
                All sessions <ArrowRight className="size-3" />
              </Link>
            </Button>
          }
        >
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="h-9 pl-4 text-xs">Session</TableHead>
                <TableHead className="h-9 text-xs">Server</TableHead>
                <TableHead className="h-9 text-xs">Encryption</TableHead>
                <TableHead className="h-9 text-xs">Risk</TableHead>
                <TableHead className="h-9 text-xs">Principal factor</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {risk.data.sessions.slice(0, 5).map((r) => (
                <TableRow key={r.ref} className="cursor-pointer" onClick={() => navigate(`/c/${captureId}/sessions/${r.ref}`)}>
                  <TableCell className="pl-4 font-mono text-xs">{r.ref}</TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">{r.server}</TableCell>
                  <TableCell>
                    <StateBadge state={r.encryption_state} />
                  </TableCell>
                  <TableCell>
                    <RiskBadge risk={r.risk_class} score={r.score} />
                  </TableCell>
                  <TableCell className="text-sm">
                    {r.drivers[0] ? (
                      <>
                        {r.drivers[0].label} <span className="tabular text-muted-foreground">+{r.drivers[0].impact.toFixed(2)}</span>
                      </>
                    ) : (
                      <span className="text-muted-foreground">None above baseline</span>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Panel>
      )}

      <NodeSheet node={selected} graph={graph.data} captureId={captureId!} onClose={() => setSelected(null)} />
    </>
  );
}
