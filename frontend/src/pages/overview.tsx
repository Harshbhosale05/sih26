import { ArrowRight, Download, FileWarning, Loader2, Lock, RefreshCw, ShieldAlert, Unlock, Waypoints } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { toast } from "sonner";

import {
  CopyButton,
  ErrorState,
  KeyValue,
  Loading,
  Meter,
  PageHeader,
  Panel,
  RiskBadge,
  SeverityBadge,
  Stat,
  TierBadge,
} from "@/components/common";
import { ScoreGauge } from "@/components/score-gauge";
import { Button } from "@/components/ui/button";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { OutcomeFlow } from "@/components/viz/outcome-flow";
import { PostureDimensions } from "@/components/viz/posture-dimensions";
import { SessionTimeline } from "@/components/viz/timeline";
import { Topology } from "@/components/viz/topology";
import {
  exportUrl,
  useAnalyze,
  useGraph,
  useOverview,
  usePosture,
  usePriorities,
  useRisk,
  useSessions,
  useSoftware,
  useStarttls,
} from "@/lib/api";
import { SEVERITIES, fmtDate, fmtDuration, fmtNum, fmtPct, riskColor, scoreColor, scoreLabel, sevColor, shortHash } from "@/lib/format";
import type { GraphData, GraphNode } from "@/lib/types";

function SeverityStrip({ bySeverity }: { bySeverity: Record<string, number> }) {
  const total = SEVERITIES.reduce((a, s) => a + (bySeverity[s] ?? 0), 0) || 1;
  return (
    <div className="space-y-2">
      <div className="flex h-2 overflow-hidden rounded-full bg-muted">
        {SEVERITIES.map((s) => (
          <div key={s} style={{ width: `${(100 * (bySeverity[s] ?? 0)) / total}%`, background: sevColor(s) }} />
        ))}
      </div>
      <div className="grid grid-cols-5 gap-1 text-center">
        {SEVERITIES.map((s) => (
          <div key={s}>
            <div className="tabular text-base font-semibold" style={{ color: (bySeverity[s] ?? 0) ? sevColor(s) : undefined }}>
              {bySeverity[s] ?? 0}
            </div>
            <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{s.toLowerCase()}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function NodeDetail({ node, graph, captureId }: { node: GraphNode; graph: GraphData; captureId: string }) {
  const { data: software } = useSoftware(captureId);
  const m = node.metrics as Record<string, unknown>;
  const radius = graph.blast_radius.find((r) => r.node === node.id);

  if (node.type === "server") {
    const sw = software?.find((s) => s.server === node.label);
    const entry = graph.servers.find((s) => s.node === node.id);
    return (
      <div className="space-y-4">
        <KeyValue
          rows={[
            ["Server", <span className="font-mono">{node.label}</span>],
            ["Software", sw ? `${sw.name}${sw.version ? ` ${sw.version}` : ""}` : "—"],
            ["Identified from", sw ? <span className="font-mono text-xs">{sw.evidence}</span> : "—"],
            ["Sessions", `${m.sessions} (${m.cleartext} cleartext)`],
            ["Clients", String(m.clients)],
          ]}
        />
        {entry && entry.weaknesses.length > 0 && (
          <div className="space-y-1.5">
            <div className="text-xs font-medium text-muted-foreground">Weaknesses on this server</div>
            {entry.weaknesses.map((w) => (
              <div key={w} className="rounded-md border px-2 py-1 text-xs">
                {w.replace(/_/g, " ")}
              </div>
            ))}
          </div>
        )}
        <Button asChild size="sm" variant="outline" className="w-full">
          <Link to={`/c/${captureId}/sessions?server=${encodeURIComponent(node.label)}`}>
            Sessions on this server <ArrowRight className="size-3.5" />
          </Link>
        </Button>
      </div>
    );
  }

  if (node.type === "weakness" && radius) {
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <SeverityBadge severity={radius.severity} />
          <span className="text-sm font-medium">{node.label}</span>
        </div>
        <div className="space-y-2">
          <div className="text-xs font-medium text-muted-foreground">Blast radius (observed environment)</div>
          {[
            ["Direct sessions", radius.direct_sessions, radius.direct_pct],
            ["Dependent sessions", radius.dependent_sessions, radius.dependent_pct],
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
          <div className="text-xs text-muted-foreground">Blast score {radius.blast_score}</div>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {radius.finding_refs.map((ref) => (
            <Button key={ref} asChild size="sm" variant="outline" className="h-7 text-xs">
              <Link to={`/c/${captureId}/findings/${ref}`}>
                Trace {ref} <ArrowRight className="size-3" />
              </Link>
            </Button>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <KeyValue
        rows={[
          ["Node", <span className="font-mono">{node.label}</span>],
          ["Type", node.sub ?? node.type],
          ...Object.entries(m)
            .filter(([, v]) => typeof v === "number")
            .map(([k, v]) => [k.replace(/_/g, " "), String(v)] as [string, string]),
        ]}
      />
      {radius && (
        <div className="text-xs text-muted-foreground">
          Used by {radius.direct_sessions} session(s) across {radius.servers.length} server(s) · blast score {radius.blast_score}
        </div>
      )}
    </div>
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
  const starttls = useStarttls(captureId);
  const analyze = useAnalyze();
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [timelineColor, setTimelineColor] = useState<"state" | "risk">("state");

  if (overview.error) return <ErrorState error={overview.error} />;
  if (!overview.data || !posture.data) return <Loading rows={4} />;

  const o = overview.data;
  const p = posture.data.posture;
  const pqc = posture.data.pqc_readiness;
  const critical = o.findings.by_severity.CRITICAL ?? 0;
  const failing = (priorities.data ?? []).filter((f) => f.verdict === "FAIL");

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow={`${o.capture.ref} · assessment`}
        title={o.capture.filename}
        description={
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <span>{fmtNum(o.capture.packet_count)} packets</span>
            <span>{fmtDuration(o.capture.duration_seconds)} of traffic</span>
            <span>{fmtDate(o.capture.first_packet_at)}</span>
            <span className="flex items-center gap-1 font-mono text-xs">
              sha256 {shortHash(o.capture.sha256, 16)} <CopyButton text={o.capture.sha256} className="size-6" />
            </span>
          </span>
        }
        actions={
          <>
            <Button
              variant="outline"
              size="sm"
              disabled={analyze.isPending}
              onClick={() =>
                analyze.mutate(captureId!, {
                  onSuccess: () => toast.success("Re-analysed with the current rules and model"),
                  onError: (e) => toast.error("Analysis failed", { description: String(e) }),
                })
              }
            >
              {analyze.isPending ? <Loader2 className="size-3.5 animate-spin" /> : <RefreshCw className="size-3.5" />}
              Re-analyse
            </Button>
            <Button asChild size="sm" variant="outline">
              <a href={exportUrl(captureId!, "report.pdf")}>
                <Download className="size-3.5" /> PDF report
              </a>
            </Button>
            <Button asChild size="sm">
              <Link to={`/c/${captureId}/remediation`}>
                Fix simulator <ArrowRight className="size-3.5" />
              </Link>
            </Button>
          </>
        }
      />

      <div className="grid gap-4 xl:grid-cols-[320px_1fr]">
        <Panel title="Cryptographic posture" description={p.note}>
          <div className="flex flex-col items-center gap-2 pb-2">
            <ScoreGauge score={p.overall} size={210} label={scoreLabel(p.overall, critical)} />
            {critical > 0 && (
              <div className="flex items-center gap-1.5 text-xs font-medium text-sev-critical">
                <ShieldAlert className="size-3.5" />
                {critical} critical finding{critical > 1 ? "s cap" : " caps"} the score
              </div>
            )}
          </div>
          <PostureDimensions dimensions={p.dimensions} />
        </Panel>

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 2xl:grid-cols-6">
            <Stat
              label="Email sessions"
              value={o.sessions.total}
              sub={Object.entries(o.sessions.by_protocol).map(([k, v]) => `${k} ${v}`).join(" · ")}
              icon={<Waypoints className="size-4" />}
            />
            <Stat
              label="Encrypted"
              value={fmtPct(o.sessions.total ? (100 * o.sessions.protected) / o.sessions.total : null)}
              color={o.sessions.cleartext ? "hsl(var(--sev-high))" : "hsl(var(--sev-ok))"}
              sub={`${o.sessions.protected} TLS · ${o.sessions.cleartext} cleartext · ${o.sessions.indeterminate} unknown`}
              icon={o.sessions.cleartext ? <Unlock className="size-4" /> : <Lock className="size-4" />}
            />
            <Stat
              label="Risk index (model)"
              value={risk.data?.index ? Math.round(risk.data.index.index) : "—"}
              color={risk.data?.index ? scoreColor(100 - risk.data.index.index) : undefined}
              sub={risk.data?.index ? `${risk.data.index.distribution.critical} critical · ${risk.data.index.distribution.high} high sessions` : "model not available"}
            />
            <Stat label="STARTTLS adoption" value={fmtPct(starttls.data?.summary.adoption_pct, 1)} sub={`${starttls.data?.summary.upgraded ?? 0} of ${starttls.data?.summary.observable ?? 0} upgraded`} />
            <Stat label="PQC readiness" value={pqc.score ?? "—"} color={scoreColor(pqc.score)} sub={pqc.level_label ?? "not assessable"} />
            <Stat label="Certificate coverage" value={fmtPct(o.coverage.certificate_coverage_pct)} sub={`${o.coverage.certificate_observable} of ${o.coverage.tls_sessions} TLS sessions`} icon={<FileWarning className="size-4" />} />
          </div>

          <Panel
            title="Infrastructure map"
            description="Every observed client, mail server, negotiated primitive and weakness — hover to trace dependencies, click for detail."
            contentClassName="grid gap-4 lg:grid-cols-[1fr_280px]"
          >
            {graph.data ? (
              <Topology graph={graph.data} height={470} selectedId={selected?.id} onSelect={setSelected} />
            ) : (
              <Loading rows={1} />
            )}
            <div className="rounded-lg border p-3">
              {selected && graph.data ? (
                <NodeDetail node={selected} graph={graph.data} captureId={captureId!} />
              ) : (
                <div className="space-y-4">
                  <div className="text-sm font-medium">Findings by severity</div>
                  <SeverityStrip bySeverity={o.findings.by_severity} />
                  <div className="text-xs text-muted-foreground">
                    {o.findings.total} findings · {o.findings.unknown_verdicts} undetermined by the evidence. Select a node on the map to inspect it.
                  </div>
                  {graph.data && (
                    <div className="space-y-1.5">
                      <div className="text-xs font-medium text-muted-foreground">Widest blast radius</div>
                      {graph.data.blast_radius.slice(0, 4).map((r) => (
                        <button
                          key={r.key}
                          onClick={() => setSelected(graph.data!.nodes.find((n) => n.id === r.node) ?? null)}
                          className="flex w-full items-center gap-2 rounded-md px-1.5 py-1 text-left text-xs hover:bg-muted"
                        >
                          <span className="size-2 shrink-0 rounded-full" style={{ background: sevColor(r.severity) }} />
                          <span className="min-w-0 flex-1 truncate">{r.title}</span>
                          <span className="tabular text-muted-foreground">{r.blast_score}</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </Panel>
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.25fr_1fr]">
        <Panel title="Where the sessions went" description="Protocol → how the session ended up → negotiated TLS version. Band width is session count.">
          {sessions.data ? <OutcomeFlow sessions={sessions.data} /> : <Loading rows={1} />}
        </Panel>
        <Panel
          title="Fix first"
          description="Findings ranked by priority: severity, exposure, blast radius, model risk."
          actions={
            <Button asChild variant="ghost" size="sm" className="h-7 text-xs">
              <Link to={`/c/${captureId}/findings`}>
                All findings <ArrowRight className="size-3" />
              </Link>
            </Button>
          }
        >
          <div className="space-y-1">
            {failing.slice(0, 6).map((f) => (
              <button
                key={f.ref}
                onClick={() => navigate(`/c/${captureId}/findings/${f.ref}`)}
                className="flex w-full items-center gap-3 rounded-md px-2 py-2 text-left hover:bg-muted/60"
              >
                <TierBadge tier={f.tier} />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-medium">{f.title}</div>
                  <div className="text-[11px] text-muted-foreground">
                    <span className="font-mono">{f.ref}</span>
                    {f.session_ref && <span className="font-mono"> · {f.session_ref}</span>} · priority {Math.round(f.priority)}
                  </div>
                </div>
                <SeverityBadge severity={f.severity} />
              </button>
            ))}
            {!failing.length && <div className="py-6 text-center text-sm text-muted-foreground">No failing findings in this capture.</div>}
          </div>
        </Panel>
      </div>

      <Panel
        title="Session timeline"
        description="One bar per session, one lane per server. Click a bar to open the reconstructed session."
        actions={
          <ToggleGroup type="single" value={timelineColor} onValueChange={(v) => v && setTimelineColor(v as "state" | "risk")} variant="outline" size="sm">
            <ToggleGroupItem value="state" className="h-7 px-2.5 text-xs">
              Encryption
            </ToggleGroupItem>
            <ToggleGroupItem value="risk" className="h-7 px-2.5 text-xs">
              Model risk
            </ToggleGroupItem>
          </ToggleGroup>
        }
      >
        {sessions.data ? <SessionTimeline captureId={captureId!} sessions={sessions.data} colorBy={timelineColor} /> : <Loading rows={1} />}
        {timelineColor === "risk" && (
          <div className="mt-2 flex flex-wrap gap-3 text-[11px] text-muted-foreground">
            {["critical", "high", "medium", "low", "minimal"].map((r) => (
              <span key={r} className="flex items-center gap-1">
                <span className="size-2 rounded-sm" style={{ background: riskColor(r) }} />
                {r}
              </span>
            ))}
          </div>
        )}
      </Panel>

      {risk.data && risk.data.sessions.length > 0 && (
        <Panel title="Riskiest sessions (our model)" description="Gradient-boosted classifier over observed facts; drivers are exact Shapley attributions.">
          <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
            {risk.data.sessions.slice(0, 6).map((r) => (
              <Link key={r.ref} to={`/c/${captureId}/sessions/${r.ref}`} className="rounded-lg border p-3 hover:bg-muted/40">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-sm font-medium">{r.ref}</span>
                  <RiskBadge risk={r.risk_class} score={r.score} />
                </div>
                <div className="mt-1 font-mono text-[11px] text-muted-foreground">{r.server}</div>
                <div className="mt-2 space-y-0.5">
                  {r.drivers.slice(0, 2).map((d) => (
                    <div key={d.feature} className="flex justify-between text-xs">
                      <span className="truncate">{d.label}</span>
                      <span className="tabular text-sev-critical">+{d.impact.toFixed(2)}</span>
                    </div>
                  ))}
                  {!r.drivers.length && <div className="text-xs text-muted-foreground">No risk factor above the healthy baseline</div>}
                </div>
              </Link>
            ))}
          </div>
        </Panel>
      )}
    </div>
  );
}
