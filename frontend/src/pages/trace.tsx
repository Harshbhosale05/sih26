import { motion } from "framer-motion";
import {
  ArrowRight,
  Binary,
  BookCheck,
  CheckCircle2,
  Download,
  FileArchive,
  Gauge,
  Hash,
  Layers,
  ListTree,
  Route,
  Scale,
  ShieldCheck,
  Wrench,
} from "lucide-react";
import { useState, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";

import {
  CodeLine,
  CopyButton,
  Empty,
  ErrorState,
  KeyValue,
  Loading,
  Meter,
  PageHeader,
  Panel,
  SeverityBadge,
  StateBadge,
  TierBadge,
  VerdictBadge,
} from "@/components/common";
import { PlaybookView } from "@/components/config-diff";
import { SimulationView } from "@/components/simulation-view";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Ladder } from "@/components/viz/ladder";
import { RiskDrivers } from "@/components/viz/risk-drivers";
import { StatePath } from "@/components/viz/state-path";
import { findingPcapUrl, useTrace } from "@/lib/api";
import { categoryLabel, scoreColor, sevColor, shortHash } from "@/lib/format";
import type { Trace } from "@/lib/types";
import { cn } from "@/lib/utils";

type TabKey = "evidence" | "reasoning" | "fix" | "after";

interface ChainStep {
  icon: typeof Hash;
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  tab: TabKey;
  color?: string;
}

function chainOf(t: Trace): ChainStep[] {
  const s = t.session;
  const frames = t.explanation.verification.evidence_frames;
  const obs = t.explanation.observations;
  const fix = t.fixes[0];
  const proj = t.projection;
  return [
    { icon: FileArchive, label: "Evidence", value: t.capture.ref, sub: <span className="font-mono">sha256 {shortHash(t.capture.sha256, 10)}</span>, tab: "evidence" },
    { icon: Layers, label: "TCP stream", value: s ? `stream ${s.stream_index}` : "capture-wide", sub: s ? <span className="font-mono">{s.client} → {s.server}</span> : "cross-session evidence", tab: "evidence" },
    { icon: Binary, label: "Frames", value: frames.length ? `#${frames.slice(0, 3).join(", #")}${frames.length > 3 ? "…" : ""}` : "—", sub: s ? `session #${s.first_frame}–#${s.last_frame}` : `${frames.length} cited`, tab: "evidence" },
    { icon: ListTree, label: "Protocol evidence", value: `${obs.length} event${obs.length === 1 ? "" : "s"}`, sub: <span className="font-mono">{obs[0]?.detail?.slice(0, 26) ?? "—"}</span>, tab: "evidence" },
    { icon: Route, label: "Encryption state", value: s ? <StateBadge state={s.encryption_state} /> : "—", sub: s ? `${s.state_transitions.length} transitions` : undefined, tab: "evidence" },
    { icon: BookCheck, label: "Rule", value: <span className="font-mono text-xs">{t.finding.category}</span>, sub: t.finding.standard_refs.slice(0, 2).join(" · ") || "policy.json", tab: "reasoning" },
    {
      icon: Scale,
      label: "Verdict",
      value: (
        <span className="flex items-center gap-1.5">
          <VerdictBadge verdict={t.finding.verdict} /> <SeverityBadge severity={t.finding.severity} />
        </span>
      ),
      sub: `${Math.round(t.finding.confidence * 100)}% confidence · ${t.finding.detection_method}`,
      tab: "reasoning",
      color: sevColor(t.finding.severity),
    },
    {
      icon: Gauge,
      label: "Priority",
      value: t.priority ? (
        <span className="flex items-center gap-1.5">
          <TierBadge tier={t.priority.tier} /> <span className="tabular">{Math.round(t.priority.priority)}</span>
        </span>
      ) : (
        "—"
      ),
      sub: t.priority?.tier_label,
      tab: "reasoning",
    },
    {
      icon: Wrench,
      label: "Fix",
      value: fix ? <span className="line-clamp-2 text-xs font-medium">{fix.title}</span> : "evidence action",
      sub: fix ? `${(proj?.applied_fixes?.length ?? 1) > 1 ? `+${proj!.applied_fixes!.length - 1} more · ` : ""}${fix.software.name ?? "generic"}` : undefined,
      tab: "fix",
    },
    {
      icon: ShieldCheck,
      label: "After fix",
      value: proj ? (
        <span className="tabular flex items-center gap-1.5 text-sm font-semibold">
          <span style={{ color: scoreColor(proj.posture.before.overall) }}>{proj.posture.before.overall}</span>
          <ArrowRight className="size-3 text-muted-foreground" />
          <span style={{ color: scoreColor(proj.posture.after.overall) }}>{proj.posture.after.overall}</span>
        </span>
      ) : (
        "—"
      ),
      sub: proj ? (proj.fixed_this_finding ? "this finding resolved" : "finding persists") : "no projection",
      tab: "after",
      color: proj?.fixed_this_finding ? "hsl(var(--sev-ok))" : undefined,
    },
  ];
}

function EvidenceChain({ steps, active, onSelect }: { steps: ChainStep[]; active: TabKey; onSelect: (t: TabKey) => void }) {
  return (
    <div className="overflow-x-auto pb-1">
      <div className="flex min-w-[1080px] items-stretch">
        {steps.map((s, i) => (
          <div key={s.label} className="flex min-w-0 flex-1 items-stretch">
            <motion.button
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.06 }}
              onClick={() => onSelect(s.tab)}
              className={cn(
                "flex min-w-0 flex-1 flex-col gap-1.5 overflow-hidden rounded-lg border bg-card p-2.5 text-left transition-colors hover:bg-muted/50",
                active === s.tab && "border-primary/60 bg-primary/5",
              )}
              style={s.color ? { borderTopColor: s.color, borderTopWidth: 2 } : undefined}
            >
              <div className="flex items-center gap-1.5 text-[10.5px] font-medium uppercase tracking-wider text-muted-foreground">
                <s.icon className="size-3.5" />
                {s.label}
              </div>
              <div className="min-h-[20px] truncate text-sm font-medium">{s.value}</div>
              {s.sub && <div className="truncate text-[10.5px] text-muted-foreground">{s.sub}</div>}
            </motion.button>
            {i < steps.length - 1 && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.06 + 0.1 }} className="flex shrink-0 items-center px-0.5">
                <div className="h-px w-2 bg-border" />
                <ArrowRight className="-ml-1 size-3 text-muted-foreground" />
              </motion.div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function renderValue(v: unknown): ReactNode {
  if (v == null) return "—";
  if (typeof v === "boolean") return v ? "yes" : "no";
  if (Array.isArray(v) && v.every((x) => typeof x !== "object")) return <span className="font-mono text-xs">{v.join(", ")}</span>;
  if (typeof v === "object")
    return <pre className="max-h-48 overflow-auto rounded bg-muted/50 p-2 font-mono text-[11px]">{JSON.stringify(v, null, 2)}</pre>;
  return <span className="font-mono text-xs">{String(v)}</span>;
}

export function TracePage() {
  const { captureId, ref } = useParams();
  const { data: t, error, isLoading } = useTrace(captureId, ref);
  const [tab, setTab] = useState<TabKey>("evidence");

  if (error) return <ErrorState error={error} />;
  if (isLoading || !t) return <Loading rows={4} />;

  const e = t.explanation;
  const s = t.session;
  const applied = t.projection?.applied_fixes ?? t.fixes.slice(0, 1).map((f) => f.id);

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow={
          <span className="flex items-center gap-2">
            <span className="font-mono">{t.finding.ref}</span> · {categoryLabel(t.finding.category)}
          </span>
        }
        title={
          <span className="flex flex-wrap items-center gap-2">
            {t.finding.title}
            <SeverityBadge severity={t.finding.severity} />
            {t.priority && <TierBadge tier={t.priority.tier} />}
          </span>
        }
        description={t.finding.description}
        actions={
          <>
            {e.verification.wireshark_filter && <CopyButton text={e.verification.wireshark_filter} label="Wireshark filter" className="h-8 border" />}
            <Button asChild size="sm" variant="outline">
              <a href={findingPcapUrl(captureId!, t.finding.ref)}>
                <Download className="size-3.5" /> Evidence slice (.pcapng)
              </a>
            </Button>
          </>
        }
      />

      <Panel title="Traceability chain" description="From the bytes in the capture to the change that fixes it. Click any link to inspect it.">
        <EvidenceChain steps={chainOf(t)} active={tab} onSelect={setTab} />
      </Panel>

      <Tabs value={tab} onValueChange={(v) => setTab(v as TabKey)}>
        <TabsList>
          <TabsTrigger value="evidence">1 · Evidence</TabsTrigger>
          <TabsTrigger value="reasoning">2 · Reasoning</TabsTrigger>
          <TabsTrigger value="fix">3 · Recommended fix</TabsTrigger>
          <TabsTrigger value="after">4 · After the fix</TabsTrigger>
        </TabsList>

        <TabsContent value="evidence" className="space-y-4">
          {s ? (
            <>
              <Panel title="Encryption state path" description="The state machine path this session took, with the frame that caused each transition.">
                <StatePath transitions={s.state_transitions} finalState={s.encryption_state} />
              </Panel>
              <Panel
                title={`Reconstructed session ${s.ref}`}
                description="Every protocol event in order. Frames cited as evidence for this finding are outlined."
                actions={
                  <Button asChild variant="ghost" size="sm" className="h-7 text-xs">
                    <Link to={`/c/${captureId}/sessions/${s.ref}`}>
                      Full session <ArrowRight className="size-3" />
                    </Link>
                  </Button>
                }
              >
                <Ladder
                  events={s.events}
                  transitions={s.state_transitions}
                  client={s.client}
                  server={s.server}
                  firstFrame={s.first_frame}
                  lastFrame={s.last_frame}
                  implicit={s.encryption_state === "IMPLICIT_TLS"}
                  highlight={e.verification.evidence_frames}
                  tls={{ version: s.tls_version, cipher: s.tls_cipher_suite }}
                />
              </Panel>
            </>
          ) : (
            <Panel title="Capture-level evidence" description="This finding is about the observed environment rather than one session.">
              <div className="space-y-2">
                {e.observations.map((o, i) => (
                  <div key={i} className="flex gap-3 text-sm">
                    <span className="font-mono text-xs text-muted-foreground">#{o.frame}</span>
                    <span>{o.detail}</span>
                  </div>
                ))}
              </div>
            </Panel>
          )}
          <div className="grid gap-4 lg:grid-cols-2">
            <Panel title="Observed facts" description="Values extracted from the capture that the rule evaluated.">
              <KeyValue rows={e.facts.map((f) => [f.label, renderValue(f.value)])} />
            </Panel>
            <Panel title="Verify it yourself" description={e.verification.how}>
              <div className="space-y-3">
                {e.verification.wireshark_filter && (
                  <div className="space-y-1">
                    <div className="text-xs text-muted-foreground">Wireshark display filter</div>
                    <CodeLine>{e.verification.wireshark_filter}</CodeLine>
                  </div>
                )}
                <div className="space-y-1">
                  <div className="text-xs text-muted-foreground">Parent capture SHA-256</div>
                  <CodeLine>{e.verification.capture_sha256}</CodeLine>
                </div>
                <div className="text-xs text-muted-foreground">
                  Evidence frames: <span className="font-mono">{e.verification.evidence_frames.join(", ") || "—"}</span>
                </div>
              </div>
            </Panel>
          </div>
        </TabsContent>

        <TabsContent value="reasoning" className="space-y-4">
          <div className="grid gap-4 lg:grid-cols-[1.2fr_1fr]">
            <Panel title="Why this is the conclusion" description="Each step traced to a stored fact, a published rule or a score term — no language model involved.">
              <ol className="relative space-y-4 border-l pl-5">
                {e.chain.map((c, i) => (
                  <li key={i} className="relative">
                    <span className="absolute -left-[27px] top-0.5 grid size-4 place-items-center rounded-full border bg-background text-[9px] font-semibold">{i + 1}</span>
                    <div className="text-sm font-medium">{c.title}</div>
                    <div className="text-sm text-muted-foreground">{c.text}</div>
                  </li>
                ))}
              </ol>
            </Panel>
            <div className="space-y-4">
              {t.priority && (
                <Panel title={`Priority ${t.priority.priority.toFixed(1)} · ${t.priority.tier} ${t.priority.tier_label}`} description="How the queue position was reached.">
                  <div className="space-y-2">
                    {t.priority.factors.map((f) => (
                      <div key={f.factor} className="space-y-1">
                        <div className="flex justify-between text-xs">
                          <span>{f.factor}</span>
                          <span className="tabular font-medium">{f.points ? `+${f.points}` : ""}</span>
                        </div>
                        <Meter value={f.points * 2} color={f.source === "ml" ? "hsl(var(--chart-3))" : "hsl(var(--primary))"} />
                        <div className="text-[11px] text-muted-foreground">{f.detail}</div>
                      </div>
                    ))}
                  </div>
                </Panel>
              )}
              {e.posture_impact.length > 0 && (
                <Panel title="Effect on the posture score">
                  {e.posture_impact.map((p) => (
                    <div key={p.dimension} className="text-sm">
                      {p.text}
                    </div>
                  ))}
                </Panel>
              )}
              {e.limits.length > 0 && (
                <Panel title="Limits of the evidence">
                  <ul className="list-disc space-y-1 pl-4 text-sm text-muted-foreground">
                    {e.limits.map((l) => (
                      <li key={l}>{l}</li>
                    ))}
                  </ul>
                </Panel>
              )}
            </div>
          </div>
          {s?.risk && (
            <Panel title="Our risk model on this session" description="Context, not verdict: how the classifier grades the session and which factors drive it.">
              <RiskDrivers risk={s.risk} />
            </Panel>
          )}
        </TabsContent>

        <TabsContent value="fix" className="space-y-4">
          {t.fixes.length ? (
            t.fixes.map((f, i) => (
              <Panel
                key={f.id}
                title={
                  <span className="flex items-center gap-2">
                    {applied.includes(f.id) ? (applied.length > 1 ? `Required fix ${applied.indexOf(f.id) + 1} of ${applied.length}` : "Recommended") : "Alternative"} · {f.title}
                  </span>
                }
                description={`${f.owner} · ${f.effort_label} · target ${f.target.host}:${f.target.port}`}
                actions={
                  i === applied.length - 1 && (
                    <Button size="sm" onClick={() => setTab("after")}>
                      See the effect <ArrowRight className="size-3.5" />
                    </Button>
                  )
                }
              >
                <PlaybookView playbook={f} />
              </Panel>
            ))
          ) : (
            <Empty title="No configuration fix applies">{t.evidence_action ?? "This finding records a limit of the evidence rather than a server fault."}</Empty>
          )}
          {t.evidence_action && t.fixes.length > 0 && (
            <div className="rounded-lg border p-3 text-sm text-muted-foreground">
              <b className="text-foreground">Improve the evidence:</b> {t.evidence_action}
            </div>
          )}
        </TabsContent>

        <TabsContent value="after">
          {t.projection ? (
            <div className="space-y-3">
              <div
                className={cn(
                  "flex items-center gap-2 rounded-lg border p-3 text-sm",
                  t.projection.fixed_this_finding ? "border-sev-ok/40 bg-sev-ok/5" : "border-sev-medium/40 bg-sev-medium/5",
                )}
              >
                <CheckCircle2 className={cn("size-4", t.projection.fixed_this_finding ? "text-sev-ok" : "text-sev-medium")} />
                {t.projection.fixed_this_finding
                  ? `Applying ${applied.length > 1 ? `these ${applied.length} fixes together` : `“${t.fixes[0]?.title}”`} to ${t.scope.join(", ") || "the affected servers"} resolves ${t.finding.ref}${applied.length > 1 ? " — neither alone is enough" : ""}.`
                  : `This fix alone does not clear ${t.finding.ref} — see the remaining findings below, or combine fixes in the simulator.`}
                <Button asChild size="sm" variant="ghost" className="ml-auto h-7 text-xs">
                  <Link to={`/c/${captureId}/remediation`}>
                    Combine fixes <ArrowRight className="size-3" />
                  </Link>
                </Button>
              </div>
              <SimulationView sim={t.projection} captureId={captureId!} compactGraph />
            </div>
          ) : (
            <Empty title="Nothing to project">Only failing findings with a configuration fix can be simulated.</Empty>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
