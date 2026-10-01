import { ArrowRight, CheckCircle2, CircleDot, Download } from "lucide-react";
import { useState, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";

import {
  CodeLine,
  CopyButton,
  Empty,
  ErrorState,
  Loading,
  Panel,
  Properties,
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
import { categoryLabel, scoreColor, shortHash } from "@/lib/format";
import type { Trace } from "@/lib/types";
import { cn } from "@/lib/utils";

type TabKey = "evidence" | "analysis" | "remediation" | "after";

function renderValue(v: unknown): ReactNode {
  if (v == null) return "—";
  if (typeof v === "boolean") return v ? "Yes" : "No";
  if (Array.isArray(v) && v.every((x) => typeof x !== "object")) return <span className="font-mono text-xs">{v.join(", ")}</span>;
  if (typeof v === "object") return <pre className="max-h-48 overflow-auto rounded-md bg-muted/50 p-2 font-mono text-[11px]">{JSON.stringify(v, null, 2)}</pre>;
  return <span className="font-mono text-xs">{String(v)}</span>;
}

function Custody({ t, onSelect }: { t: Trace; onSelect: (k: TabKey) => void }) {
  const s = t.session;
  const frames = t.explanation.verification.evidence_frames;
  const proj = t.projection;
  const steps: { label: string; value: ReactNode; tab: TabKey; done?: boolean }[] = [
    { label: "Evidence", value: <span className="font-mono">{t.capture.ref} · {shortHash(t.capture.sha256, 8)}</span>, tab: "evidence" },
    { label: "TCP stream", value: s ? <span className="font-mono">stream {s.stream_index}</span> : "Capture-wide", tab: "evidence" },
    { label: "Frames", value: <span className="font-mono">{frames.length ? frames.map((f) => `#${f}`).join(", ") : "—"}</span>, tab: "evidence" },
    { label: "Encryption state", value: s ? <StateBadge state={s.encryption_state} /> : "—", tab: "evidence" },
    { label: "Rule", value: <span className="font-mono text-xs">{t.finding.category}</span>, tab: "analysis" },
    {
      label: "Verdict",
      value: (
        <span className="flex gap-1.5">
          <VerdictBadge verdict={t.finding.verdict} />
          <SeverityBadge severity={t.finding.severity} />
        </span>
      ),
      tab: "analysis",
    },
    { label: "Remediation", value: t.fixes[0]?.title ?? "Evidence action", tab: "remediation" },
    {
      label: "Projected outcome",
      value: proj ? (
        <span className="tabular">
          Posture {proj.posture.before.overall} → <span style={{ color: scoreColor(proj.posture.after.overall) }}>{proj.posture.after.overall}</span>
          {proj.fixed_this_finding ? " · resolved" : " · persists"}
        </span>
      ) : (
        "—"
      ),
      tab: "after",
      done: proj?.fixed_this_finding,
    },
  ];
  return (
    <ol>
      {steps.map((st, i) => (
        <li key={st.label} className="relative flex gap-3 pb-3 last:pb-0">
          {i < steps.length - 1 && <span className="absolute left-[7px] top-4 h-full w-px bg-border" />}
          {st.done ? (
            <CheckCircle2 className="relative mt-0.5 size-[15px] shrink-0 bg-card text-sev-ok" />
          ) : (
            <CircleDot className="relative mt-0.5 size-[15px] shrink-0 bg-card text-muted-foreground" />
          )}
          <button type="button" onClick={() => onSelect(st.tab)} className="min-w-0 flex-1 text-left">
            <div className="text-xs text-muted-foreground">{st.label}</div>
            <div className="truncate text-sm">{st.value}</div>
          </button>
        </li>
      ))}
    </ol>
  );
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
  const asset = t.scope[0] ?? t.session?.server ?? "Environment";

  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 space-y-2">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Link to={`/c/${captureId}/findings`} className="hover:text-foreground">
              Findings
            </Link>
            <span>/</span>
            <span className="font-mono">{t.finding.ref}</span>
          </div>
          <h1 className="text-lg font-semibold tracking-tight">{t.finding.title}</h1>
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={t.finding.severity} />
            {t.priority && <TierBadge tier={t.priority.tier} score={t.priority.priority} />}
            <VerdictBadge verdict={t.finding.verdict} />
            <span className="text-xs text-muted-foreground">{categoryLabel(t.finding.category)}</span>
          </div>
        </div>
        <div className="flex gap-2">
          {e.verification.wireshark_filter && <CopyButton text={e.verification.wireshark_filter} label="Copy Wireshark filter" />}
          <Button asChild size="sm" variant="outline" className="h-8">
            <a href={findingPcapUrl(captureId!, t.finding.ref)}>
              <Download className="size-3.5" /> Evidence slice
            </a>
          </Button>
        </div>
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_320px]">
        <div className="min-w-0 space-y-4">
          <p className="text-sm leading-relaxed text-foreground/90">{t.finding.description}</p>
          <Tabs value={tab} onValueChange={(v) => setTab(v as TabKey)}>
            <TabsList>
              <TabsTrigger value="evidence">Evidence</TabsTrigger>
              <TabsTrigger value="analysis">Analysis</TabsTrigger>
              <TabsTrigger value="remediation">Remediation</TabsTrigger>
              <TabsTrigger value="after">After remediation</TabsTrigger>
            </TabsList>

            <TabsContent value="evidence" className="mt-4 space-y-4">
              {s ? (
                <>
                  <Panel title="Encryption state">
                    <StatePath transitions={s.state_transitions} finalState={s.encryption_state} />
                  </Panel>
                  <Panel
                    title={`Session ${s.ref}`}
                    info="Every protocol event reconstructed from the TCP stream, in order. Frames cited as evidence are outlined."
                    actions={
                      <Button asChild variant="ghost" size="sm" className="h-7 text-xs">
                        <Link to={`/c/${captureId}/sessions/${s.ref}`}>
                          Open session <ArrowRight className="size-3" />
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
                <Panel title="Observations">
                  <div className="space-y-2 text-sm">
                    {e.observations.map((o, i) => (
                      <div key={i} className="flex gap-3">
                        <span className="font-mono text-xs text-muted-foreground">#{o.frame}</span>
                        <span>{o.detail}</span>
                      </div>
                    ))}
                  </div>
                </Panel>
              )}
              <Panel title="Observed values">
                <Properties rows={e.facts.map((f) => [f.label, renderValue(f.value)])} />
              </Panel>
            </TabsContent>

            <TabsContent value="analysis" className="mt-4 space-y-4">
              <Panel title="Reasoning">
                <ol className="space-y-3">
                  {e.chain.map((c, i) => (
                    <li key={i} className="grid grid-cols-[20px_1fr] gap-2 text-sm">
                      <span className="font-mono text-xs text-muted-foreground">{i + 1}.</span>
                      <div>
                        <div className="font-medium">{c.title}</div>
                        <div className="text-muted-foreground">{c.text}</div>
                      </div>
                    </li>
                  ))}
                </ol>
              </Panel>
              {s?.risk && (
                <Panel title="Session risk classification" info="SecureMailScope risk model. Context for prioritisation; it does not decide the verdict.">
                  <RiskDrivers risk={s.risk} />
                </Panel>
              )}
              <div className="grid gap-4 lg:grid-cols-2">
                {t.priority && (
                  <Panel title="Priority factors">
                    <div className="space-y-2 text-sm">
                      {t.priority.factors.map((f) => (
                        <div key={f.factor} className="flex items-start justify-between gap-3">
                          <div>
                            <div>{f.factor}</div>
                            <div className="text-xs text-muted-foreground">{f.detail}</div>
                          </div>
                          <span className="tabular shrink-0 font-medium">{f.points ? `+${f.points}` : ""}</span>
                        </div>
                      ))}
                    </div>
                  </Panel>
                )}
                {(e.limits.length > 0 || e.posture_impact.length > 0) && (
                  <Panel title="Scope and limits">
                    <ul className="space-y-1.5 text-sm text-muted-foreground">
                      {e.posture_impact.map((p) => (
                        <li key={p.dimension}>{p.text}</li>
                      ))}
                      {e.limits.map((l) => (
                        <li key={l}>{l}</li>
                      ))}
                    </ul>
                  </Panel>
                )}
              </div>
            </TabsContent>

            <TabsContent value="remediation" className="mt-4 space-y-4">
              {t.fixes.length ? (
                t.fixes.map((f) => (
                  <Panel
                    key={f.id}
                    title={f.title}
                    description={applied.includes(f.id) ? (applied.length > 1 ? `Required ${applied.indexOf(f.id) + 1} of ${applied.length}` : "Recommended") : "Alternative"}
                    actions={
                      applied[applied.length - 1] === f.id && (
                        <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => setTab("after")}>
                          Projected effect <ArrowRight className="size-3" />
                        </Button>
                      )
                    }
                  >
                    <PlaybookView playbook={f} />
                  </Panel>
                ))
              ) : (
                <Panel>
                  <Empty title="No configuration change applies">{t.evidence_action ?? "This finding records a limit of the evidence."}</Empty>
                </Panel>
              )}
            </TabsContent>

            <TabsContent value="after" className="mt-4 space-y-4">
              {t.projection ? (
                <>
                  <div
                    className={cn(
                      "flex items-center gap-2 rounded-lg border px-3 py-2.5 text-sm",
                      t.projection.fixed_this_finding ? "border-sev-ok/40" : "border-sev-medium/40",
                    )}
                  >
                    <CheckCircle2 className={cn("size-4 shrink-0", t.projection.fixed_this_finding ? "text-sev-ok" : "text-sev-medium")} />
                    {t.projection.fixed_this_finding
                      ? `${applied.length > 1 ? `Applying these ${applied.length} changes together` : "Applying this change"} to ${t.scope.join(", ") || "the affected server"} resolves ${t.finding.ref}.`
                      : `This change alone does not resolve ${t.finding.ref}. Combine changes in Remediation.`}
                    <Button asChild size="sm" variant="ghost" className="ml-auto h-7 text-xs">
                      <Link to={`/c/${captureId}/remediation`}>
                        Open remediation <ArrowRight className="size-3" />
                      </Link>
                    </Button>
                  </div>
                  <SimulationView sim={t.projection} captureId={captureId!} compactGraph />
                </>
              ) : (
                <Panel>
                  <Empty title="Nothing to project">Only failing findings with a configuration change can be projected.</Empty>
                </Panel>
              )}
            </TabsContent>
          </Tabs>
        </div>

        <aside className="space-y-4">
          <Panel title="Details">
            <Properties
              rows={[
                ["Status", "Open"],
                ["Severity", <SeverityBadge severity={t.finding.severity} />],
                ["Priority", t.priority ? `${t.priority.tier} · ${t.priority.tier_label}` : "—"],
                ["Confidence", `${Math.round(t.finding.confidence * 100)}%`],
                ["Detection", `${t.finding.detection_method.charAt(0).toUpperCase()}${t.finding.detection_method.slice(1)} rule`],
                ["Asset", <span className="font-mono text-xs">{asset}</span>],
                [
                  "Session",
                  s ? (
                    <Link to={`/c/${captureId}/sessions/${s.ref}`} className="font-mono text-xs underline-offset-2 hover:underline">
                      {s.ref}
                    </Link>
                  ) : (
                    "—"
                  ),
                ],
                ["Software", t.software ? t.software.name : "—"],
                ["Standards", t.finding.standard_refs.join(", ") || "—"],
              ]}
            />
          </Panel>
          <Panel title="Chain of custody">
            <Custody t={t} onSelect={setTab} />
          </Panel>
          <Panel title="Verify">
            <div className="space-y-3">
              {e.verification.wireshark_filter && (
                <div className="space-y-1">
                  <div className="text-xs text-muted-foreground">Wireshark display filter</div>
                  <CodeLine>{e.verification.wireshark_filter}</CodeLine>
                </div>
              )}
              <div className="space-y-1">
                <div className="text-xs text-muted-foreground">Evidence SHA-256</div>
                <CodeLine>{e.verification.capture_sha256}</CodeLine>
              </div>
            </div>
          </Panel>
        </aside>
      </div>
    </>
  );
}
