import { AnimatePresence, motion } from "framer-motion";
import { ArrowRight, CheckCircle2, CircleAlert, FlaskConical, MinusCircle } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";

import { Panel, RiskBadge, SeverityBadge, StateBadge } from "@/components/common";
import { ScoreGauge } from "@/components/score-gauge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { PostureDimensions } from "@/components/viz/posture-dimensions";
import { Topology } from "@/components/viz/topology";
import { categoryLabel, scoreColor } from "@/lib/format";
import type { Simulation } from "@/lib/types";

function Delta({ label, before, after, lowerIsBetter, suffix = "" }: { label: string; before: number | null | undefined; after: number | null | undefined; lowerIsBetter?: boolean; suffix?: string }) {
  const b = before ?? 0;
  const a = after ?? 0;
  const better = lowerIsBetter ? a < b : a > b;
  const worse = lowerIsBetter ? a > b : a < b;
  return (
    <div className="rounded-lg border p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="tabular mt-1 flex items-baseline gap-2">
        <span className="text-lg font-semibold text-muted-foreground">
          {before ?? "—"}
          {suffix}
        </span>
        <ArrowRight className="size-3.5 self-center text-muted-foreground" />
        <motion.span
          key={String(after)}
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-lg font-semibold"
          style={{ color: better ? "hsl(var(--sev-ok))" : worse ? "hsl(var(--sev-critical))" : undefined }}
        >
          {after ?? "—"}
          {suffix}
        </motion.span>
      </div>
    </div>
  );
}

export function SimulationView({ sim, captureId, compactGraph }: { sim: Simulation; captureId: string; compactGraph?: boolean }) {
  const [view, setView] = useState<"after" | "before" | "compare">("compare");
  const pb = sim.posture.before;
  const pa = sim.posture.after;
  const rb = sim.risk.before?.index;
  const ra = sim.risk.after?.index;

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-2 rounded-lg border border-primary/30 bg-primary/5 p-3 text-xs text-muted-foreground">
        <FlaskConical className="mt-0.5 size-3.5 shrink-0 text-primary" />
        <span>
          <b className="text-foreground">Projection.</b> {sim.note}
        </span>
      </div>

      <div className="grid gap-4 lg:grid-cols-[260px_1fr]">
        <div className="flex flex-col items-center justify-center rounded-lg border p-4">
          <ScoreGauge score={pa.overall} ghost={pb.overall} size={200} label="projected posture" />
          <div className="mt-2 text-xs text-muted-foreground">
            from <b style={{ color: scoreColor(pb.overall) }}>{pb.overall ?? "—"}</b> today
          </div>
        </div>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
          <Delta label="Posture score" before={pb.overall} after={pa.overall} />
          <Delta label="Failing findings" before={sim.findings.before} after={sim.findings.after} lowerIsBetter />
          <Delta label="Risk index (model)" before={rb != null ? Math.round(rb) : null} after={ra != null ? Math.round(ra) : null} lowerIsBetter />
          <Delta label="Cleartext sessions" before={sim.state.before.cleartext} after={sim.state.after.cleartext} lowerIsBetter />
          <Delta label="Credentials exposed" before={sim.state.before.credentials_exposed} after={sim.state.after.credentials_exposed} lowerIsBetter />
          <Delta label="Protected sessions" before={sim.state.before.protected} after={sim.state.after.protected} />
          <Delta label="PQC readiness" before={sim.pqc.before.score} after={sim.pqc.after.score} />
          <Delta label="Hybrid PQC sessions" before={sim.state.before.pqc_selected} after={sim.state.after.pqc_selected} />
          <Delta label="Harvest-now-decrypt-later exposed" before={sim.pqc.before.hndl_exposed_pct} after={sim.pqc.after.hndl_exposed_pct} lowerIsBetter suffix="%" />
        </div>
      </div>

      {(sim.pqc.before.score !== sim.pqc.after.score || sim.state.before.pqc_selected !== sim.state.after.pqc_selected) && (
        <Panel title="Post-quantum exposure after the fix" description="Share of sessions in each harvest-now-decrypt-later tier, today and projected.">
          <div className="space-y-3">
            {sim.pqc.before.exposure.map((t) => {
              const after = sim.pqc.after.exposure.find((x) => x.tier === t.tier);
              const color = t.tier === "pqc_hybrid" ? "hsl(var(--sev-ok))" : t.tier === "cleartext" || t.tier === "static_rsa" ? "hsl(var(--sev-critical))" : "hsl(var(--sev-medium))";
              return (
                <div key={t.tier} className="grid grid-cols-[220px_1fr_110px] items-center gap-3 text-xs">
                  <span>{t.label}</span>
                  <div className="space-y-1">
                    <div className="h-1.5 overflow-hidden rounded-full bg-muted"><div className="h-full rounded-full opacity-40" style={{ width: `${t.pct}%`, background: color }} /></div>
                    <div className="h-1.5 overflow-hidden rounded-full bg-muted"><motion.div className="h-full rounded-full" style={{ background: color }} initial={{ width: `${t.pct}%` }} animate={{ width: `${after?.pct ?? 0}%` }} transition={{ duration: 0.8 }} /></div>
                  </div>
                  <span className="tabular text-right text-muted-foreground">
                    {t.pct}% → <b className="text-foreground">{after?.pct ?? 0}%</b>
                  </span>
                </div>
              );
            })}
            <div className="text-[11px] text-muted-foreground">Faded bar: today. Solid bar: projected after the selected fixes.</div>
          </div>
        </Panel>
      )}

      {sim.graph && (
        <Panel
          title="Infrastructure after the fix"
          description="Same layout before and after: resolved weaknesses are struck through, nodes whose risk dropped are marked."
          actions={
            <ToggleGroup type="single" value={view} onValueChange={(v) => v && setView(v as typeof view)} variant="outline" size="sm">
              <ToggleGroupItem value="before" className="h-7 px-2.5 text-xs">
                Before
              </ToggleGroupItem>
              <ToggleGroupItem value="after" className="h-7 px-2.5 text-xs">
                After
              </ToggleGroupItem>
              <ToggleGroupItem value="compare" className="h-7 px-2.5 text-xs">
                Compare
              </ToggleGroupItem>
            </ToggleGroup>
          }
        >
          <AnimatePresence mode="wait">
            <motion.div key={view} initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.2 }}>
              <Topology
                graph={view === "before" ? sim.graph.before : sim.graph.after}
                compare={view === "compare" ? sim.graph.before : undefined}
                height={compactGraph ? 380 : 470}
              />
            </motion.div>
          </AnimatePresence>
        </Panel>
      )}

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Posture by dimension" description="Today (solid) and projected (faded) per dimension.">
          <PostureDimensions dimensions={pb.dimensions} after={pa.dimensions} />
        </Panel>
        <Panel title="Findings" description={`${sim.findings.resolved.length} resolved · ${sim.findings.remaining.length} remain · ${sim.findings.introduced.length} new`}>
          <div className="max-h-[320px] space-y-1 overflow-y-auto pr-1">
            {sim.findings.resolved.map((f, i) => (
              <FindingLine key={`r${i}`} f={f} status="resolved" captureId={captureId} />
            ))}
            {sim.findings.remaining.map((f, i) => (
              <FindingLine key={`m${i}`} f={f} status="remaining" captureId={captureId} />
            ))}
            {sim.findings.introduced.map((f, i) => (
              <FindingLine key={`n${i}`} f={f} status="new" captureId={captureId} />
            ))}
            {!sim.findings.resolved.length && !sim.findings.remaining.length && !sim.findings.introduced.length && (
              <div className="text-sm text-muted-foreground">No failing findings before or after.</div>
            )}
          </div>
        </Panel>
      </div>

      {sim.sessions_changed.length > 0 && (
        <Panel title="Sessions that change" description="Each session re-evaluated as it would have looked with the fix in place.">
          <div className="max-h-[360px] overflow-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Session</TableHead>
                  <TableHead>Before</TableHead>
                  <TableHead />
                  <TableHead>After</TableHead>
                  <TableHead>Risk</TableHead>
                  <TableHead>Basis</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sim.sessions_changed.map((c) => (
                  <TableRow key={c.ref}>
                    <TableCell className="font-mono text-xs">
                      <Link to={`/c/${captureId}/sessions/${c.ref}`} className="hover:underline">
                        {c.ref}
                      </Link>
                      <div className="text-[10.5px] text-muted-foreground">{c.server}</div>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-col gap-1">
                        <StateBadge state={c.before.encryption_state} />
                        <span className="text-[11px] text-muted-foreground">{[c.before.tls_version, c.before.cipher_suite?.replace(/^TLS_/, "")].filter(Boolean).join(" · ") || "no TLS"}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <ArrowRight className="size-3.5 text-muted-foreground" />
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-col gap-1">
                        <StateBadge state={c.after.encryption_state} />
                        <span className="text-[11px] text-muted-foreground">{[c.after.tls_version, c.after.cipher_suite?.replace(/^TLS_/, "")].filter(Boolean).join(" · ")}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <RiskBadge risk={c.before.risk_class} />
                        <ArrowRight className="size-3 text-muted-foreground" />
                        <RiskBadge risk={c.after.risk_class} />
                      </div>
                    </TableCell>
                    <TableCell className="text-[11px] text-muted-foreground" title={c.tls_profile_source ?? undefined}>
                      {c.tls_profile_source
                        ? c.tls_profile_source.startsWith("policy")
                          ? "policy target (no TLS seen on server)"
                          : `copied from ${c.tls_profile_source.match(/\(([^)]+)\)/)?.[1] ?? "server"}`
                        : c.fixes.map((f) => f.replace(/_/g, " ")).join(", ")}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </Panel>
      )}
    </div>
  );
}

function FindingLine({ f, status, captureId }: { f: Simulation["findings"]["resolved"][number]; status: "resolved" | "remaining" | "new"; captureId: string }) {
  const Icon = status === "resolved" ? CheckCircle2 : status === "new" ? CircleAlert : MinusCircle;
  const color = status === "resolved" ? "hsl(var(--sev-ok))" : status === "new" ? "hsl(var(--sev-critical))" : "hsl(var(--muted-foreground))";
  const body = (
    <div className="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-muted/60">
      <Icon className="size-4 shrink-0" style={{ color }} />
      <SeverityBadge severity={f.severity} />
      <span className={status === "resolved" ? "min-w-0 flex-1 truncate text-muted-foreground line-through" : "min-w-0 flex-1 truncate"}>{f.title}</span>
      <span className="shrink-0 font-mono text-[11px] text-muted-foreground">{f.session_ref ?? categoryLabel(f.category)}</span>
    </div>
  );
  return f.ref && f.ref.startsWith("F-") ? <Link to={`/c/${captureId}/findings/${f.ref}`}>{body}</Link> : body;
}
