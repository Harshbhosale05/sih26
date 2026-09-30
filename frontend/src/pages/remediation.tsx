import { ArrowRight, FileCode2, Loader2, RotateCcw, Sparkles, Telescope } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Bar, CartesianGrid, ComposedChart, Line, ReferenceLine, XAxis, YAxis } from "recharts";
import { useParams } from "react-router-dom";

import { Empty, ErrorState, Loading, PageHeader, Panel, SeverityBadge } from "@/components/common";
import { PlaybookView } from "@/components/config-diff";
import { SimulationView } from "@/components/simulation-view";
import { Button } from "@/components/ui/button";
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart";
import { Checkbox } from "@/components/ui/checkbox";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { usePlan, useSimulation } from "@/lib/api";
import { scoreColor } from "@/lib/format";
import type { PlanStep } from "@/lib/types";
import { cn } from "@/lib/utils";

const chartConfig = {
  score: { label: "Projected posture", color: "hsl(var(--primary))" },
  findings: { label: "Failing findings", color: "hsl(var(--sev-high))" },
} satisfies ChartConfig;

function Effort({ n }: { n: number }) {
  return (
    <span className="flex items-center gap-0.5" title={`effort ${n}/3`}>
      {[1, 2, 3].map((i) => (
        <span key={i} className={cn("h-1.5 w-2.5 rounded-sm", i <= n ? "bg-foreground/60" : "bg-muted")} />
      ))}
    </span>
  );
}

function StepCard({ step, checked, onToggle, onOpen }: { step: PlanStep; checked: boolean; onToggle: () => void; onOpen: () => void }) {
  return (
    <div className={cn("rounded-lg border p-3 transition-colors", checked ? "border-primary/50 bg-primary/5" : "bg-card")}>
      <div className="flex items-start gap-3">
        <Checkbox checked={checked} onCheckedChange={onToggle} className="mt-0.5" aria-label={`Apply step ${step.step}`} />
        <div className="min-w-0 flex-1 space-y-1.5">
          <div className="flex items-start justify-between gap-2">
            <div className="text-sm font-medium leading-snug">
              <span className="mr-1.5 font-mono text-xs text-muted-foreground">{step.step}.</span>
              {step.title}
            </div>
            <div className="tabular shrink-0 text-xs">
              <span style={{ color: scoreColor(step.score_before) }}>{step.score_before ?? "—"}</span>
              <span className="mx-1 text-muted-foreground">→</span>
              <b style={{ color: scoreColor(step.score_after) }}>{step.score_after ?? "—"}</b>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted-foreground">
            <span>{step.owner}</span>
            <Effort n={step.effort} />
            <span className="font-mono">
              {step.software.map((s) => `${s.server} · ${s.name}`).join(" | ") || step.servers.join(", ") || "all servers"}
            </span>
          </div>
          <div className="flex flex-wrap gap-1">
            {step.addresses.slice(0, 6).map((a) => (
              <SeverityBadge key={a.ref} severity={a.severity} className="text-[10px]" />
            ))}
            <span className="text-[11px] text-muted-foreground">
              closes {step.addresses.length} finding{step.addresses.length === 1 ? "" : "s"}
            </span>
          </div>
          <Button variant="ghost" size="sm" className="-ml-2 h-7 text-xs" onClick={onOpen}>
            <FileCode2 className="size-3.5" /> Config for {step.playbook.software.name ?? "this server"}
          </Button>
        </div>
      </div>
    </div>
  );
}

export function RemediationPage() {
  const { captureId } = useParams();
  const plan = usePlan(captureId);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [open, setOpen] = useState<PlanStep | null>(null);

  useEffect(() => {
    if (plan.data) setSelected(new Set(plan.data.steps.map((s) => s.step)));
  }, [plan.data]);

  const fixes = useMemo(
    () =>
      (plan.data?.steps ?? [])
        .filter((s) => selected.has(s.step))
        .map((s) => ({ id: s.fix_id, servers: s.servers.length ? s.servers : null })),
    [plan.data, selected],
  );
  const sim = useSimulation(captureId, fixes);

  if (plan.error) return <ErrorState error={plan.error} />;
  if (!plan.data) return <Loading rows={4} />;

  const p = plan.data;
  const trajectory = [
    { step: "Today", score: p.baseline.score ?? 0, findings: p.baseline.findings },
    ...p.steps.map((s) => ({ step: `Step ${s.step}`, score: s.score_after ?? 0, findings: s.findings_after })),
  ];
  const toggle = (n: number) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(n)) next.delete(n);
      else next.add(n);
      return next;
    });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Fix simulator"
        description="An ordered remediation plan written for the server software we identified, and a digital twin of this capture that shows what a re-capture would look like with the chosen fixes in place — posture, findings, sessions and the infrastructure map."
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => setSelected(new Set())}>
              <RotateCcw className="size-3.5" /> Clear
            </Button>
            <Button size="sm" onClick={() => setSelected(new Set(p.steps.map((s) => s.step)))}>
              <Sparkles className="size-3.5" /> Apply full plan
            </Button>
          </>
        }
      />

      {!p.steps.length ? (
        <Empty title="Nothing to fix">No failing finding in this capture has a configuration remedy.</Empty>
      ) : (
        <div className="grid gap-6 xl:grid-cols-[420px_1fr]">
          <div className="space-y-4">
            <Panel title="Plan" description={p.method}>
              <div className="space-y-2">
                {p.steps.map((s) => (
                  <StepCard key={s.step} step={s} checked={selected.has(s.step)} onToggle={() => toggle(s.step)} onOpen={() => setOpen(s)} />
                ))}
              </div>
            </Panel>
            {p.evidence_gaps.length > 0 && (
              <Panel title="Evidence gaps" description="Not faults — things a better capture would let us assess.">
                <div className="space-y-2">
                  {p.evidence_gaps.map((g) => (
                    <div key={g.category} className="flex gap-2 text-xs">
                      <Telescope className="mt-0.5 size-3.5 shrink-0 text-muted-foreground" />
                      <div>
                        <div className="font-medium">
                          {g.category.replace(/_/g, " ")} · {g.findings.length}
                        </div>
                        <div className="text-muted-foreground">{g.action}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </Panel>
            )}
          </div>

          <div className="min-w-0 space-y-4">
            <Panel
              title="Posture trajectory"
              description="Projected score and failing findings after each step of the plan, in order. Click a step to apply the plan up to it."
            >
              <ChartContainer config={chartConfig} className="h-[220px] w-full">
                <ComposedChart
                  data={trajectory}
                  margin={{ left: 0, right: 12, top: 8 }}
                  onClick={(e) => {
                    const i = e?.activeTooltipIndex;
                    if (typeof i === "number") setSelected(new Set(p.steps.slice(0, i).map((s) => s.step)));
                  }}
                >
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="step" tickLine={false} axisLine={false} fontSize={11} />
                  <YAxis yAxisId="score" domain={[0, 100]} tickLine={false} axisLine={false} width={32} fontSize={11} />
                  <YAxis yAxisId="findings" orientation="right" allowDecimals={false} tickLine={false} axisLine={false} width={28} fontSize={11} />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <ReferenceLine yAxisId="score" y={80} stroke="hsl(var(--sev-ok))" strokeDasharray="4 4" label={{ value: "strong", position: "insideTopLeft", fontSize: 10, fill: "hsl(var(--sev-ok))" }} />
                  <Bar yAxisId="findings" dataKey="findings" fill="var(--color-findings)" fillOpacity={0.35} radius={[3, 3, 0, 0]} barSize={26} isAnimationActive={false} />
                  <Line yAxisId="score" type="stepAfter" dataKey="score" stroke="var(--color-score)" strokeWidth={2.5} dot={{ r: 4, fill: "var(--color-score)" }} activeDot={{ r: 6 }} isAnimationActive={false} />
                </ComposedChart>
              </ChartContainer>
            </Panel>

            <div className="flex items-center gap-2 text-sm">
              {sim.isFetching && <Loader2 className="size-4 animate-spin text-primary" />}
              <span className="text-muted-foreground">
                Simulating <b className="text-foreground">{fixes.length}</b> fix{fixes.length === 1 ? "" : "es"}
                {fixes.length ? ":" : " — select steps to project their effect."}
              </span>
              <span className="flex flex-wrap gap-1">
                {p.steps
                  .filter((s) => selected.has(s.step))
                  .map((s) => (
                    <span key={s.step} className="rounded border px-1.5 py-0.5 text-[11px]">
                      {s.step}. {s.fix_id.replace(/_/g, " ")}
                    </span>
                  ))}
              </span>
            </div>

            {sim.error ? <ErrorState error={sim.error} /> : sim.data ? <SimulationView sim={sim.data} captureId={captureId!} /> : <Loading rows={3} />}
          </div>
        </div>
      )}

      <Sheet open={!!open} onOpenChange={(o) => !o && setOpen(null)}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-2xl">
          {open && (
            <>
              <SheetHeader>
                <SheetTitle>
                  Step {open.step} · {open.title}
                </SheetTitle>
                <SheetDescription>
                  {open.owner} · {open.playbook.effort_label} · target {open.playbook.target.host}:{open.playbook.target.port}
                </SheetDescription>
              </SheetHeader>
              <div className="mt-5 space-y-5">
                <PlaybookView playbook={open.playbook} />
                <div className="space-y-1.5">
                  <div className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Closes</div>
                  {open.addresses.map((a) => (
                    <a key={a.ref} href={`/c/${captureId}/findings/${a.ref}`} className="flex items-center gap-2 rounded-md px-1.5 py-1 text-sm hover:bg-muted">
                      <SeverityBadge severity={a.severity} />
                      <span className="flex-1">{a.title}</span>
                      <span className="font-mono text-xs text-muted-foreground">{a.ref}</span>
                      <ArrowRight className="size-3 text-muted-foreground" />
                    </a>
                  ))}
                </div>
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
