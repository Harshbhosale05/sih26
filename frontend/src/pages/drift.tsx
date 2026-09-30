import { ArrowRight, TrendingDown, TrendingUp } from "lucide-react";
import { useEffect, useState } from "react";
import { CartesianGrid, Line, LineChart, XAxis, YAxis } from "recharts";

import { Empty, ErrorState, Loading, PageHeader, Panel, SeverityBadge, Stat } from "@/components/common";
import { ChartContainer, ChartLegend, ChartLegendContent, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useDriftCompare, useDriftTimeline } from "@/lib/api";

const chartConfig = {
  posture: { label: "Posture", color: "hsl(var(--chart-1))" },
  pqc_readiness: { label: "PQC readiness", color: "hsl(var(--chart-3))" },
  encrypted_pct: { label: "Encrypted %", color: "hsl(var(--chart-2))" },
} satisfies ChartConfig;

const DIR_COLOR: Record<string, string> = {
  improved: "hsl(var(--sev-ok))",
  regressed: "hsl(var(--sev-critical))",
  changed: "hsl(var(--sev-medium))",
  unchanged: "hsl(var(--muted-foreground))",
};

export function DriftPage() {
  const timeline = useDriftTimeline();
  const points = timeline.data?.points ?? [];
  const [baseline, setBaseline] = useState<string>();
  const [current, setCurrent] = useState<string>();
  const compare = useDriftCompare(baseline, current);

  useEffect(() => {
    if (points.length >= 2 && !baseline && !current) {
      setBaseline(points[0].capture_id);
      setCurrent(points[1].capture_id);
    }
  }, [points, baseline, current]);

  if (timeline.error) return <ErrorState error={timeline.error} />;
  if (!timeline.data) return <Loading rows={3} />;
  if (points.length < 2) return <Empty title="Drift needs two analysed captures">Upload another capture of the same infrastructure to see what changed.</Empty>;

  const data = points.map((p) => ({ ref: p.ref, ...p.metrics }));
  const c = compare.data;

  return (
    <div className="space-y-6">
      <PageHeader title="Cryptographic drift" description="How the posture of the same infrastructure changes between captures: which servers regressed, which primitives changed, which findings appeared or cleared." />

      <Panel title="Across all analysed captures" description="Ordered by capture time.">
        <ChartContainer config={chartConfig} className="h-[240px] w-full">
          <LineChart data={data} margin={{ left: 0, right: 12, top: 8 }}>
            <CartesianGrid vertical={false} />
            <XAxis dataKey="ref" tickLine={false} axisLine={false} fontSize={11} />
            <YAxis domain={[0, 100]} tickLine={false} axisLine={false} width={32} fontSize={11} />
            <ChartTooltip content={<ChartTooltipContent />} />
            <ChartLegend content={<ChartLegendContent />} />
            {Object.keys(chartConfig).map((k) => (
              <Line key={k} dataKey={k} type="monotone" stroke={`var(--color-${k})`} strokeWidth={2} dot={{ r: 3 }} connectNulls isAnimationActive={false} />
            ))}
          </LineChart>
        </ChartContainer>
      </Panel>

      <Panel
        title="Compare two captures"
        actions={
          <div className="flex items-center gap-2">
            {[baseline, current].map((v, i) => (
              <div key={i} className="flex items-center gap-2">
                {i === 1 && <ArrowRight className="size-4 text-muted-foreground" />}
                <Select value={v} onValueChange={i === 0 ? setBaseline : setCurrent}>
                  <SelectTrigger className="h-8 w-[240px] text-xs">
                    <SelectValue placeholder={i === 0 ? "Baseline" : "Current"} />
                  </SelectTrigger>
                  <SelectContent>
                    {points.map((p) => (
                      <SelectItem key={p.capture_id} value={p.capture_id}>
                        <span className="font-mono text-xs">{p.ref}</span> {p.filename}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            ))}
          </div>
        }
      >
        {compare.error ? (
          <ErrorState error={compare.error} />
        ) : !c ? (
          <Loading rows={2} />
        ) : (
          <div className="space-y-5">
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <Stat label="Verdict" value={c.summary.verdict} color={DIR_COLOR[c.summary.verdict] ?? undefined} />
              <Stat label="Regressions" value={c.summary.regressions} color={c.summary.regressions ? DIR_COLOR.regressed : undefined} icon={<TrendingDown className="size-4" />} />
              <Stat label="Improvements" value={c.summary.improvements} color={c.summary.improvements ? DIR_COLOR.improved : undefined} icon={<TrendingUp className="size-4" />} />
              <Stat label="Servers compared" value={c.summary.servers_compared} sub={`${c.summary.servers_added} added · ${c.summary.servers_removed} removed`} />
            </div>

            <div className="grid gap-4 xl:grid-cols-2">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Metric</TableHead>
                    <TableHead className="text-right">{c.baseline.ref}</TableHead>
                    <TableHead className="text-right">{c.current.ref}</TableHead>
                    <TableHead className="text-right">Δ</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {c.metrics.map((m) => (
                    <TableRow key={m.key}>
                      <TableCell className="text-sm">{m.label}</TableCell>
                      <TableCell className="tabular text-right">{m.baseline ?? "—"}</TableCell>
                      <TableCell className="tabular text-right">{m.current ?? "—"}</TableCell>
                      <TableCell className="tabular text-right font-medium" style={{ color: DIR_COLOR[m.direction] }}>
                        {m.delta == null ? "—" : `${m.delta > 0 ? "+" : ""}${m.delta}`}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>

              <div className="space-y-4">
                <div className="space-y-2">
                  <div className="text-sm font-medium">Server changes</div>
                  {c.servers.map((s) => (
                    <div key={s.server} className="rounded-lg border p-3">
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-sm">{s.server}</span>
                        <span className="text-xs font-medium" style={{ color: DIR_COLOR[s.status] ?? undefined }}>
                          {s.status}
                        </span>
                      </div>
                      {s.changes.map((ch) => (
                        <div key={ch.dimension} className="mt-1 flex flex-wrap items-center gap-1.5 text-xs">
                          <span className="text-muted-foreground">{ch.label}</span>
                          <span className="font-mono">{ch.from}</span>
                          <ArrowRight className="size-3" style={{ color: DIR_COLOR[ch.direction] }} />
                          <span className="font-mono" style={{ color: DIR_COLOR[ch.direction] }}>
                            {ch.to}
                          </span>
                        </div>
                      ))}
                    </div>
                  ))}
                </div>
                <div className="space-y-1.5">
                  <div className="text-sm font-medium">Finding changes</div>
                  {c.findings.map((f) => (
                    <div key={f.category} className="flex items-center gap-2 text-sm">
                      <SeverityBadge severity={f.severity} />
                      <span className="flex-1">{f.title}</span>
                      <span className="tabular text-xs text-muted-foreground">
                        {f.baseline_count} → {f.current_count}
                      </span>
                      <span className="w-16 text-right text-xs font-medium" style={{ color: f.status === "resolved" ? DIR_COLOR.improved : f.status === "new" ? DIR_COLOR.regressed : undefined }}>
                        {f.status}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </Panel>
    </div>
  );
}
