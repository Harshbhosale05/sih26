import clsx from "clsx";
import { ArrowDownRight, ArrowRight, ArrowUpRight, ArrowLeftRight, Minus, Plus, Shuffle } from "lucide-react";
import { useEffect, useState } from "react";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Card, ChartTooltip, Empty, ErrorState, Mono, PageHeader, SeverityBadge, Spinner, Stat, Table, Td, Th } from "../components/ui";
import { useApi } from "../lib/api";
import { fmtDate } from "../lib/format";
import type { DriftCompare, DriftTimeline } from "../lib/types";

const DIRECTION_STYLE: Record<string, { icon: typeof Minus; cls: string; label: string }> = {
  improved: { icon: ArrowUpRight, cls: "text-good", label: "Improved" },
  regressed: { icon: ArrowDownRight, cls: "text-crit", label: "Regressed" },
  changed: { icon: Shuffle, cls: "text-accent", label: "Changed" },
  unchanged: { icon: Minus, cls: "text-muted", label: "Unchanged" },
  not_comparable: { icon: Minus, cls: "text-muted", label: "n/a" },
  mixed: { icon: Shuffle, cls: "text-serious", label: "Mixed" },
  added: { icon: Plus, cls: "text-accent", label: "New server" },
  removed: { icon: Minus, cls: "text-muted", label: "Not observed" },
  stable: { icon: Minus, cls: "text-muted", label: "Stable" },
};

function Direction({ value }: { value: string }) {
  const s = DIRECTION_STYLE[value] ?? DIRECTION_STYLE.unchanged;
  const Icon = s.icon;
  return (
    <span className="inline-flex items-center gap-1 text-[12.5px] font-medium text-ink">
      <Icon size={14} className={s.cls} />
      {s.label}
    </span>
  );
}

const FINDING_STATUS: Record<string, string> = {
  new: "text-crit",
  worse: "text-serious",
  persisting: "text-ink2",
  better: "text-good",
  resolved: "text-good",
};

function fmtMetric(v: number | null, unit: string) {
  if (v === null || v === undefined) return "—";
  return unit === "pct" ? `${v}%` : String(v);
}

function Comparison({ baseline, current }: { baseline: string; current: string }) {
  const res = useApi<DriftCompare>(`/api/drift/compare?baseline=${baseline}&current=${current}`);
  if (res.error) return <ErrorState error={res.error} onRetry={res.reload} />;
  if (!res.data) return <Spinner label="Comparing captures…" />;
  const d = res.data;
  const changedServers = d.servers.filter((s) => s.status !== "unchanged");

  return (
    <>
      <div className="mb-4 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Verdict" value={<Direction value={d.summary.verdict} />} />
        <Stat label="Regressions" value={d.summary.regressions} status={d.summary.regressions ? "crit" : "good"} />
        <Stat label="Improvements" value={d.summary.improvements} status={d.summary.improvements ? "good" : "none"} />
        <Stat label="Neutral changes" value={d.summary.neutral_changes} hint={`${d.summary.servers_compared} matched · ${d.summary.servers_added} new · ${d.summary.servers_removed} gone`} />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Environment metrics" subtitle={`${d.baseline.ref} → ${d.current.ref}`} padded={false}>
          <Table>
            <thead>
              <tr>
                <Th>Metric</Th>
                <Th className="text-right">Baseline</Th>
                <Th className="text-right">Current</Th>
                <Th className="text-right">Δ</Th>
                <Th>Drift</Th>
              </tr>
            </thead>
            <tbody>
              {d.metrics.map((m) => (
                <tr key={m.key}>
                  <Td>{m.label}</Td>
                  <Td className="tabular text-right text-ink2">{fmtMetric(m.baseline, m.unit)}</Td>
                  <Td className="tabular text-right font-medium">{fmtMetric(m.current, m.unit)}</Td>
                  <Td className="tabular text-right">{m.delta === null ? "—" : `${m.delta > 0 ? "+" : ""}${m.delta}`}</Td>
                  <Td>
                    <Direction value={m.direction} />
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Card>

        <div className="space-y-4">
          <Card title="Server configuration drift" subtitle="Matched on ip:port, compared on each server's dominant behaviour">
            {changedServers.length === 0 ? (
              <p className="text-[13px] text-ink2">No server changed its observed cryptographic behaviour.</p>
            ) : (
              <div className="space-y-3">
                {changedServers.map((s) => (
                  <div key={s.server} className="rounded-lg border border-line p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <Mono>{s.server}</Mono>
                      <Direction value={s.status} />
                    </div>
                    {s.changes.map((c) => (
                      <div key={c.dimension} className="mt-2 flex flex-wrap items-center gap-2 text-[12.5px]">
                        <span className="w-44 shrink-0 text-ink2">{c.label}</span>
                        <Mono>{c.from}</Mono>
                        <ArrowRight size={13} className="text-muted" />
                        <Mono>{c.to}</Mono>
                        <Direction value={c.direction} />
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            )}
          </Card>

          <Card title="Findings drift" padded={false}>
            {d.findings.length === 0 ? (
              <p className="p-5 text-[13px] text-ink2">No failing findings in either capture.</p>
            ) : (
              <div className="divide-y divide-line">
                {d.findings.map((f) => (
                  <div key={f.category} className="flex items-center gap-3 px-5 py-2.5">
                    <SeverityBadge severity={f.severity} compact />
                    <span className="min-w-0 flex-1 truncate text-[13px] text-ink">{f.title}</span>
                    <span className="tabular text-[12.5px] text-ink2">
                      {f.baseline_count} → {f.current_count}
                    </span>
                    <span className={clsx("w-20 text-right text-[12px] font-semibold uppercase", FINDING_STATUS[f.status])}>{f.status}</span>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>
      <p className="mt-4 text-[12px] leading-relaxed text-muted">{d.method}</p>
    </>
  );
}

export function DriftPage() {
  const timeline = useApi<DriftTimeline>("/api/drift/timeline");
  const [metric, setMetric] = useState("posture");
  const [baseline, setBaseline] = useState("");
  const [current, setCurrent] = useState("");
  const [allSteps, setAllSteps] = useState(false);

  useEffect(() => {
    const pts = timeline.data?.points;
    if (pts && pts.length >= 2 && !baseline) {
      setBaseline(pts[pts.length - 2].capture_id);
      setCurrent(pts[pts.length - 1].capture_id);
    }
  }, [timeline.data, baseline]);

  if (timeline.error) return <ErrorState error={timeline.error} onRetry={timeline.reload} />;
  if (!timeline.data) return <Spinner label="Computing snapshots…" />;
  const t = timeline.data;
  const def = t.metrics.find((m) => m.key === metric)!;
  const series = t.points.map((p) => ({ ref: p.ref, filename: p.filename, at: p.observed_at, value: p.metrics[metric] }));

  const select = (value: string, onChange: (v: string) => void) => (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="min-w-0 flex-1 rounded-lg border border-line bg-surface px-3 py-2 text-[13px] text-ink focus:outline-none focus:ring-2 focus:ring-accent/40"
    >
      {t.points.map((p) => (
        <option key={p.capture_id} value={p.capture_id}>
          {p.ref} · {p.filename}
        </option>
      ))}
    </select>
  );

  return (
    <>
      <PageHeader
        eyebrow="Innovation 2"
        title="Cryptographic drift"
        description="A capture is a photograph; drift is what changed between photographs. Compare any two analysed captures to see servers whose TLS behaviour moved, metrics that regressed, and findings that appeared or were resolved."
      />

      {t.points.length < 2 ? (
        <Empty icon={<ArrowLeftRight size={28} />} title="Drift needs at least two analysed captures">
          Upload and analyse another capture of the same infrastructure — ideally from a different day — to see how its posture changed.
        </Empty>
      ) : (
        <>
          <Card
            className="mb-6"
            title="Posture over time"
            subtitle={`${t.points.length} analysed captures, ordered by capture time · ${def.better === "higher" ? "higher is better" : "lower is better"}`}
            action={
              <select
                value={metric}
                onChange={(e) => setMetric(e.target.value)}
                className="rounded-lg border border-line bg-surface px-3 py-1.5 text-[13px] text-ink focus:outline-none focus:ring-2 focus:ring-accent/40"
              >
                {t.metrics.map((m) => (
                  <option key={m.key} value={m.key}>
                    {m.label}
                  </option>
                ))}
              </select>
            }
          >
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={series} margin={{ top: 8, right: 16, bottom: 0, left: -16 }}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="ref" tickLine={false} />
                  <YAxis tickLine={false} axisLine={false} domain={[0, def.unit === "count" ? "auto" : 100]} allowDecimals={false} />
                  <Tooltip
                    cursor={{ stroke: "rgb(var(--muted))", strokeDasharray: "3 3" }}
                    content={({ active, payload }) => {
                      const row = payload?.[0]?.payload as (typeof series)[number] | undefined;
                      return row ? (
                        <ChartTooltip
                          active={active}
                          label={`${row.ref} · ${row.filename}`}
                          rows={[
                            { name: def.label, value: fmtMetric(row.value, def.unit), color: "var(--s1)" },
                            { name: "Captured", value: fmtDate(row.at) },
                          ]}
                        />
                      ) : null;
                    }}
                  />
                  <Line isAnimationActive={false} type="linear" dataKey="value" stroke="var(--s1)" strokeWidth={2} dot={{ r: 4, strokeWidth: 2, stroke: "rgb(var(--surface))", fill: "var(--s1)" }} activeDot={{ r: 6 }} connectNulls />
                </LineChart>
              </ResponsiveContainer>
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              {(allSteps ? t.steps : t.steps.slice(-8)).map((s) => (
                <button
                  key={`${s.from}-${s.to}`}
                  onClick={() => {
                    const from = t.points.find((p) => p.ref === s.from);
                    const to = t.points.find((p) => p.ref === s.to);
                    if (from && to) {
                      setBaseline(from.capture_id);
                      setCurrent(to.capture_id);
                    }
                  }}
                  className="inline-flex items-center gap-2 rounded-lg border border-line bg-surface px-2.5 py-1.5 text-[12px] hover:border-accent/40"
                >
                  <span className="font-mono text-ink2">
                    {s.from}→{s.to}
                  </span>
                  <Direction value={s.verdict} />
                  {s.regressions > 0 && <span className="text-crit">−{s.regressions}</span>}
                  {s.improvements > 0 && <span className="text-good">+{s.improvements}</span>}
                </button>
              ))}
              {t.steps.length > 8 && (
                <button onClick={() => setAllSteps((v) => !v)} className="px-2 text-[12px] font-medium text-accent hover:underline">
                  {allSteps ? "Show recent only" : `Show all ${t.steps.length} steps`}
                </button>
              )}
            </div>
          </Card>

          <div className="mb-4 flex flex-col gap-3 rounded-xl border border-line bg-surface p-4 shadow-card sm:flex-row sm:items-center">
            <span className="text-[13px] font-medium text-ink2">Baseline</span>
            {select(baseline, setBaseline)}
            <ArrowRight size={16} className="hidden shrink-0 text-muted sm:block" />
            <span className="text-[13px] font-medium text-ink2">Current</span>
            {select(current, setCurrent)}
          </div>

          {baseline && current && baseline !== current ? (
            <Comparison baseline={baseline} current={current} />
          ) : (
            <Empty title="Choose two different captures to compare" />
          )}
        </>
      )}
    </>
  );
}
