import { ArrowDown, Lock, LockOpen, ShieldAlert, Unplug } from "lucide-react";
import { useParams } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Card, ChartTooltip, Empty, ErrorState, Meter, Mono, PageHeader, Pill, RiskBadge, Spinner, Stat, Table, Td, Th } from "../components/ui";
import { useApi } from "../lib/api";
import { fmtPct, humanize } from "../lib/format";
import type { StarttlsAnalytics } from "../lib/types";

const OWNER_LABEL: Record<string, string> = {
  server: "Server fix",
  client: "Client fix",
  network: "Network path",
  both: "Client + server",
};

export function StarttlsPage() {
  const { captureId } = useParams();
  const res = useApi<StarttlsAnalytics>(`/api/captures/${captureId}/starttls`);
  if (res.error) return <ErrorState error={res.error} onRetry={res.reload} />;
  if (!res.data) return <Spinner />;
  const d = res.data;
  const start = d.funnel[0]?.count || 1;

  return (
    <>
      <PageHeader
        eyebrow="Innovation 5"
        title="STARTTLS failure points & adoption"
        description="An opportunistic upgrade is a chain of steps, each owned by someone different. Every plaintext-start session is placed at the first step it failed, then aggregated per server, per protocol and over the capture's timeline."
      />

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Adoption rate" value={fmtPct(d.summary.adoption_pct)} status={d.summary.adoption_pct === null ? "none" : d.summary.adoption_pct >= 90 ? "good" : d.summary.adoption_pct >= 60 ? "warn" : "crit"} icon={<Lock size={16} />} hint={`${d.summary.upgraded} of ${d.summary.observable} observable sessions`} />
        <Stat label="Cleartext fallbacks" value={d.summary.cleartext_fallbacks} status={d.summary.cleartext_fallbacks ? "crit" : "good"} icon={<LockOpen size={16} />} hint="Mail or credentials sent after a failed / skipped upgrade" />
        <Stat label="Stripped in transit" value={d.summary.stripped} status={d.summary.stripped ? "crit" : "good"} icon={<ShieldAlert size={16} />} hint="Capability line mangled on path" />
        <Stat label="Implicit TLS" value={d.summary.implicit_tls} icon={<Unplug size={16} />} hint={`Bypassed STARTTLS · ${d.summary.unobservable} unobservable`} />
      </div>

      {d.summary.starttls_eligible === 0 ? (
        <Empty title="No plaintext-start sessions">Every session in this capture used implicit TLS, so there is no STARTTLS behaviour to analyse.</Empty>
      ) : (
        <>
          <div className="mb-4 grid gap-4 xl:grid-cols-[1fr_1.2fr]">
            <Card title="Upgrade funnel" subtitle="Observable plaintext-start sessions reaching each stage">
              <div className="space-y-2.5">
                {d.funnel.map((f, i) => (
                  <div key={f.stage}>
                    {i > 0 && f.drop_from_previous > 0 && (
                      <div className="mb-1 flex items-center gap-1 pl-1 text-[11.5px] text-serious">
                        <ArrowDown size={12} /> {f.drop_from_previous} lost
                      </div>
                    )}
                    <div className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1">
                      <span className="truncate text-[13px] text-ink">{f.label}</span>
                      <span className="tabular text-[13px] font-medium text-ink">
                        {f.count} <span className="font-normal text-muted">· {fmtPct(f.pct_of_start)}</span>
                      </span>
                      <div className="col-span-2 h-3 rounded-[4px] bg-line/50">
                        <div
                          className="h-full rounded-[4px] transition-[width] duration-500"
                          style={{ width: `${Math.max(1, (100 * f.count) / start)}%`, background: `var(--ord-${i + 1})` }}
                        />
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </Card>

            <Card title="Where upgrades stop" subtitle="First failed stage, with who owns the fix">
              <div className="space-y-3">
                {d.failure_points.map((f) => (
                  <div key={f.key} className="rounded-lg border border-line p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <RiskBadge risk={f.severity === "ok" ? "ok" : f.severity} label={f.severity === "ok" ? "OK" : f.severity} />
                        <span className="text-[13.5px] font-semibold text-ink">{f.label}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        {f.owner && <Pill>{OWNER_LABEL[f.owner] ?? f.owner}</Pill>}
                        <span className="tabular text-[13px] font-semibold text-ink">
                          {f.count} <span className="font-normal text-muted">({f.pct}%)</span>
                        </span>
                      </div>
                    </div>
                    <p className="mt-1.5 text-[12.5px] leading-snug text-ink2">{f.explanation}</p>
                    {f.key !== "success" && (
                      <div className="mt-2 flex flex-wrap gap-1.5 text-[11.5px]">
                        {f.servers.slice(0, 4).map((s) => (
                          <Mono key={s}>{s}</Mono>
                        ))}
                        {f.examples.slice(0, 3).map((e) => (
                          <span key={e.session_ref} className="text-muted">
                            {e.session_ref}
                            {e.evidence_frame ? ` @#${e.evidence_frame}` : ""}
                          </span>
                        ))}
                        {f.cleartext_fallbacks > 0 && <span className="font-medium text-crit">{f.cleartext_fallbacks} fell back to cleartext</span>}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </Card>
          </div>

          <Card className="mb-4" title="Behaviour over the capture's timeline" subtitle="Sessions per time bucket, split by outcome">
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={d.timeline} margin={{ top: 8, right: 8, bottom: 0, left: -16 }} barCategoryGap="20%">
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="offset_seconds" tickFormatter={(v) => `+${Number(v).toFixed(0)}s`} tickLine={false} />
                  <YAxis allowDecimals={false} tickLine={false} axisLine={false} />
                  <Tooltip
                    cursor={{ fill: "rgb(var(--line) / 0.4)" }}
                    content={({ active, payload }) => {
                      const row = payload?.[0]?.payload as StarttlsAnalytics["timeline"][number] | undefined;
                      return row ? (
                        <ChartTooltip
                          active={active}
                          label={`+${row.offset_seconds.toFixed(1)}s`}
                          rows={[
                            { name: "Upgraded", value: row.upgraded, color: "var(--s1)" },
                            { name: "Failed", value: row.failed, color: "var(--s2)" },
                            { name: "Unobservable", value: row.unobservable, color: "rgb(var(--muted))" },
                            { name: "Adoption", value: fmtPct(row.adoption_pct) },
                          ]}
                        />
                      ) : null;
                    }}
                  />
                  <Legend iconType="square" iconSize={10} wrapperStyle={{ fontSize: 12 }} />
                  <Bar isAnimationActive={false} dataKey="upgraded" name="Upgraded" stackId="a" fill="var(--s1)" stroke="rgb(var(--surface))" strokeWidth={2} />
                  <Bar isAnimationActive={false} dataKey="failed" name="Failed" stackId="a" fill="var(--s2)" stroke="rgb(var(--surface))" strokeWidth={2} />
                  <Bar isAnimationActive={false} dataKey="unobservable" name="Unobservable" stackId="a" fill="rgb(var(--muted))" stroke="rgb(var(--surface))" strokeWidth={2} radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Card>

          <div className="grid gap-4 xl:grid-cols-[2fr_1fr]">
            <Card title="Per-server adoption" subtitle="Lowest adoption first" padded={false}>
              <Table>
                <thead>
                  <tr>
                    <Th>Server</Th>
                    <Th className="w-48">Adoption</Th>
                    <Th className="text-right">Advertised</Th>
                    <Th>Dominant failure</Th>
                    <Th className="text-right">Implicit TLS</Th>
                  </tr>
                </thead>
                <tbody>
                  {d.servers.map((s) => (
                    <tr key={s.key}>
                      <Td>
                        <Mono>{s.key}</Mono>
                        <div className="mt-1 text-[11.5px] text-muted">{s.sessions} plaintext-start session(s)</div>
                      </Td>
                      <Td>
                        <div className="mb-1 tabular text-[13px] font-medium">{fmtPct(s.adoption_pct)}</div>
                        <Meter value={s.adoption_pct} />
                      </Td>
                      <Td className="tabular text-right">{fmtPct(s.advertise_pct)}</Td>
                      <Td className="text-[12.5px]">
                        {s.dominant_failure ? humanize(s.dominant_failure) : <span className="text-muted">—</span>}
                        {s.cleartext_fallbacks > 0 && <div className="text-[11.5px] text-crit">{s.cleartext_fallbacks} cleartext fallback(s)</div>}
                      </Td>
                      <Td className="tabular text-right">{s.implicit_tls_sessions}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </Card>

            <Card title="By protocol">
              <div className="space-y-4">
                {d.protocols.map((p) => (
                  <div key={p.key}>
                    <div className="mb-1 flex justify-between text-[13px]">
                      <span className="font-medium text-ink">{p.key}</span>
                      <span className="tabular text-ink2">
                        {fmtPct(p.adoption_pct)} · {p.observable} obs.
                      </span>
                    </div>
                    <Meter value={p.adoption_pct} />
                  </div>
                ))}
              </div>
              <p className="mt-5 text-[12px] leading-relaxed text-muted">{d.method}</p>
            </Card>
          </div>
        </>
      )}
    </>
  );
}
