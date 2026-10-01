import { FileDown, FlaskConical } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";

import { Dot, ErrorState, InfoTip, Loading, Meter, PageHeader, Panel, StatStrip } from "@/components/common";
import { ScoreGauge } from "@/components/score-gauge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { MoscaTimeline } from "@/components/viz/mosca";
import { exportUrl, usePlan, usePqc, useQuantumForecast } from "@/lib/api";
import { fmtPct } from "@/lib/format";
import type { PqcReadiness } from "@/lib/types";

const TIER_COLOR: Record<string, string> = {
  cleartext: "hsl(var(--sev-critical))",
  static_rsa: "hsl(var(--sev-high))",
  classical: "hsl(var(--sev-medium))",
  pqc_hybrid: "hsl(var(--sev-ok))",
};

function tierColor(tier: string) {
  return TIER_COLOR[tier] ?? (tier.includes("hybrid") || tier.includes("pqc") ? TIER_COLOR.pqc_hybrid : tier.includes("rsa") ? TIER_COLOR.static_rsa : tier.includes("clear") ? TIER_COLOR.cleartext : TIER_COLOR.classical);
}

function serverStatus(s: PqcReadiness["servers"][number]): { label: string; color: string } {
  if (s.pqc_selected > 0) return { label: "Hybrid PQC in use", color: "hsl(var(--sev-ok))" };
  if (s.migration_gap) return { label: "Clients ready, server not", color: "hsl(var(--sev-high))" };
  if (s.tls13 < s.sessions) return { label: "Requires TLS 1.3", color: "hsl(var(--sev-critical))" };
  return { label: "Enable hybrid groups", color: "hsl(var(--sev-medium))" };
}

export function PqcPage() {
  const { captureId } = useParams();
  const { data: q, error } = usePqc(captureId);
  const plan = usePlan(captureId);
  const [shelf, setShelf] = useState(10);
  const forecast = useQuantumForecast(captureId, shelf);

  if (error) return <ErrorState error={error} />;
  if (!q) return <Loading rows={4} />;

  const tlsTotal = Object.values(q.tls_versions ?? {}).reduce((a, b) => a + b, 0);
  const tls13 = q.tls_versions?.["TLS 1.3"] ?? 0;
  const offering = q.components.find((c) => c.key === "client_capability");
  const selected = q.components.find((c) => c.key === "pqc_key_exchange");
  const exposureTotal = q.exposure.reduce((a, t) => a + t.sessions, 0) || 1;
  const pqcStep = plan.data?.steps.find((s) => s.fix_id === "enable_hybrid_pqc");

  return (
    <>
      <PageHeader
        title="Post-quantum readiness"
        description="How much of the observed email traffic already uses quantum-resistant key exchange, and what stands in the way of the rest."
        actions={
          <>
            <Button asChild size="sm" variant="outline" className="h-8">
              <a href={exportUrl(captureId!, "cbom")} download>
                <FileDown className="size-3.5" /> Export CBOM
              </a>
            </Button>
            <Button asChild size="sm" className="h-8">
              <Link to={`/c/${captureId}/remediation${pqcStep ? "?fix=enable_hybrid_pqc" : ""}`}>
                <FlaskConical className="size-3.5" /> {pqcStep ? "Simulate hybrid PQC" : "Remediation plan"}
              </Link>
            </Button>
          </>
        }
      />

      <div className="grid gap-5 lg:grid-cols-[300px_minmax(0,1fr)]">
        <Panel title="Readiness score" info={`${q.formula}. ${q.cap_note ?? ""}`}>
          <div className="flex flex-col items-center gap-2 py-2">
            <ScoreGauge score={q.score} size={210} label={q.level_label ?? "Not assessable"} />
            {q.cap_note && <p className="text-center text-xs text-muted-foreground">{q.cap_note}</p>}
          </div>
        </Panel>

        <Panel title="Harvest-now, decrypt-later exposure" info="Traffic recorded today that a future cryptographically relevant quantum computer could decrypt, grouped by key-exchange protection.">
          <div className="space-y-5">
            <div className="flex items-baseline gap-2">
              <span className="tabular text-3xl font-semibold tracking-tight">{fmtPct(q.hndl_exposed_pct, 1)}</span>
              <span className="text-sm text-muted-foreground">
                of sessions exposed ({q.hndl_exposed_sessions ?? 0} of {exposureTotal})
              </span>
            </div>
            <div className="flex h-3 overflow-hidden rounded-full bg-muted">
              {q.exposure
                .filter((t) => t.sessions > 0)
                .map((t) => (
                  <div key={t.tier} title={`${t.label}: ${t.sessions}`} style={{ width: `${(100 * t.sessions) / exposureTotal}%`, background: tierColor(t.tier) }} />
                ))}
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              {q.exposure.map((t) => (
                <div key={t.tier} className="flex gap-2.5">
                  <Dot color={tierColor(t.tier)} className="mt-1.5" />
                  <div className="min-w-0">
                    <div className="flex items-baseline gap-2 text-sm">
                      <span className="font-medium">{t.label}</span>
                      <span className="tabular text-muted-foreground">
                        {t.sessions} · {t.pct}%
                      </span>
                    </div>
                    <div className="text-xs text-muted-foreground">{t.explanation}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </Panel>
      </div>

      <StatStrip
        items={[
          { label: "TLS 1.3 sessions", value: `${tls13} / ${tlsTotal}`, sub: tlsTotal ? `${fmtPct((100 * tls13) / tlsTotal)} · prerequisite for hybrid groups` : "No TLS observed" },
          { label: "Clients offering hybrid PQC", value: offering ? `${offering.observed} / ${offering.total}` : "—", sub: "X25519MLKEM768 and related groups" },
          { label: "Sessions using hybrid PQC", value: selected ? `${selected.observed} / ${selected.total}` : "—", sub: "Selected by the server" },
          {
            label: "Servers with a migration gap",
            value: q.servers.filter((s) => s.migration_gap).length,
            sub: `of ${q.servers.length} server${q.servers.length === 1 ? "" : "s"}`,
            accent: q.servers.some((s) => s.migration_gap) ? "hsl(var(--sev-high))" : undefined,
          },
        ]}
      />

      <Panel
        title="Quantum risk forecast"
        info={forecast.data ? `${forecast.data.method} Sources: ${forecast.data.sources.join("; ")}.` : undefined}
        actions={
          <label className="flex items-center gap-2 text-xs text-muted-foreground">
            Confidentiality period
            <input type="range" min={1} max={25} value={shelf} onChange={(e) => setShelf(Number(e.target.value))} className="w-32 accent-foreground" />
            <span className="tabular w-14 font-medium text-foreground">{shelf} years</span>
          </label>
        }
      >
        {!forecast.data ? (
          <Loading rows={1} />
        ) : (
          <div className="space-y-4">
            <p className="text-sm">{forecast.data.summary}</p>
            <MoscaTimeline f={forecast.data} />
            <div className="overflow-hidden rounded-md border">
              <Table>
                <TableHeader className="bg-muted/40">
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="h-8 text-xs">Quantum computer scenario</TableHead>
                    <TableHead className="h-8 text-xs">Year</TableHead>
                    <TableHead className="h-8 text-xs">X + Y vs Z</TableHead>
                    <TableHead className="h-8 text-xs">Mosca verdict</TableHead>
                    <TableHead className="h-8 text-xs">Captured sessions still sensitive</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {forecast.data.scenarios.map((r) => (
                    <TableRow key={r.key} className="hover:bg-transparent">
                      <TableCell className="py-2 text-sm">
                        {r.label}
                        <div className="text-xs text-muted-foreground">{r.basis}</div>
                      </TableCell>
                      <TableCell className="tabular py-2 text-sm">{r.year}</TableCell>
                      <TableCell className="tabular py-2 text-xs">
                        {r.x_plus_y} y vs {r.years_from_today} y
                      </TableCell>
                      <TableCell className="py-2">
                        <span className="inline-flex items-center gap-1.5 text-xs font-medium">
                          <Dot color={r.mosca_verdict === "Act now" ? "hsl(var(--sev-critical))" : "hsl(var(--sev-ok))"} className="size-1.5" />
                          {r.mosca_verdict}
                        </span>
                      </TableCell>
                      <TableCell className="tabular py-2 text-xs">
                        {r.exposed_sessions} ({r.exposed_pct}%){r.years_of_exposure > 0 ? ` · ${r.years_of_exposure} y of exposure` : ""}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </div>
        )}
      </Panel>

      <div className="grid gap-5 xl:grid-cols-2">
        <Panel title="Score components" flush info="Each component is scored from observed sessions only; components without evidence are excluded.">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="h-9 pl-4 text-xs">Component</TableHead>
                <TableHead className="h-9 w-16 text-xs">Weight</TableHead>
                <TableHead className="h-9 w-20 text-xs">Evidence</TableHead>
                <TableHead className="h-9 w-40 pr-4 text-xs">Score</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {q.components.map((c) => (
                <TableRow key={c.key} className="hover:bg-transparent">
                  <TableCell className="pl-4 text-sm">{c.label}</TableCell>
                  <TableCell className="tabular text-xs text-muted-foreground">{Math.round(c.weight * 100)}%</TableCell>
                  <TableCell className="tabular text-xs text-muted-foreground">
                    {c.observed}/{c.total}
                  </TableCell>
                  <TableCell className="pr-4">
                    {c.score == null ? (
                      <span className="text-xs text-muted-foreground">No evidence</span>
                    ) : (
                      <div className="flex items-center gap-2">
                        <Meter value={c.score} color={c.score >= 80 ? "hsl(var(--sev-ok))" : c.score >= 40 ? "hsl(var(--sev-medium))" : "hsl(var(--sev-critical))"} />
                        <span className="tabular w-8 text-right text-xs">{c.score}</span>
                      </div>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Panel>

        <Panel title="Key-exchange groups" flush info="How often clients offered each group in the ClientHello, and how often the server selected it.">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="h-9 pl-4 text-xs">Group</TableHead>
                <TableHead className="h-9 text-xs">Type</TableHead>
                <TableHead className="h-9 w-28 text-xs">Offered</TableHead>
                <TableHead className="h-9 w-28 pr-4 text-xs">Selected</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(q.groups ?? []).map((g) => (
                <TableRow key={g.group} className="hover:bg-transparent">
                  <TableCell className="pl-4 font-mono text-xs">{g.group}</TableCell>
                  <TableCell>
                    <span className="inline-flex items-center gap-1.5 text-xs">
                      <Dot color={g.pqc ? "hsl(var(--sev-ok))" : "hsl(var(--sev-medium))"} className="size-1.5" />
                      {g.pqc ? "Hybrid post-quantum" : "Classical"}
                    </span>
                  </TableCell>
                  <TableCell className="tabular text-xs">
                    {g.offered} <span className="text-muted-foreground">({g.offered_pct}%)</span>
                  </TableCell>
                  <TableCell className="tabular pr-4 text-xs">
                    {g.selected ? (
                      <>
                        {g.selected} <span className="text-muted-foreground">({g.selected_pct}%)</span>
                      </>
                    ) : (
                      <span className={g.pqc && g.offered ? "text-sev-high" : "text-muted-foreground"}>{g.pqc && g.offered ? "Never selected" : "0"}</span>
                    )}
                  </TableCell>
                </TableRow>
              ))}
              {!(q.groups ?? []).length && (
                <TableRow className="hover:bg-transparent">
                  <TableCell colSpan={4} className="h-16 text-center text-sm text-muted-foreground">
                    No key-exchange groups observed.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </Panel>
      </div>

      <Panel title="Servers" flush>
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="h-9 pl-4 text-xs">Server</TableHead>
              <TableHead className="h-9 text-xs">Sessions</TableHead>
              <TableHead className="h-9 text-xs">TLS 1.3</TableHead>
              <TableHead className="h-9 text-xs">Clients offering PQC</TableHead>
              <TableHead className="h-9 text-xs">Hybrid selected</TableHead>
              <TableHead className="h-9 text-xs">Dominant group</TableHead>
              <TableHead className="h-9 pr-4 text-xs">Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {q.servers.map((s) => {
              const st = serverStatus(s);
              return (
                <TableRow key={s.server} className="hover:bg-transparent">
                  <TableCell className="pl-4 font-mono text-xs">{s.server}</TableCell>
                  <TableCell className="tabular text-xs">{s.sessions}</TableCell>
                  <TableCell className="tabular text-xs">{s.tls13}</TableCell>
                  <TableCell className="tabular text-xs">{s.clients_offering_pqc}</TableCell>
                  <TableCell className="tabular text-xs">{s.pqc_selected}</TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">{s.dominant_group ?? "—"}</TableCell>
                  <TableCell className="pr-4">
                    <span className="inline-flex items-center gap-1.5 text-xs">
                      <Dot color={st.color} className="size-1.5" />
                      {st.label}
                    </span>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </Panel>

      <Panel
        title="Migration plan"
        info="Steps derived from what blocks readiness in this capture, in order."
        actions={<span className="text-xs text-muted-foreground">{q.standards.join(" · ")}</span>}
      >
        <ol className="space-y-3">
          {q.actions.map((a, i) => (
            <li key={a.priority} className="grid grid-cols-[24px_1fr] gap-2">
              <span className="grid size-5 place-items-center rounded-full border font-mono text-[11px]">{i + 1}</span>
              <div>
                <div className="text-sm font-medium">{a.title}</div>
                <div className="text-sm text-muted-foreground">{a.detail}</div>
              </div>
            </li>
          ))}
          {!q.actions.length && <li className="text-sm text-muted-foreground">No migration steps required.</li>}
        </ol>
        {pqcStep && (
          <div className="mt-4 flex items-center justify-between gap-3 rounded-md border px-3 py-2.5 text-sm">
            <span>
              Configuration for <b>{pqcStep.playbook.software.name ?? "this server"}</b> and a projection of its effect are available.
            </span>
            <Button asChild size="sm" variant="outline" className="h-7">
              <Link to={`/c/${captureId}/remediation?fix=enable_hybrid_pqc`}>Open in remediation</Link>
            </Button>
          </div>
        )}
      </Panel>
      <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
        <InfoTip>{q.framing}</InfoTip>
        {q.framing}
      </p>
    </>
  );
}
