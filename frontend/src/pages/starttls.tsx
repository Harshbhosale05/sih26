import { motion } from "framer-motion";
import { Link, useParams } from "react-router-dom";

import { ErrorState, Loading, Meter, PageHeader, Panel, Stat } from "@/components/common";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useStarttls } from "@/lib/api";
import { fmtPct, riskColor } from "@/lib/format";

const OWNER: Record<string, string> = { server: "Server admin", client: "Client / MUA", network: "Network path", both: "Client + server" };

export function StarttlsPage() {
  const { captureId } = useParams();
  const { data, error } = useStarttls(captureId);
  if (error) return <ErrorState error={error} />;
  if (!data) return <Loading rows={3} />;

  const s = data.summary;
  const start = data.funnel[0]?.count || 1;

  return (
    <div className="space-y-6">
      <PageHeader title="STARTTLS upgrade analysis" description={data.method} />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat label="Adoption" value={fmtPct(s.adoption_pct, 1)} sub={`${s.upgraded} of ${s.observable} observable upgraded`} />
        <Stat label="Implicit TLS" value={s.implicit_tls} sub="no plaintext phase (RFC 8314)" />
        <Stat label="Cleartext fallbacks" value={s.cleartext_fallbacks} color={s.cleartext_fallbacks ? "hsl(var(--sev-critical))" : undefined} />
        <Stat label="Stripped" value={s.stripped} color={s.stripped ? "hsl(var(--sev-critical))" : undefined} sub="capability altered in transit" />
        <Stat label="Unobservable" value={s.unobservable} sub="capture cannot tell" />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Upgrade funnel" description="Plaintext-start sessions, stage by stage.">
          <div className="space-y-3">
            {data.funnel.map((f, i) => (
              <div key={f.stage} className="space-y-1">
                <div className="flex justify-between text-sm">
                  <span>{f.label}</span>
                  <span className="tabular text-muted-foreground">
                    {f.count} {f.pct_of_start != null && `· ${f.pct_of_start}%`}
                    {f.drop_from_previous > 0 && <span className="ml-2 text-sev-high">−{f.drop_from_previous}</span>}
                  </span>
                </div>
                <div className="h-7 overflow-hidden rounded-md bg-muted">
                  <motion.div
                    className="h-full rounded-md"
                    style={{ background: `hsl(var(--primary) / ${1 - i * 0.14})` }}
                    initial={{ width: 0 }}
                    animate={{ width: `${(100 * f.count) / start}%` }}
                    transition={{ duration: 0.6, delay: i * 0.08 }}
                  />
                </div>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="Where upgrades stop — and who owns the fix">
          <div className="space-y-2">
            {data.failure_points.map((f) => (
              <div key={f.key} className="rounded-lg border p-3">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <span className="size-2 rounded-full" style={{ background: f.severity === "ok" ? "hsl(var(--sev-ok))" : riskColor(f.severity) }} />
                    <span className="text-sm font-medium">{f.label}</span>
                  </div>
                  <span className="tabular text-sm">
                    {f.count} <span className="text-xs text-muted-foreground">· {f.pct}%</span>
                  </span>
                </div>
                <div className="mt-1 text-xs text-muted-foreground">{f.explanation}</div>
                <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px]">
                  {f.owner && <span className="rounded border px-1.5 py-0.5">fix owner: {OWNER[f.owner] ?? f.owner}</span>}
                  {f.examples.slice(0, 4).map((e) => (
                    <Link key={e.session_ref} to={`/c/${captureId}/sessions/${e.session_ref}`} className="rounded border px-1.5 py-0.5 font-mono hover:bg-muted">
                      {e.session_ref}
                    </Link>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      <Panel title="Per server">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Server</TableHead>
              <TableHead className="text-right">Sessions</TableHead>
              <TableHead className="w-[200px]">Adoption</TableHead>
              <TableHead className="w-[200px]">Advertised</TableHead>
              <TableHead>Dominant failure</TableHead>
              <TableHead className="text-right">Fallbacks</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.servers.map((srv) => (
              <TableRow key={srv.key}>
                <TableCell className="font-mono text-xs">{srv.key}</TableCell>
                <TableCell className="tabular text-right">{srv.sessions}</TableCell>
                <TableCell>
                  <div className="flex items-center gap-2">
                    <Meter value={srv.adoption_pct} color={(srv.adoption_pct ?? 0) >= 95 ? "hsl(var(--sev-ok))" : "hsl(var(--sev-high))"} />
                    <span className="tabular w-12 text-right text-xs">{fmtPct(srv.adoption_pct)}</span>
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-2">
                    <Meter value={srv.advertise_pct} />
                    <span className="tabular w-12 text-right text-xs">{fmtPct(srv.advertise_pct)}</span>
                  </div>
                </TableCell>
                <TableCell className="text-xs">{srv.dominant_failure?.replace(/_/g, " ") ?? "—"}</TableCell>
                <TableCell className="tabular text-right">{srv.cleartext_fallbacks}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Panel>
    </div>
  );
}
