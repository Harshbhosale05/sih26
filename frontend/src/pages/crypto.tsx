import { ArrowRight } from "lucide-react";
import { useMemo } from "react";
import { Bar, BarChart, CartesianGrid, Cell, XAxis, YAxis } from "recharts";
import { Link, useParams } from "react-router-dom";

import { ErrorState, Loading, Meter, PageHeader, Panel, Stat, Tag } from "@/components/common";
import { ScoreGauge } from "@/components/score-gauge";
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useOverview, usePosture, useSessions } from "@/lib/api";
import { fmtPct, riskColor } from "@/lib/format";
import type { Session } from "@/lib/types";

const VERSION_COLOR: Record<string, string> = {
  "TLS 1.3": "hsl(var(--sev-ok))",
  "TLS 1.2": "hsl(var(--sev-low))",
  "TLS 1.1": "hsl(var(--sev-high))",
  "TLS 1.0": "hsl(var(--sev-critical))",
  "SSL 3.0": "hsl(var(--sev-critical))",
};

function suiteWeakness(name: string): string | null {
  if (/RC4|3DES|NULL|EXPORT|_DES_/.test(name)) return "broken cipher";
  if (/^TLS_RSA_WITH/.test(name)) return "no forward secrecy";
  if (/CBC/.test(name)) return "CBC mode";
  return null;
}

export function CryptoPage() {
  const { captureId } = useParams();
  const overview = useOverview(captureId);
  const posture = usePosture(captureId);
  const sessions = useSessions(captureId);

  const suites = useMemo(() => {
    const m = new Map<string, { n: number; fs: boolean | null; aead: boolean | null; version: Set<string> }>();
    for (const s of sessions.data ?? []) {
      if (!s.tls_cipher_suite) continue;
      const e = m.get(s.tls_cipher_suite) ?? { n: 0, fs: s.tls_forward_secrecy, aead: s.tls_aead, version: new Set<string>() };
      e.n++;
      if (s.tls_version) e.version.add(s.tls_version);
      m.set(s.tls_cipher_suite, e);
    }
    return [...m.entries()].sort((a, b) => b[1].n - a[1].n);
  }, [sessions.data]);

  const groups = useMemo(() => {
    const m = new Map<string, number>();
    for (const s of sessions.data ?? []) {
      if (!s.tls_version) continue;
      const k = s.tls_selected_group ?? (s.tls_forward_secrecy === false ? "RSA key transport" : "not visible (TLS ≤ 1.2 ECDHE)");
      m.set(k, (m.get(k) ?? 0) + 1);
    }
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [sessions.data]);

  if (overview.error || posture.error) return <ErrorState error={overview.error ?? posture.error} />;
  if (!overview.data || !posture.data || !sessions.data) return <Loading rows={4} />;

  const o = overview.data;
  const tlsTotal = o.coverage.tls_sessions || 1;
  const versions = Object.entries(o.crypto.by_tls_version)
    .sort((a, b) => b[0].localeCompare(a[0]))
    .map(([version, count]) => ({ version, count }));
  const pqc = posture.data.pqc_readiness;
  const certSessions = sessions.data.filter((s: Session) => s.cert_observable);
  const versionConfig = { count: { label: "Sessions", color: "hsl(var(--primary))" } } satisfies ChartConfig;

  return (
    <div className="space-y-6">
      <PageHeader title="Cryptography" description="What was actually negotiated: protocol versions, cipher suites, key exchange, certificates, per-server behaviour and readiness for post-quantum migration." />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat label="TLS sessions" value={o.coverage.tls_sessions} sub={`of ${o.sessions.total} email sessions`} />
        <Stat label="TLS 1.3 share" value={fmtPct((100 * (o.crypto.by_tls_version["TLS 1.3"] ?? 0)) / tlsTotal)} color={VERSION_COLOR["TLS 1.3"]} />
        <Stat label="Forward secrecy" value={fmtPct((100 * o.crypto.forward_secrecy) / tlsTotal)} sub={`${o.crypto.forward_secrecy} of ${o.coverage.tls_sessions}`} />
        <Stat label="Hybrid PQC selected" value={o.crypto.pqc_selected} sub={`${o.crypto.pqc_offered} client(s) offered it`} />
        <Stat label="Certificates examined" value={o.coverage.certificate_observable} sub={o.coverage.note.slice(0, 80)} />
      </div>

      <div className="grid gap-4 xl:grid-cols-[1fr_1.4fr]">
        <Panel title="Negotiated protocol versions" description="RFC 8996 deprecates TLS 1.0 and 1.1.">
          <ChartContainer config={versionConfig} className="h-[200px] w-full">
            <BarChart data={versions} layout="vertical" margin={{ left: 10, right: 20 }}>
              <CartesianGrid horizontal={false} />
              <XAxis type="number" allowDecimals={false} tickLine={false} axisLine={false} fontSize={11} />
              <YAxis type="category" dataKey="version" tickLine={false} axisLine={false} width={64} fontSize={12} />
              <ChartTooltip content={<ChartTooltipContent hideIndicator />} />
              <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={22}>
                {versions.map((v) => (
                  <Cell key={v.version} fill={VERSION_COLOR[v.version] ?? "hsl(var(--sev-info))"} />
                ))}
              </Bar>
            </BarChart>
          </ChartContainer>
          <div className="mt-4 space-y-2">
            <div className="text-xs font-medium text-muted-foreground">Key exchange</div>
            {groups.map(([g, n]) => (
              <div key={g} className="flex items-center gap-3 text-xs">
                <span className="w-44 truncate font-mono">{g}</span>
                <Meter value={(100 * n) / tlsTotal} color={/MLKEM|Kyber/i.test(g) ? "hsl(var(--sev-ok))" : g.startsWith("RSA") ? "hsl(var(--sev-critical))" : "hsl(var(--chart-3))"} />
                <span className="tabular w-8 text-right text-muted-foreground">{n}</span>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="Cipher suites" description="Decomposed from the ServerHello. Static RSA, CBC, 3DES and RC4 are flagged.">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Suite</TableHead>
                <TableHead>Version</TableHead>
                <TableHead className="text-center">FS</TableHead>
                <TableHead className="text-center">AEAD</TableHead>
                <TableHead className="text-right">Sessions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {suites.map(([name, e]) => {
                const weak = suiteWeakness(name);
                return (
                  <TableRow key={name}>
                    <TableCell>
                      <div className="font-mono text-xs">{name}</div>
                      {weak && <div className="text-[11px] font-medium text-sev-high">{weak}</div>}
                    </TableCell>
                    <TableCell className="text-xs">{[...e.version].join(", ")}</TableCell>
                    <TableCell className="text-center text-xs">{e.fs ? "✓" : <span className="text-sev-critical">✗</span>}</TableCell>
                    <TableCell className="text-center text-xs">{e.aead ? "✓" : <span className="text-sev-high">✗</span>}</TableCell>
                    <TableCell className="tabular text-right">{e.n}</TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </Panel>
      </div>

      <Panel title="Post-quantum readiness" description={pqc.framing}>
        <div className="grid gap-6 lg:grid-cols-[220px_1fr_1fr]">
          <div className="flex flex-col items-center">
            <ScoreGauge score={pqc.score} size={190} label={pqc.level_label ?? "not assessable"} />
            {pqc.cap_note && <div className="mt-2 text-center text-[11px] text-muted-foreground">{pqc.cap_note}</div>}
          </div>
          <div className="space-y-2">
            <div className="text-xs font-medium text-muted-foreground">Harvest-now-decrypt-later exposure</div>
            {pqc.exposure.map((t) => (
              <div key={t.tier} className="space-y-1">
                <div className="flex justify-between text-xs">
                  <span>{t.label}</span>
                  <span className="tabular text-muted-foreground">
                    {t.sessions} · {t.pct}%
                  </span>
                </div>
                <Meter value={t.pct} color={t.tier === "pqc_hybrid" ? "hsl(var(--sev-ok))" : riskColor(t.risk)} />
              </div>
            ))}
          </div>
          <div className="space-y-2">
            <div className="text-xs font-medium text-muted-foreground">Migration steps</div>
            <ol className="space-y-2">
              {pqc.actions.map((a) => (
                <li key={a.priority} className="text-sm">
                  <span className="mr-1.5 font-mono text-xs text-muted-foreground">{a.priority}.</span>
                  <b>{a.title}.</b> <span className="text-muted-foreground">{a.detail}</span>
                </li>
              ))}
            </ol>
          </div>
        </div>
      </Panel>

      <Panel title="Server cryptographic fingerprints" description="Each server's established behaviour; sessions deviating from it are flagged on the Sessions page.">
        <div className="grid gap-3 lg:grid-cols-2">
          {posture.data.fingerprints.map((f) => (
            <div key={f.server} className="rounded-lg border p-3">
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-sm font-medium">{f.server}</span>
                <span className="text-xs text-muted-foreground">
                  {f.sessions} sessions · {f.has_baseline ? "baseline established" : "too few for baseline"}
                </span>
              </div>
              {f.banner && <div className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">“{f.banner}”</div>}
              <div className="mt-2 space-y-1.5">
                {Object.entries(f.dimensions)
                  .filter(([, d]) => d.values.length)
                  .slice(0, 6)
                  .map(([k, d]) => (
                    <div key={k} className="flex items-center gap-2 text-xs">
                      <span className="w-28 shrink-0 text-muted-foreground">{d.name}</span>
                      <div className="flex min-w-0 flex-wrap gap-1">
                        {d.values.slice(0, 3).map((v) => (
                          <Tag key={v.value}>
                            {v.value} · {Math.round(v.share * 100)}%
                          </Tag>
                        ))}
                      </div>
                    </div>
                  ))}
              </div>
            </div>
          ))}
        </div>
      </Panel>

      <Panel title="Certificates" description="Visible only on TLS ≤ 1.2 (TLS 1.3 encrypts the Certificate message). Open a session to see the full chain and link verification.">
        {certSessions.length ? (
          <div className="flex flex-wrap gap-2">
            {certSessions.map((s) => (
              <Link key={s.ref} to={`/c/${captureId}/sessions/${s.ref}`} className="flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-xs hover:bg-muted">
                <span className="font-mono">{s.ref}</span>
                <span className="text-muted-foreground">{s.tls_sni ?? s.server_ip}</span>
                <ArrowRight className="size-3 text-muted-foreground" />
              </Link>
            ))}
          </div>
        ) : (
          <div className="text-sm text-muted-foreground">{o.coverage.note}</div>
        )}
      </Panel>
    </div>
  );
}
