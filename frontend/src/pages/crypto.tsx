import type { ColumnDef } from "@tanstack/react-table";
import { useMemo } from "react";
import { Bar, BarChart, CartesianGrid, Cell, XAxis, YAxis } from "recharts";
import { useNavigate, useParams } from "react-router-dom";

import { Dot, ErrorState, Loading, Meter, PageHeader, Panel, StatStrip, Tag } from "@/components/common";
import { DataTable, SortHeader } from "@/components/data-table";
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useOverview, usePosture, useSessions } from "@/lib/api";
import { fmtPct } from "@/lib/format";

const VERSION_COLOR: Record<string, string> = {
  "TLS 1.3": "hsl(var(--sev-ok))",
  "TLS 1.2": "hsl(var(--sev-low))",
  "TLS 1.1": "hsl(var(--sev-high))",
  "TLS 1.0": "hsl(var(--sev-critical))",
  "SSL 3.0": "hsl(var(--sev-critical))",
};

function suiteWeakness(name: string): string | null {
  if (/RC4|3DES|NULL|EXPORT|_DES_/.test(name)) return "Broken cipher";
  if (/^TLS_RSA_WITH/.test(name)) return "No forward secrecy";
  if (/CBC/.test(name)) return "CBC mode";
  return null;
}

type SuiteRow = { suite: string; sessions: number; versions: string; fs: boolean | null; aead: boolean | null; weakness: string | null };

const suiteColumns: ColumnDef<SuiteRow, unknown>[] = [
  { accessorKey: "suite", header: ({ column }) => <SortHeader column={column} title="Cipher suite" />, cell: ({ row }) => <span className="font-mono text-xs">{row.original.suite}</span> },
  { accessorKey: "versions", header: "Version", cell: ({ row }) => <span className="text-xs">{row.original.versions}</span>, size: 90 },
  { id: "fs", header: "Forward secrecy", cell: ({ row }) => <span className={row.original.fs ? "text-xs" : "text-xs text-sev-critical"}>{row.original.fs ? "Yes" : "No"}</span>, size: 120 },
  { id: "aead", header: "AEAD", cell: ({ row }) => <span className={row.original.aead ? "text-xs" : "text-xs text-sev-high"}>{row.original.aead ? "Yes" : "No"}</span>, size: 70 },
  {
    accessorKey: "weakness",
    header: "Assessment",
    cell: ({ row }) =>
      row.original.weakness ? (
        <span className="inline-flex items-center gap-1.5 text-xs">
          <Dot color="hsl(var(--sev-high))" className="size-1.5" />
          {row.original.weakness}
        </span>
      ) : (
        <span className="inline-flex items-center gap-1.5 text-xs">
          <Dot color="hsl(var(--sev-ok))" className="size-1.5" />
          Acceptable
        </span>
      ),
    size: 150,
  },
  { accessorKey: "sessions", header: ({ column }) => <SortHeader column={column} title="Sessions" />, cell: ({ row }) => <span className="tabular">{row.original.sessions}</span>, size: 90 },
];

export function CryptoPage() {
  const { captureId } = useParams();
  const navigate = useNavigate();
  const overview = useOverview(captureId);
  const posture = usePosture(captureId);
  const sessions = useSessions(captureId);

  const suites = useMemo<SuiteRow[]>(() => {
    const m = new Map<string, SuiteRow & { vset: Set<string> }>();
    for (const s of sessions.data ?? []) {
      if (!s.tls_cipher_suite) continue;
      const e = m.get(s.tls_cipher_suite) ?? { suite: s.tls_cipher_suite, sessions: 0, versions: "", fs: s.tls_forward_secrecy, aead: s.tls_aead, weakness: suiteWeakness(s.tls_cipher_suite), vset: new Set<string>() };
      e.sessions++;
      if (s.tls_version) e.vset.add(s.tls_version);
      m.set(s.tls_cipher_suite, e);
    }
    return [...m.values()].map(({ vset, ...r }) => ({ ...r, versions: [...vset].join(", ") }));
  }, [sessions.data]);

  const groups = useMemo(() => {
    const m = new Map<string, number>();
    for (const s of sessions.data ?? []) {
      if (!s.tls_version) continue;
      const k = s.tls_selected_group ?? (s.tls_forward_secrecy === false ? "RSA key transport" : "Not visible (TLS 1.2 ECDHE)");
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
  const certSessions = sessions.data.filter((s) => s.cert_observable);
  const versionConfig = { count: { label: "Sessions", color: "hsl(var(--primary))" } } satisfies ChartConfig;
  const deprecated = (o.crypto.by_tls_version["TLS 1.0"] ?? 0) + (o.crypto.by_tls_version["TLS 1.1"] ?? 0) + (o.crypto.by_tls_version["SSL 3.0"] ?? 0);

  return (
    <>
      <PageHeader title="Cryptography" description="Protocol versions, cipher suites, key exchange and certificates negotiated in the capture." />

      <StatStrip
        items={[
          { label: "TLS sessions", value: `${o.coverage.tls_sessions} / ${o.sessions.total}` },
          { label: "TLS 1.3", value: fmtPct((100 * (o.crypto.by_tls_version["TLS 1.3"] ?? 0)) / tlsTotal) },
          { label: "Deprecated versions", value: deprecated, accent: deprecated ? "hsl(var(--sev-critical))" : undefined, sub: "TLS 1.0, 1.1, SSL 3.0" },
          { label: "Forward secrecy", value: fmtPct((100 * o.crypto.forward_secrecy) / tlsTotal) },
          { label: "Certificates examined", value: o.coverage.certificate_observable, info: o.coverage.note },
        ]}
      />

      <div className="grid gap-5 xl:grid-cols-[380px_minmax(0,1fr)]">
        <div className="space-y-5">
          <Panel title="Protocol versions">
            <ChartContainer config={versionConfig} className="h-[150px] w-full">
              <BarChart data={versions} layout="vertical" margin={{ left: 4, right: 16 }}>
                <CartesianGrid horizontal={false} />
                <XAxis type="number" allowDecimals={false} tickLine={false} axisLine={false} fontSize={11} />
                <YAxis type="category" dataKey="version" tickLine={false} axisLine={false} width={58} fontSize={12} />
                <ChartTooltip content={<ChartTooltipContent hideIndicator />} />
                <Bar dataKey="count" radius={[0, 3, 3, 0]} barSize={18} isAnimationActive={false}>
                  {versions.map((v) => (
                    <Cell key={v.version} fill={VERSION_COLOR[v.version] ?? "hsl(var(--sev-info))"} />
                  ))}
                </Bar>
              </BarChart>
            </ChartContainer>
          </Panel>
          <Panel title="Key exchange">
            <div className="space-y-2.5">
              {groups.map(([g, n]) => (
                <div key={g} className="space-y-1">
                  <div className="flex justify-between text-xs">
                    <span className="font-mono">{g}</span>
                    <span className="tabular text-muted-foreground">{n}</span>
                  </div>
                  <Meter value={(100 * n) / tlsTotal} color={/MLKEM|Kyber/i.test(g) ? "hsl(var(--sev-ok))" : g.startsWith("RSA") ? "hsl(var(--sev-critical))" : "hsl(var(--muted-foreground))"} />
                </div>
              ))}
              {!groups.length && <div className="text-sm text-muted-foreground">No TLS handshakes observed.</div>}
            </div>
          </Panel>
        </div>

        <div className="min-w-0 space-y-2">
          <h2 className="text-sm font-medium">Cipher suites</h2>
          <DataTable columns={suiteColumns} data={suites} searchPlaceholder="Search cipher suites" initialSorting={[{ id: "sessions", desc: true }]} pageSize={10} />
        </div>
      </div>

      <Panel title="Server fingerprints" flush info="Each server's dominant negotiated parameters. Sessions that deviate are marked on the Sessions tab.">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="h-9 pl-4 text-xs">Server</TableHead>
              <TableHead className="h-9 text-xs">Sessions</TableHead>
              <TableHead className="h-9 text-xs">Baseline</TableHead>
              {["tls_version", "cipher_suite", "key_group", "ja4s"].map((k) => (
                <TableHead key={k} className="h-9 text-xs">
                  {{ tls_version: "TLS", cipher_suite: "Cipher suite", key_group: "Group", ja4s: "JA4S" }[k]}
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {posture.data.fingerprints.map((f) => (
              <TableRow key={f.server} className="hover:bg-transparent">
                <TableCell className="pl-4">
                  <div className="font-mono text-xs">{f.server}</div>
                  {f.banner && <div className="max-w-[260px] truncate text-[11px] text-muted-foreground">{f.banner}</div>}
                </TableCell>
                <TableCell className="tabular text-xs">{f.sessions}</TableCell>
                <TableCell className="text-xs text-muted-foreground">{f.has_baseline ? "Established" : "Too few sessions"}</TableCell>
                {["tls_version", "cipher_suite", "key_group", "ja4s"].map((k) => {
                  const top = f.dimensions[k]?.values?.[0];
                  return (
                    <TableCell key={k} className="max-w-[220px]">
                      {top ? (
                        <Tag className="max-w-full truncate">
                          {top.value.replace(/^TLS_/, "")} · {Math.round(top.share * 100)}%
                        </Tag>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </TableCell>
                  );
                })}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Panel>

      <Panel title="Certificates" flush info="Certificates are visible only in TLS 1.2 and earlier; TLS 1.3 encrypts the certificate message.">
        {certSessions.length ? (
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="h-9 pl-4 text-xs">Session</TableHead>
                <TableHead className="h-9 text-xs">Server</TableHead>
                <TableHead className="h-9 text-xs">Name (SNI)</TableHead>
                <TableHead className="h-9 text-xs">TLS</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {certSessions.map((s) => (
                <TableRow key={s.ref} className="cursor-pointer" onClick={() => navigate(`/c/${captureId}/sessions/${s.ref}`)}>
                  <TableCell className="pl-4 font-mono text-xs">{s.ref}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {s.server_ip}:{s.server_port}
                  </TableCell>
                  <TableCell className="text-xs">{s.tls_sni ?? "—"}</TableCell>
                  <TableCell className="text-xs">{s.tls_version}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <div className="p-4 text-sm text-muted-foreground">{o.coverage.note}</div>
        )}
      </Panel>
    </>
  );
}
