import { Download, Search } from "lucide-react";
import { ReactNode, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { Card, Drawer, ErrorState, Mono, PageHeader, Pill, RiskBadge, Spinner, Table, Td, Th } from "../components/ui";
import { useApi } from "../lib/api";
import { humanize, SECURE_STATES, UNKNOWN_STATES } from "../lib/format";
import type { Session, SessionDetail } from "../lib/types";

function StateBadge({ state }: { state: string }) {
  const risk = SECURE_STATES.has(state) ? "ok" : UNKNOWN_STATES.has(state) ? "unknown" : "high";
  return <RiskBadge risk={risk} label={humanize(state)} />;
}

function SessionPanel({ captureId, ref_ }: { captureId: string; ref_: string }) {
  const res = useApi<SessionDetail>(`/api/captures/${captureId}/sessions/${ref_}`);
  if (res.error) return <ErrorState error={res.error} />;
  if (!res.data) return <Spinner />;
  const s = res.data;

  const facts: [string, ReactNode][] = [
    ["Client", <Mono>{`${s.client_ip}:${s.client_port}`}</Mono>],
    ["Server", <Mono>{`${s.server_ip}:${s.server_port}`}</Mono>],
    ["Banner", s.server_banner ?? "—"],
    ["TLS version", s.tls_version ?? "—"],
    ["Cipher suite", s.tls_cipher_suite ?? "—"],
    ["Key group", s.tls_selected_group ?? "—"],
    ["SNI", s.tls_sni ?? "—"],
    ["JA4 / JA4S", s.tls_ja4 ? `${s.tls_ja4} / ${s.tls_ja4s ?? "—"}` : "—"],
    ["Forward secrecy", s.tls_forward_secrecy === null ? "—" : s.tls_forward_secrecy ? "yes" : "no"],
    ["PQC offered / selected", `${s.tls_pqc_offered ? "yes" : "no"} / ${s.tls_pqc_selected ? "yes" : "no"}`],
    ["Frames", `${s.first_frame} – ${s.last_frame}`],
  ];

  return (
    <div className="space-y-6">
      <dl className="grid gap-x-4 gap-y-2 text-[13px] sm:grid-cols-[160px_1fr]">
        {facts.map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-ink2">{k}</dt>
            <dd className="min-w-0 break-words text-ink">{v}</dd>
          </div>
        ))}
      </dl>

      <div>
        <h3 className="mb-3 text-[12px] font-semibold uppercase tracking-wider text-muted">Encryption state machine</h3>
        <ol className="relative space-y-3 border-l border-line pl-5">
          {(s.state_transitions ?? []).map((t, i) => (
            <li key={i} className="relative">
              <span className="absolute -left-[26px] top-1 h-2.5 w-2.5 rounded-full border-2 border-surface bg-accent" />
              <div className="text-[13px] text-ink">
                {humanize(t.from)} → <span className="font-semibold">{humanize(t.to)}</span>
              </div>
              <div className="text-[12px] text-muted">
                frame #{t.frame} · {t.trigger}
              </div>
            </li>
          ))}
        </ol>
      </div>

      <div>
        <h3 className="mb-2 text-[12px] font-semibold uppercase tracking-wider text-muted">Protocol events</h3>
        <div className="max-h-96 overflow-auto rounded-lg border border-line">
          {(s.events ?? []).map((e, i) => (
            <div key={i} className="flex gap-3 border-b border-line/70 bg-surface px-3 py-1.5 font-mono text-[11.5px] last:border-0">
              <span className="w-12 shrink-0 text-muted">#{e.frame}</span>
              <span className="w-36 shrink-0 truncate text-accent">{e.kind}</span>
              <span className="min-w-0 break-all text-ink">{e.detail}</span>
            </div>
          ))}
        </div>
      </div>

      <div>
        <div className="mb-1 text-[12px] text-muted">Wireshark filter</div>
        <pre className="overflow-x-auto rounded-md bg-raised p-2.5 font-mono text-[12px] text-ink ring-1 ring-inset ring-line">{s.wireshark_filter}</pre>
        <a
          href={`/api/captures/${captureId}/sessions/${s.ref}/pcap`}
          className="mt-3 inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-2 text-[13px] font-medium text-white hover:brightness-110"
        >
          <Download size={14} /> Download session frames
        </a>
      </div>
    </div>
  );
}

export function SessionsPage() {
  const { captureId } = useParams();
  const res = useApi<Session[]>(`/api/captures/${captureId}/sessions`);
  const [query, setQuery] = useState("");
  const [protocol, setProtocol] = useState("ALL");
  const [open, setOpen] = useState<string | null>(null);

  const rows = useMemo(() => {
    const q = query.toLowerCase();
    return (res.data ?? []).filter(
      (s) =>
        (protocol === "ALL" || s.protocol === protocol) &&
        (!q || [s.ref, s.client_ip, s.server_ip, s.encryption_state, s.tls_version ?? "", s.tls_cipher_suite ?? ""].some((v) => v.toLowerCase().includes(q))),
    );
  }, [res.data, query, protocol]);

  if (res.error) return <ErrorState error={res.error} onRetry={res.reload} />;
  if (!res.data) return <Spinner />;
  const protocols = [...new Set(res.data.map((s) => s.protocol).filter(Boolean))] as string[];

  return (
    <>
      <PageHeader eyebrow="Reconstruction" title="Sessions" description="Every reconstructed SMTP, IMAP and POP3 session with its encryption lifecycle and negotiated cryptography." />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <select
          value={protocol}
          onChange={(e) => setProtocol(e.target.value)}
          className="rounded-lg border border-line bg-surface px-3 py-2 text-[13px] text-ink focus:outline-none focus:ring-2 focus:ring-accent/40"
        >
          <option value="ALL">All protocols</option>
          {protocols.map((p) => (
            <option key={p}>{p}</option>
          ))}
        </select>
        <label className="relative w-full sm:w-72">
          <Search size={15} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter by ref, IP, state, cipher…"
            className="w-full rounded-lg border border-line bg-surface py-2 pl-9 pr-3 text-[13px] text-ink placeholder:text-muted focus:outline-none focus:ring-2 focus:ring-accent/40"
          />
        </label>
        <span className="text-[13px] text-muted">{rows.length} session(s)</span>
      </div>

      <Card padded={false}>
        <Table>
          <thead>
            <tr>
              <Th>Session</Th>
              <Th>Client → Server</Th>
              <Th>Encryption</Th>
              <Th>TLS</Th>
              <Th>Signals</Th>
            </tr>
          </thead>
          <tbody>
            {rows.map((s) => (
              <tr key={s.ref} onClick={() => setOpen(s.ref)} className="cursor-pointer hover:bg-raised/60">
                <Td>
                  <div className="font-mono text-[12.5px] font-medium">{s.ref}</div>
                  <div className="text-[11.5px] text-muted">{s.protocol}</div>
                </Td>
                <Td className="font-mono text-[12px]">
                  {s.client_ip}
                  <span className="text-muted"> → </span>
                  {s.server_ip}:{s.server_port}
                </Td>
                <Td>
                  <StateBadge state={s.encryption_state} />
                </Td>
                <Td className="text-[12.5px]">
                  {s.tls_version ?? <span className="text-muted">—</span>}
                  {s.tls_cipher_suite && <div className="max-w-[220px] truncate font-mono text-[11px] text-muted">{s.tls_cipher_suite}</div>}
                </Td>
                <Td>
                  <div className="flex flex-wrap gap-1">
                    {s.cleartext_auth_observed && <RiskBadge risk="critical" label="creds" />}
                    {s.tls_pqc_selected && <Pill tone="accent">PQC</Pill>}
                    {s.is_anomalous && <Pill>anomalous</Pill>}
                    {(s.baseline_deviation_score ?? 0) > 0 && <Pill>deviates</Pill>}
                  </div>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Card>

      <Drawer
        open={open !== null}
        onClose={() => setOpen(null)}
        title={<div className="font-mono text-[15px] font-semibold text-ink">{open}</div>}
      >
        {open && captureId && <SessionPanel captureId={captureId} ref_={open} />}
      </Drawer>
    </>
  );
}
