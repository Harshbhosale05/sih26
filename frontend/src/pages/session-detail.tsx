import { ArrowRight, Download, ShieldQuestion } from "lucide-react";
import { Link, useParams } from "react-router-dom";

import {
  CodeLine,
  Empty,
  ErrorState,
  KeyValue,
  Loading,
  PageHeader,
  Panel,
  RiskBadge,
  SeverityBadge,
  StateBadge,
  Tag,
} from "@/components/common";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { CertChain } from "@/components/viz/cert-chain";
import { Ladder } from "@/components/viz/ladder";
import { RiskDrivers } from "@/components/viz/risk-drivers";
import { StatePath } from "@/components/viz/state-path";
import { sessionPcapUrl, useFindings, useSession } from "@/lib/api";

function Yes({ v, good = true }: { v: boolean | null | undefined; good?: boolean }) {
  if (v == null) return <span className="text-muted-foreground">—</span>;
  const ok = good ? v : !v;
  return <span className={ok ? "text-sev-ok" : "text-sev-critical"}>{v ? "yes" : "no"}</span>;
}

export function SessionDetailPage() {
  const { captureId, ref } = useParams();
  const { data: s, error } = useSession(captureId, ref);
  const findings = useFindings(captureId);

  if (error) return <ErrorState error={error} />;
  if (!s) return <Loading rows={4} />;

  const tls = s.tls_detail ?? {};
  const suite = tls.cipher_suite;
  const cert = tls.certificate;
  const related = (findings.data ?? []).filter((f) => f.session_ref === s.ref || (f.evidence as { affected_session?: string } | null)?.affected_session === s.ref);

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow={`${s.protocol} session · stream ${s.stream_index ?? "—"} · frames ${s.first_frame}–${s.last_frame}`}
        title={
          <span className="flex flex-wrap items-center gap-2 font-mono">
            {s.ref}
            <StateBadge state={s.encryption_state} className="font-sans" />
            <RiskBadge risk={s.risk_class} score={s.risk_score} className="font-sans" />
          </span>
        }
        description={
          <span className="font-mono text-xs">
            {s.client_ip}:{s.client_port} → {s.server_ip}:{s.server_port}
            {s.server_banner ? ` · “${s.server_banner}”` : ""}
          </span>
        }
        actions={
          <Button asChild size="sm" variant="outline">
            <a href={sessionPcapUrl(captureId!, s.ref)}>
              <Download className="size-3.5" /> Session .pcapng
            </a>
          </Button>
        }
      />

      <Panel title="Encryption state path">
        <StatePath transitions={s.state_transitions ?? []} finalState={s.encryption_state} />
      </Panel>

      <Tabs defaultValue="conversation">
        <TabsList>
          <TabsTrigger value="conversation">Conversation</TabsTrigger>
          <TabsTrigger value="tls">TLS handshake</TabsTrigger>
          <TabsTrigger value="certificate">Certificate chain</TabsTrigger>
          <TabsTrigger value="risk">Risk & behaviour</TabsTrigger>
          <TabsTrigger value="findings">Findings ({related.length})</TabsTrigger>
        </TabsList>

        <TabsContent value="conversation">
          <Panel title="Reconstructed conversation" description="Reassembled from TCP segments with frame provenance for every line. Encrypted records are counted, never read.">
            <Ladder
              events={s.events ?? []}
              transitions={s.state_transitions ?? []}
              client={`${s.client_ip}:${s.client_port}`}
              server={`${s.server_ip}:${s.server_port}`}
              firstFrame={s.first_frame}
              lastFrame={s.last_frame}
              implicit={s.encryption_state === "IMPLICIT_TLS"}
              highlight={related.flatMap((f) => f.evidence_frames ?? [])}
              tls={{ version: s.tls_version, cipher: s.tls_cipher_suite, offered: tls.versions_offered }}
            />
            <div className="mt-3">
              <CodeLine>{s.wireshark_filter}</CodeLine>
            </div>
          </Panel>
        </TabsContent>

        <TabsContent value="tls" className="space-y-4">
          {!s.tls_version ? (
            <Empty title="No TLS handshake in this session">The session never started TLS, so there is no negotiation to analyse.</Empty>
          ) : (
            <div className="grid gap-4 lg:grid-cols-2">
              <Panel title="Negotiated parameters">
                <KeyValue
                  rows={[
                    ["Version", <span className="font-medium">{s.tls_version}</span>],
                    ["Offered versions", tls.versions_offered?.join(", ") ?? "—"],
                    ["Cipher suite", <span className="font-mono text-xs">{suite?.name ?? s.tls_cipher_suite}</span>],
                    ["Key exchange", suite?.key_exchange ?? (s.tls_version === "TLS 1.3" ? `(EC)DHE · ${s.tls_selected_group ?? "group n/a"}` : "—")],
                    ["Authentication", suite?.authentication ?? "from certificate"],
                    ["Encryption", suite ? `${suite.encryption ?? "—"} ${suite.key_size ?? ""} ${suite.mode ?? ""}` : "—"],
                    ["MAC / PRF hash", suite?.mac_hash ?? "—"],
                    ["Forward secrecy", <Yes v={s.tls_forward_secrecy} />],
                    ["AEAD", <Yes v={s.tls_aead} />],
                    ["Selected group", s.tls_selected_group ?? "—"],
                    ["Groups offered", tls.groups_offered?.join(", ") ?? "—"],
                    ["Hybrid PQC", s.tls_pqc_selected ? <span className="text-sev-ok">selected ({tls.pqc_group_selected})</span> : s.tls_pqc_offered ? <span className="text-sev-medium">offered by client, not selected</span> : "not offered"],
                    ["Handshake", tls.handshake_duration_ms != null ? `${tls.handshake_duration_ms.toFixed(2)} ms` : "—"],
                  ]}
                />
                {suite?.weaknesses && suite.weaknesses.length > 0 && (
                  <div className="mt-4 space-y-1.5">
                    {suite.weaknesses.map((w) => (
                      <div key={w} className="rounded-md border border-sev-high/40 bg-sev-high/5 p-2 text-xs">
                        {w}
                      </div>
                    ))}
                  </div>
                )}
              </Panel>
              <Panel title="Identity & fingerprints" description="Standard JA3/JA3S/JA4/JA4S, comparable with other SOC tooling.">
                <KeyValue
                  rows={[
                    ["SNI", s.tls_sni ? <span className="font-mono">{s.tls_sni}</span> : "—"],
                    ["ALPN", tls.alpn ?? "—"],
                    ["JA3", <Tag>{s.tls_ja3 ?? "—"}</Tag>],
                    ["JA3S", <Tag>{tls.ja3s ?? "—"}</Tag>],
                    ["JA4", <Tag>{s.tls_ja4 ?? "—"}</Tag>],
                    ["JA4S", <Tag>{s.tls_ja4s ?? "—"}</Tag>],
                  ]}
                />
              </Panel>
            </div>
          )}
        </TabsContent>

        <TabsContent value="certificate">
          {cert?.observed ? (
            <Panel title="Presented certificate chain" description={`Validity judged at capture time (${cert.evaluated_at?.slice(0, 19).replace("T", " ")} UTC), not today.`}>
              <CertChain cert={cert} />
            </Panel>
          ) : (
            <Empty title="Certificate not observable" icon={<ShieldQuestion className="size-6" />}>
              {s.cert_unobservable_reason ?? "No certificate was present in the captured bytes."}
            </Empty>
          )}
        </TabsContent>

        <TabsContent value="risk" className="space-y-4">
          {s.risk_detail ? (
            <Panel title="Risk classification (our model)" description="Exact Shapley attribution over risk-factor groups: bars sum from the healthy baseline to the model output.">
              <RiskDrivers risk={s.risk_detail} />
            </Panel>
          ) : (
            <Empty title="Not classified">Sessions with incomplete evidence are not classified.</Empty>
          )}
          <div className="grid gap-4 lg:grid-cols-2">
            <Panel title="Deviation from this server's baseline" description="Deterministic comparison with the server's own dominant behaviour.">
              {s.baseline_deviations?.length ? (
                <div className="space-y-2">
                  {s.baseline_deviations.map((d) => (
                    <div key={d.label} className="rounded-md border p-2 text-sm">
                      <div className="font-medium">{d.label}</div>
                      <div className="flex items-center gap-2 font-mono text-xs text-muted-foreground">
                        expected {d.expected} <ArrowRight className="size-3" /> <span className="text-sev-high">observed {d.observed}</span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-sm text-muted-foreground">Matches its server's established profile (or no baseline exists).</div>
              )}
            </Panel>
            <Panel title="Isolation Forest anomaly" description="Unsupervised: how unusual this session is among its peers. Deviation, not proof of attack.">
              {s.anomaly_score != null ? (
                <div className="space-y-2">
                  <div className="text-sm">
                    Score <b className="tabular">{s.anomaly_score.toFixed(3)}</b> · {s.is_anomalous ? <span className="text-chart-3">outlier</span> : "inlier"}
                  </div>
                  {(s.anomaly_attribution ?? []).map((a) => (
                    <div key={a.feature} className="flex justify-between text-xs">
                      <span className="font-mono">{a.feature}</span>
                      <span className="text-muted-foreground">
                        {a.value} vs median {a.population_median} · {a.deviation_mad}× MAD
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-sm text-muted-foreground">Too few sessions in this capture for an outlier model (needs 20).</div>
              )}
            </Panel>
          </div>
        </TabsContent>

        <TabsContent value="findings">
          <Panel title="Findings on this session">
            {related.length ? (
              <div className="space-y-1">
                {related.map((f) => (
                  <Link key={f.ref} to={`/c/${captureId}/findings/${f.ref}`} className="flex items-center gap-3 rounded-md px-2 py-2 hover:bg-muted/60">
                    <SeverityBadge severity={f.severity} />
                    <span className="flex-1 text-sm">{f.title}</span>
                    <span className="font-mono text-xs text-muted-foreground">{f.ref}</span>
                    <ArrowRight className="size-3.5 text-muted-foreground" />
                  </Link>
                ))}
              </div>
            ) : (
              <div className="text-sm text-muted-foreground">No findings reference this session.</div>
            )}
          </Panel>
        </TabsContent>
      </Tabs>
    </div>
  );
}
