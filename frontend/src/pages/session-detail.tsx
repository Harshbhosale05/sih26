import { ArrowRight, Download } from "lucide-react";
import { Link, useParams } from "react-router-dom";

import {
  CodeLine,
  Empty,
  ErrorState,
  Loading,
  Panel,
  Properties,
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

function YesNo({ v }: { v: boolean | null | undefined }) {
  if (v == null) return <span className="text-muted-foreground">—</span>;
  return <span className={v ? "" : "text-sev-critical"}>{v ? "Yes" : "No"}</span>;
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
  const related = (findings.data ?? []).filter(
    (f) => f.session_ref === s.ref || (f.evidence as { affected_session?: string } | null)?.affected_session === s.ref,
  );
  const offered13 = tls.versions_offered?.includes("TLS 1.3");

  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 space-y-2">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Link to={`/c/${captureId}/sessions`} className="hover:text-foreground">
              Sessions
            </Link>
            <span>/</span>
            <span className="font-mono">{s.ref}</span>
          </div>
          <h1 className="font-mono text-lg font-semibold tracking-tight">
            {s.client_ip}:{s.client_port} → {s.server_ip}:{s.server_port}
          </h1>
          <div className="flex flex-wrap items-center gap-2">
            <StateBadge state={s.encryption_state} />
            <RiskBadge risk={s.risk_class} score={s.risk_score} />
            <span className="text-xs text-muted-foreground">
              {s.protocol} · stream {s.stream_index} · frames {s.first_frame}–{s.last_frame}
            </span>
          </div>
        </div>
        <Button asChild size="sm" variant="outline" className="h-8">
          <a href={sessionPcapUrl(captureId!, s.ref)}>
            <Download className="size-3.5" /> Session capture
          </a>
        </Button>
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_320px]">
        <div className="min-w-0 space-y-4">
          <Panel title="Encryption state">
            <StatePath transitions={s.state_transitions ?? []} finalState={s.encryption_state} />
          </Panel>
          <Tabs defaultValue="conversation">
            <TabsList>
              <TabsTrigger value="conversation">Conversation</TabsTrigger>
              <TabsTrigger value="handshake">TLS handshake</TabsTrigger>
              <TabsTrigger value="certificate">Certificate</TabsTrigger>
              <TabsTrigger value="risk">Risk</TabsTrigger>
              <TabsTrigger value="findings">Findings ({related.length})</TabsTrigger>
            </TabsList>

            <TabsContent value="conversation" className="mt-4">
              <Panel title="Protocol conversation" info="Reassembled from TCP segments with the source frame of every line. Encrypted records are counted, not read.">
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
              </Panel>
            </TabsContent>

            <TabsContent value="handshake" className="mt-4 space-y-4">
              {!s.tls_version ? (
                <Panel>
                  <Empty title="No TLS handshake">This session never started TLS.</Empty>
                </Panel>
              ) : (
                <>
                  {offered13 && s.tls_version !== "TLS 1.3" && (
                    <div className="rounded-lg border border-sev-medium/40 px-3 py-2.5 text-sm">
                      The client offered <b>TLS 1.3</b>, but the server selected <b>{s.tls_version}</b>. Hybrid post-quantum key exchange requires TLS 1.3.
                    </div>
                  )}
                  <div className="grid gap-4 lg:grid-cols-2">
                    <Panel title="Negotiated">
                      <Properties
                        rows={[
                          ["Version", s.tls_version],
                          ["Offered versions", tls.versions_offered?.join(", ") ?? "—"],
                          ["Cipher suite", <span className="font-mono text-xs">{suite?.name ?? s.tls_cipher_suite}</span>],
                          ["Key exchange", suite?.key_exchange ?? (s.tls_version === "TLS 1.3" ? "(EC)DHE" : "—")],
                          ["Group", s.tls_selected_group ?? "Not visible in TLS ≤ 1.2 ServerHello"],
                          ["Authentication", suite?.authentication ?? "Certificate"],
                          ["Encryption", suite ? `${suite.encryption ?? "—"} ${suite.key_size ?? ""} ${suite.mode ?? ""}` : "—"],
                          ["Forward secrecy", <YesNo v={s.tls_forward_secrecy} />],
                          ["AEAD", <YesNo v={s.tls_aead} />],
                          ["Handshake time", tls.handshake_duration_ms != null ? `${tls.handshake_duration_ms.toFixed(2)} ms` : "—"],
                        ]}
                      />
                    </Panel>
                    <Panel title="Offered by the client">
                      <Properties
                        rows={[
                          ["Key exchange groups", (
                            <div className="flex flex-wrap gap-1">
                              {(tls.groups_offered ?? []).map((g) => (
                                <Tag key={g} className={/mlkem|kyber/i.test(g) ? "border-sev-ok/50 text-sev-ok" : ""}>
                                  {g}
                                </Tag>
                              ))}
                            </div>
                          )],
                          ["Hybrid PQC", s.tls_pqc_selected ? "Selected" : s.tls_pqc_offered ? "Offered, not selected" : "Not offered"],
                          ["SNI", s.tls_sni ?? "—"],
                          ["ALPN", tls.alpn ?? "—"],
                          ["JA3", <Tag>{s.tls_ja3 ?? "—"}</Tag>],
                          ["JA4", <Tag>{s.tls_ja4 ?? "—"}</Tag>],
                          ["JA4S", <Tag>{s.tls_ja4s ?? "—"}</Tag>],
                        ]}
                      />
                    </Panel>
                  </div>
                  {suite?.weaknesses && suite.weaknesses.length > 0 && (
                    <Panel title="Cipher suite weaknesses">
                      <ul className="list-disc space-y-1 pl-4 text-sm">
                        {suite.weaknesses.map((w) => (
                          <li key={w}>{w}</li>
                        ))}
                      </ul>
                    </Panel>
                  )}
                </>
              )}
            </TabsContent>

            <TabsContent value="certificate" className="mt-4">
              {cert?.observed ? (
                <Panel title="Presented chain" description={`Evaluated at capture time, ${cert.evaluated_at?.slice(0, 10)}`}>
                  <CertChain cert={cert} />
                </Panel>
              ) : (
                <Panel>
                  <Empty title="Certificate not observable">{s.cert_unobservable_reason ?? "No certificate was present in the captured data."}</Empty>
                </Panel>
              )}
            </TabsContent>

            <TabsContent value="risk" className="mt-4 space-y-4">
              {s.risk_detail ? (
                <Panel title="Risk classification" info="Shapley attribution over risk-factor groups, from the session's healthy baseline to the model output.">
                  <RiskDrivers risk={s.risk_detail} />
                </Panel>
              ) : (
                <Panel>
                  <Empty title="Not classified">Sessions with incomplete evidence are not classified.</Empty>
                </Panel>
              )}
              <div className="grid gap-4 lg:grid-cols-2">
                <Panel title="Deviation from server baseline">
                  {s.baseline_deviations?.length ? (
                    <div className="space-y-2 text-sm">
                      {s.baseline_deviations.map((d) => (
                        <div key={d.label}>
                          <div>{d.label}</div>
                          <div className="font-mono text-xs text-muted-foreground">
                            expected {d.expected} → observed {d.observed}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-sm text-muted-foreground">Consistent with the server's established behaviour, or no baseline available.</div>
                  )}
                </Panel>
                <Panel title="Anomaly detection" info="Isolation Forest over session features. Indicates deviation, not an attack.">
                  {s.anomaly_score != null ? (
                    <div className="space-y-2 text-sm">
                      <div>
                        Score <span className="tabular font-medium">{s.anomaly_score.toFixed(3)}</span> · {s.is_anomalous ? "Outlier" : "Inlier"}
                      </div>
                      {(s.anomaly_attribution ?? []).map((a) => (
                        <div key={a.feature} className="flex justify-between text-xs">
                          <span className="font-mono">{a.feature}</span>
                          <span className="text-muted-foreground">
                            {a.value} vs {a.population_median} ({a.deviation_mad}× MAD)
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-sm text-muted-foreground">Requires at least 20 sessions in the capture.</div>
                  )}
                </Panel>
              </div>
            </TabsContent>

            <TabsContent value="findings" className="mt-4">
              <Panel flush>
                {related.length ? (
                  <ul className="divide-y">
                    {related.map((f) => (
                      <li key={f.ref}>
                        <Link to={`/c/${captureId}/findings/${f.ref}`} className="flex items-center gap-3 px-4 py-3 hover:bg-muted/50">
                          <SeverityBadge severity={f.severity} />
                          <span className="flex-1 text-sm">{f.title}</span>
                          <span className="font-mono text-xs text-muted-foreground">{f.ref}</span>
                          <ArrowRight className="size-3.5 text-muted-foreground" />
                        </Link>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <Empty title="No findings reference this session" />
                )}
              </Panel>
            </TabsContent>
          </Tabs>
        </div>

        <aside className="space-y-4">
          <Panel title="Connection">
            <Properties
              rows={[
                ["Protocol", s.protocol],
                ["Detected by", s.detection_method.replace(/_/g, " ")],
                ["Server banner", s.server_banner ? <span className="font-mono text-xs">{s.server_banner}</span> : "—"],
                ["STARTTLS", s.upgrade_advertised ? (s.upgrade_requested ? "Offered and used" : "Offered, not used") : "Not offered"],
                ["Credentials", s.cleartext_auth_observed ? <span className="text-sev-critical">Sent in cleartext</span> : "Not exposed"],
                ["Complete", <YesNo v={s.session_complete} />],
              ]}
            />
          </Panel>
          <Panel title="Wireshark filter">
            <CodeLine>{s.wireshark_filter}</CodeLine>
          </Panel>
        </aside>
      </div>
    </>
  );
}
