import { Atom, Brain, Calculator, ListChecks } from "lucide-react";
import { useParams } from "react-router-dom";
import { Section } from "../components/Layout";
import { ScoreRing } from "../components/ScoreRing";
import { Card, ErrorState, Meter, Mono, PageHeader, Pill, RiskBadge, Spinner, Table, Td, Th } from "../components/ui";
import { useApi } from "../lib/api";
import { fmtPct } from "../lib/format";
import type { PostureResponse } from "../lib/types";

const TIER_COLOR: Record<string, string> = {
  cleartext: "rgb(var(--crit))",
  static_rsa: "rgb(var(--serious))",
  classical: "rgb(var(--warn))",
  pqc_hybrid: "rgb(var(--good))",
};

const TIER_RISK: Record<string, string> = {
  cleartext: "critical",
  static_rsa: "high",
  classical: "medium",
  pqc_hybrid: "ok",
};

export function PosturePage() {
  const { captureId } = useParams();
  const res = useApi<PostureResponse>(`/api/captures/${captureId}/posture`);
  if (res.error) return <ErrorState error={res.error} onRetry={res.reload} />;
  if (!res.data) return <Spinner />;

  const { posture, pqc_readiness: pqc, deviations, anomaly } = res.data;
  const exposed = pqc.exposure.filter((t) => t.sessions > 0);

  return (
    <>
      <PageHeader
        eyebrow="Assessment"
        title="Cryptographic posture & PQC readiness"
        description="Two questions about the same handshakes: how secure is this traffic against today's attacker, and how much of it survives one who records it now and decrypts it with a quantum computer later."
      />

      <Section title="Today — posture score">
        <div className="grid gap-4 lg:grid-cols-[300px_1fr]">
          <Card>
            <div className="flex flex-col items-center text-center">
              <ScoreRing score={posture.overall} size={150} label="of 100" />
              <p className="mt-4 text-[13px] leading-relaxed text-ink2">{posture.note}</p>
              <div className="mt-3">
                <Pill tone="accent">
                  {posture.dimensions_assessed}/{posture.dimensions_total} dimensions assessed
                </Pill>
              </div>
            </div>
          </Card>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
            {posture.dimensions.map((d) => (
              <Card key={d.key} className="flex flex-col">
                <div className="flex items-start justify-between gap-2">
                  <div className="text-[14px] font-semibold text-ink">{d.label}</div>
                  <div className="text-[22px] font-semibold leading-none text-ink">
                    {d.score ?? <span className="text-[13px] font-medium text-muted">Not assessed</span>}
                  </div>
                </div>
                <div className="mt-3">
                  <Meter value={d.score} />
                </div>
                <div className="mt-2 flex justify-between text-[12px] text-muted">
                  <span>coverage {fmtPct(d.coverage_pct)}</span>
                  <span>weight {Math.round(d.weight * 100)}%</span>
                </div>
                <ul className="mt-3 space-y-1 text-[12.5px] text-ink2">
                  {(d.contributors.length ? d.contributors : [d.detail]).map((c) => (
                    <li key={c} className="leading-snug">
                      · {c}
                    </li>
                  ))}
                </ul>
                <div className="mt-auto pt-3 text-[11px] text-muted">{d.standard}</div>
              </Card>
            ))}
          </div>
        </div>

        <Card className="mt-4" title={<span className="flex items-center gap-2"><Calculator size={16} className="text-accent" /> How the score was calculated</span>} subtitle={posture.calculation.formula} padded={false}>
          <Table>
            <thead>
              <tr>
                <Th>Dimension</Th>
                <Th className="text-right">Score</Th>
                <Th className="text-right">Weight</Th>
                <Th className="text-right">Score × weight</Th>
              </tr>
            </thead>
            <tbody>
              {posture.calculation.terms.map((t) => (
                <tr key={t.dimension}>
                  <Td>{t.dimension}</Td>
                  <Td className="tabular text-right">{t.score}</Td>
                  <Td className="tabular text-right">{t.weight}</Td>
                  <Td className="tabular text-right">{t.product}</Td>
                </tr>
              ))}
              {posture.calculation.excluded.map((t) => (
                <tr key={t.dimension} className="text-muted">
                  <Td className="text-muted">{t.dimension} <span className="text-[11px]">(excluded — no evidence)</span></Td>
                  <Td className="text-right text-muted">—</Td>
                  <Td className="tabular text-right text-muted">{t.weight}</Td>
                  <Td className="text-right text-muted">—</Td>
                </tr>
              ))}
              <tr className="font-medium">
                <Td>Total</Td>
                <Td />
                <Td className="tabular text-right">{posture.calculation.denominator}</Td>
                <Td className="tabular text-right">
                  {posture.calculation.numerator} ÷ {posture.calculation.denominator} = {posture.calculation.result ?? "—"}
                </Td>
              </tr>
            </tbody>
          </Table>
        </Card>
      </Section>

      <Section title="Tomorrow — post-quantum readiness">
        <div className="grid gap-4 lg:grid-cols-[300px_1fr]">
          <Card>
            <div className="flex flex-col items-center text-center">
              <ScoreRing score={pqc.score} size={150} label="PQC ready" sublabel={pqc.level_label ?? undefined} />
              <p className="mt-4 text-[13px] leading-relaxed text-ink2">{pqc.framing}</p>
              <div className="mt-3 flex flex-wrap justify-center gap-1">
                {pqc.standards.map((s) => (
                  <Pill key={s}>{s}</Pill>
                ))}
              </div>
            </div>
          </Card>

          <div className="grid gap-4">
            <Card title={<span className="flex items-center gap-2"><Atom size={16} className="text-accent" /> Harvest-now-decrypt-later exposure</span>} subtitle="Every observed session, by how long its confidentiality lasts.">
              {exposed.length === 0 ? (
                <p className="text-[13px] text-ink2">No assessable sessions.</p>
              ) : (
                <>
                  {/* One stacked bar: parts of a whole, 2px surface gaps between segments. */}
                  <div className="flex h-4 w-full gap-[2px] overflow-hidden rounded-md">
                    {exposed.map((t) => (
                      <div
                        key={t.tier}
                        title={`${t.label}: ${t.sessions} (${t.pct}%)`}
                        style={{ width: `${t.pct}%`, background: TIER_COLOR[t.tier] }}
                        className="first:rounded-l-md last:rounded-r-md"
                      />
                    ))}
                  </div>
                  <div className="mt-4 grid gap-3 sm:grid-cols-2">
                    {pqc.exposure.map((t) => (
                      <div key={t.tier} className="flex gap-3">
                        <span className="mt-1 h-3 w-3 shrink-0 rounded-sm" style={{ background: TIER_COLOR[t.tier] }} />
                        <div>
                          <div className="text-[13px] font-medium text-ink">
                            {t.label} <span className="tabular text-ink2">· {t.sessions} ({t.pct}%)</span>
                          </div>
                          <div className="text-[12px] leading-snug text-ink2">{t.explanation}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </Card>

            <Card title="Readiness components" subtitle={pqc.cap_note ?? pqc.formula}>
              <div className="space-y-3">
                {pqc.components.map((c) => (
                  <div key={c.key} className="grid grid-cols-[1fr_auto] items-center gap-x-4 gap-y-1">
                    <span className="text-[13px] text-ink">
                      {c.label} <span className="text-muted">· weight {Math.round(c.weight * 100)}%</span>
                    </span>
                    <span className="tabular text-[13px] font-medium">
                      {c.assessed ? `${c.score} · ${c.observed}/${c.total}` : <span className="text-muted">no evidence</span>}
                    </span>
                    <div className="col-span-2">
                      <Meter value={c.score} />
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        </div>

        <div className="mt-4 grid gap-4 xl:grid-cols-[2fr_1fr]">
          <Card title="Per-server quantum readiness" padded={false}>
            <Table>
              <thead>
                <tr>
                  <Th>Server</Th>
                  <Th>Worst exposure</Th>
                  <Th>Key group</Th>
                  <Th className="text-right">TLS 1.3</Th>
                  <Th className="text-right">PQC offered / selected</Th>
                </tr>
              </thead>
              <tbody>
                {pqc.servers.map((s) => (
                  <tr key={s.server}>
                    <Td>
                      <Mono>{s.server}</Mono>
                      {s.migration_gap && <div className="mt-1 text-[11px] text-serious">Clients ready, server declines</div>}
                    </Td>
                    <Td>
                      {s.worst_tier ? (
                        <RiskBadge
                          risk={TIER_RISK[s.worst_tier] ?? "info"}
                          label={pqc.exposure.find((t) => t.tier === s.worst_tier)?.label}
                        />
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </Td>
                    <Td className="font-mono text-[12px]">{s.dominant_group ?? "—"}</Td>
                    <Td className="tabular text-right">
                      {s.tls13}/{s.sessions}
                    </Td>
                    <Td className="tabular text-right">
                      {s.clients_offering_pqc} / {s.pqc_selected}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </Card>

          <Card title={<span className="flex items-center gap-2"><ListChecks size={16} className="text-accent" /> Migration plan</span>}>
            {pqc.actions.length === 0 ? (
              <p className="text-[13px] text-ink2">Nothing blocking readiness in the observed traffic.</p>
            ) : (
              <ol className="space-y-3">
                {pqc.actions.map((a, i) => (
                  <li key={a.title} className="flex gap-3">
                    <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-accent/10 text-[12px] font-semibold text-accent">
                      {i + 1}
                    </span>
                    <div>
                      <div className="text-[13px] font-medium text-ink">{a.title}</div>
                      <div className="text-[12.5px] leading-snug text-ink2">{a.detail}</div>
                    </div>
                  </li>
                ))}
              </ol>
            )}
          </Card>
        </div>
      </Section>

      <Section title="Behavioural intelligence">
        <Card
          title={<span className="flex items-center gap-2"><Brain size={16} className="text-accent" /> Deviations from each server's own baseline</span>}
          subtitle={anomaly.available ? `${anomaly.model} · ${anomaly.sessions_scored} sessions scored · ${anomaly.outliers} outlier(s). ${anomaly.disclaimer}` : anomaly.reason ?? anomaly.disclaimer}
          padded={false}
        >
          {deviations.length === 0 ? (
            <p className="p-5 text-[13px] text-ink2">Every session matched its server's established profile.</p>
          ) : (
            <Table>
              <thead>
                <tr>
                  <Th>Session</Th>
                  <Th>Server</Th>
                  <Th>What differed</Th>
                  <Th className="text-right">Deviation</Th>
                  <Th className="text-right">Anomaly</Th>
                </tr>
              </thead>
              <tbody>
                {deviations.map((d) => (
                  <tr key={d.session_ref}>
                    <Td className="font-mono text-[12px]">{d.session_ref}</Td>
                    <Td className="font-mono text-[12px]">{d.server}</Td>
                    <Td>
                      {d.deviations.map((x) => (
                        <div key={x.label} className="text-[12.5px]">
                          <span className="text-ink2">{x.label}:</span> expected <Mono>{x.expected}</Mono> saw <Mono>{x.observed}</Mono>
                        </div>
                      ))}
                    </Td>
                    <Td className="tabular text-right">{d.score?.toFixed(2) ?? "—"}</Td>
                    <Td className="tabular text-right">
                      {d.anomaly_score?.toFixed(2) ?? "—"}
                      {d.is_anomalous && <div className="text-[11px] text-serious">outlier</div>}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </Card>
      </Section>
    </>
  );
}
