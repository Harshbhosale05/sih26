import { Activity, AlertOctagon, ArrowRight, Download, FileText, GitBranch, Lock, LockOpen, ShieldQuestion } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { ScoreRing } from "../components/ScoreRing";
import { Card, ErrorState, LinkButton, Meter, PageHeader, RiskBadge, SeverityBadge, Spinner, Stat } from "../components/ui";
import { useApi } from "../lib/api";
import { fmtBytes, fmtDate, fmtNum, fmtPct, SEVERITY_ORDER } from "../lib/format";
import type { GraphData, Overview, PostureResponse, StarttlsAnalytics } from "../lib/types";

export function OverviewPage() {
  const { captureId } = useParams();
  const base = `/api/captures/${captureId}`;
  const overview = useApi<Overview>(`${base}/overview`);
  const posture = useApi<PostureResponse>(`${base}/posture`);
  const starttls = useApi<StarttlsAnalytics>(`${base}/starttls`);
  const graph = useApi<GraphData>(`${base}/graph`);

  if (overview.error) return <ErrorState error={overview.error} onRetry={overview.reload} />;
  if (!overview.data) return <Spinner />;

  const o = overview.data;
  const p = posture.data?.posture;
  const pqc = posture.data?.pqc_readiness;
  const maxSeverity = Math.max(1, ...SEVERITY_ORDER.map((s) => o.findings.by_severity[s] ?? 0));

  return (
    <>
      <PageHeader
        eyebrow={o.capture.ref}
        title={o.capture.filename}
        description={
          <>
            {fmtNum(o.capture.packet_count)} packets · {fmtBytes(o.capture.size_bytes)} · captured {fmtDate(o.capture.first_packet_at)}
            <span className="mt-1 block font-mono text-[11px] text-muted">SHA-256 {o.capture.sha256}</span>
          </>
        }
        actions={
          <>
            <LinkButton href={`${base}/report.html`}>
              <FileText size={14} /> Report
            </LinkButton>
            <LinkButton href={`${base}/cbom`} download>
              <Download size={14} /> CBOM
            </LinkButton>
          </>
        }
      />

      {(o.findings.by_severity.CRITICAL ?? 0) > 0 && (
        <Link
          to="findings"
          className="mb-4 flex items-center gap-3 rounded-xl border border-crit/40 bg-crit/10 px-4 py-3 text-[13.5px] text-ink hover:border-crit/70"
        >
          <AlertOctagon size={18} className="shrink-0 text-crit" />
          <span className="flex-1">
            <b>Action required:</b> {o.findings.by_severity.CRITICAL} critical finding
            {o.findings.by_severity.CRITICAL > 1 ? "s" : ""} in this capture. A single critical exposure outranks the average score.
          </span>
          <span className="flex items-center gap-1 font-medium text-accent">
            Review <ArrowRight size={14} />
          </span>
        </Link>
      )}

      {/* Headline: today's posture and tomorrow's readiness, side by side. */}
      <div className="mb-6 grid gap-4 lg:grid-cols-2">
        <Card>
          <div className="flex flex-col items-center gap-6 sm:flex-row sm:items-center">
            <ScoreRing score={p?.overall ?? null} label="Posture" />
            <div className="w-full min-w-0 flex-1 space-y-2.5">
              <div className="text-[13px] text-ink2">How secure is this communication today?</div>
              {p?.dimensions.map((d) => (
                <div key={d.key} className="grid grid-cols-[1fr_auto] items-center gap-x-3 gap-y-1">
                  <span className="truncate text-[13px] text-ink">{d.label}</span>
                  <span className="tabular text-[13px] font-medium text-ink">{d.score ?? <span className="text-muted">n/a</span>}</span>
                  <div className="col-span-2">
                    <Meter value={d.score} />
                  </div>
                </div>
              ))}
              {!p && <Spinner />}
            </div>
          </div>
        </Card>
        <Card>
          <div className="flex flex-col items-center gap-6 sm:flex-row sm:items-center">
            <ScoreRing score={pqc?.score ?? null} label="PQC ready" sublabel={pqc?.level_label ?? undefined} />
            <div className="w-full min-w-0 flex-1">
              <div className="text-[13px] text-ink2">How prepared is it for quantum-era threats?</div>
              {pqc && (
                <>
                  <div className="mt-3 text-[28px] font-semibold leading-none text-ink">{fmtPct(pqc.hndl_exposed_pct)}</div>
                  <div className="mt-1 text-[13px] text-ink2">
                    of sessions exposed to harvest-now-decrypt-later ({pqc.hndl_exposed_sessions} session(s))
                  </div>
                  {pqc.actions[0] && (
                    <div className="mt-4 rounded-lg border border-line bg-raised p-3 text-[13px]">
                      <div className="font-medium text-ink">Next step: {pqc.actions[0].title}</div>
                      <div className="mt-0.5 text-ink2">{pqc.actions[0].detail}</div>
                    </div>
                  )}
                  <Link to="posture" className="mt-3 inline-flex items-center gap-1 text-[13px] font-medium text-accent hover:underline">
                    Full posture & PQC breakdown <ArrowRight size={14} />
                  </Link>
                </>
              )}
            </div>
          </div>
        </Card>
      </div>

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Email sessions" value={fmtNum(o.sessions.total)} hint={Object.entries(o.sessions.by_protocol).map(([k, v]) => `${k} ${v}`).join(" · ")} />
        <Stat label="Encrypted" value={fmtNum(o.sessions.protected)} status="good" icon={<Lock size={16} />} hint={o.sessions.total ? fmtPct((100 * o.sessions.protected) / o.sessions.total) + " of sessions" : undefined} />
        <Stat label="Cleartext" value={fmtNum(o.sessions.cleartext)} status={o.sessions.cleartext ? "crit" : "good"} icon={<LockOpen size={16} />} hint="Data provably crossed unencrypted" />
        <Stat label="Indeterminate" value={fmtNum(o.sessions.indeterminate)} icon={<ShieldQuestion size={16} />} hint="Reported UNKNOWN, never guessed" />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="Findings by severity" subtitle={`${o.findings.total} total · ${o.findings.unknown_verdicts} unknown`} action={<Link to="findings" className="text-[13px] font-medium text-accent hover:underline">View all</Link>}>
          <div className="space-y-3">
            {SEVERITY_ORDER.map((s) => {
              const n = o.findings.by_severity[s] ?? 0;
              return (
                <div key={s} className="grid grid-cols-[92px_1fr_32px] items-center gap-3">
                  <SeverityBadge severity={s} />
                  <div className="h-2 overflow-hidden rounded-full bg-line/60">
                    <div className="h-full rounded-full bg-ink2/70" style={{ width: `${(100 * n) / maxSeverity}%` }} />
                  </div>
                  <span className="tabular text-right text-[13px] font-medium">{n}</span>
                </div>
              );
            })}
          </div>
        </Card>

        <Card title={<span className="flex items-center gap-2"><GitBranch size={16} className="text-accent" /> Largest blast radius</span>} action={<Link to="graph" className="text-[13px] font-medium text-accent hover:underline">Graph</Link>}>
          {!graph.data ? (
            <Spinner />
          ) : graph.data.blast_radius.length === 0 ? (
            <p className="text-[13px] text-ink2">No weakness with a measurable blast radius.</p>
          ) : (
            <ul className="space-y-3">
              {graph.data.blast_radius.slice(0, 4).map((r) => (
                <li key={r.key} className="rounded-lg border border-line p-3">
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-[13px] font-medium leading-snug text-ink">{r.title}</span>
                    <SeverityBadge severity={r.severity} compact />
                  </div>
                  <div className="mt-1.5 text-[12px] text-ink2">
                    {r.direct_sessions} direct · {r.dependent_clients} dependent client(s) · {fmtPct(r.clients_pct)} of observed clients
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title={<span className="flex items-center gap-2"><Activity size={16} className="text-accent" /> STARTTLS adoption</span>} action={<Link to="starttls" className="text-[13px] font-medium text-accent hover:underline">Analytics</Link>}>
          {!starttls.data ? (
            <Spinner />
          ) : (
            <>
              <div className="text-[28px] font-semibold leading-none text-ink">{fmtPct(starttls.data.summary.adoption_pct)}</div>
              <div className="mt-1 text-[13px] text-ink2">
                of {starttls.data.summary.observable} observable plaintext-start sessions upgraded
              </div>
              <div className="mt-4 space-y-2">
                {starttls.data.failure_points
                  .filter((f) => f.key !== "success")
                  .slice(0, 3)
                  .map((f) => (
                    <div key={f.key} className="flex items-center justify-between gap-2 text-[13px]">
                      <span className="flex items-center gap-2 text-ink">
                        <RiskBadge risk={f.severity} label={String(f.count)} />
                        {f.label}
                      </span>
                    </div>
                  ))}
              </div>
            </>
          )}
        </Card>
      </div>

      <Card className="mt-4" title="Evidence coverage" subtitle={o.coverage.note}>
        <div className="grid gap-6 sm:grid-cols-2">
          <div>
            <div className="mb-1 flex justify-between text-[13px]">
              <span className="text-ink2">Sessions fully observed</span>
              <span className="tabular font-medium">{fmtPct(o.coverage.session_coverage_pct)}</span>
            </div>
            <Meter value={o.coverage.session_coverage_pct} status="none" />
          </div>
          <div>
            <div className="mb-1 flex justify-between text-[13px]">
              <span className="text-ink2">Certificates observable</span>
              <span className="tabular font-medium">
                {o.coverage.certificate_observable}/{o.coverage.tls_sessions} · {fmtPct(o.coverage.certificate_coverage_pct)}
              </span>
            </div>
            <Meter value={o.coverage.certificate_coverage_pct} status="none" />
          </div>
        </div>
      </Card>
    </>
  );
}
