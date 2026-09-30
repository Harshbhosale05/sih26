import clsx from "clsx";
import {
  AlertCircle,
  Brain,
  CheckCircle2,
  ChevronRight,
  Copy,
  Download,
  Eye,
  FileSearch,
  Gavel,
  Lightbulb,
  Scale,
  Search,
  Target,
} from "lucide-react";
import { useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { Card, Drawer, Empty, ErrorState, Mono, PageHeader, Pill, SeverityBadge, Spinner, Tabs } from "../components/ui";
import { useApi } from "../lib/api";
import { fmtPct, humanize, SEVERITY_ORDER } from "../lib/format";
import type { Explanation, Finding } from "../lib/types";

const STEP_ICON: Record<string, typeof Eye> = {
  observation: Eye,
  rule: Gavel,
  reasoning: Lightbulb,
  verdict: Scale,
};

function renderValue(v: unknown) {
  if (v === null || v === undefined) return "—";
  if (typeof v === "boolean") return v ? "yes" : "no";
  if (typeof v === "string" || typeof v === "number") return String(v);
  if (Array.isArray(v) && v.every((x) => typeof x !== "object")) return v.join(", ");
  return (
    <pre className="max-h-40 overflow-auto whitespace-pre-wrap rounded bg-raised p-2 font-mono text-[11px] text-ink">
      {JSON.stringify(v, null, 2)}
    </pre>
  );
}

function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      onClick={() => {
        navigator.clipboard?.writeText(text).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        });
      }}
      className="inline-flex items-center gap-1 text-[12px] font-medium text-accent hover:underline"
    >
      {done ? <CheckCircle2 size={13} /> : <Copy size={13} />}
      {done ? "Copied" : "Copy"}
    </button>
  );
}

function ExplainPanel({ captureId, finding }: { captureId: string; finding: Finding }) {
  const res = useApi<Explanation>(`/api/captures/${captureId}/findings/${finding.ref}/explain`);
  if (res.error) return <ErrorState error={res.error} onRetry={res.reload} />;
  if (!res.data) return <Spinner label="Assembling evidence chain…" />;
  const x = res.data;

  return (
    <div className="space-y-6">
      <p className="text-[14px] leading-relaxed text-ink">{x.finding.description}</p>

      {/* The chain */}
      <div>
        <h3 className="mb-3 text-[12px] font-semibold uppercase tracking-wider text-muted">Reasoning chain</h3>
        <ol className="relative space-y-4 border-l border-line pl-6">
          {x.chain.map((step) => {
            const Icon = STEP_ICON[step.kind] ?? Lightbulb;
            return (
              <li key={step.title} className="relative">
                <span className="absolute -left-[37px] flex h-6 w-6 items-center justify-center rounded-full border border-line bg-surface text-accent">
                  <Icon size={13} />
                </span>
                <div className="text-[13px] font-semibold text-ink">{step.title}</div>
                <div className="mt-0.5 text-[13px] leading-relaxed text-ink2">{step.text}</div>
              </li>
            );
          })}
        </ol>
      </div>

      {x.observations.length > 0 && (
        <div>
          <h3 className="mb-2 text-[12px] font-semibold uppercase tracking-wider text-muted">Wire evidence</h3>
          <div className="overflow-hidden rounded-lg border border-line">
            {x.observations.map((o, i) => (
              <div key={i} className="flex gap-3 border-b border-line/70 bg-surface px-3 py-2 font-mono text-[12px] last:border-0">
                <span className="w-14 shrink-0 text-muted">#{o.frame}</span>
                {o.direction && <span className="w-10 shrink-0 text-accent">{o.direction === "c2s" ? "C→S" : o.direction === "s2c" ? "S→C" : o.direction}</span>}
                <span className="min-w-0 break-words text-ink">{o.detail || o.kind}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {x.facts.length > 0 && (
        <div>
          <h3 className="mb-2 text-[12px] font-semibold uppercase tracking-wider text-muted">Recorded facts</h3>
          <dl className="grid gap-x-4 gap-y-2 text-[13px] sm:grid-cols-[180px_1fr]">
            {x.facts.map((f) => (
              <div key={f.key} className="contents">
                <dt className="text-ink2">{f.label}</dt>
                <dd className="min-w-0 break-words text-ink">{renderValue(f.value)}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}

      <div className="grid gap-4 sm:grid-cols-2">
        <div className="rounded-lg border border-line bg-surface p-4">
          <div className="mb-2 flex items-center gap-2 text-[13px] font-semibold text-ink">
            <Scale size={14} className="text-accent" /> Confidence {fmtPct(x.finding.confidence * 100)}
          </div>
          <ul className="space-y-1 text-[12.5px] text-ink2">
            {x.confidence_factors.map((c) => (
              <li key={c.factor}>
                {c.factor}: <span className="text-ink">{String(c.value ?? "—")}</span>
                {c.note && <div className="text-muted">{c.note}</div>}
              </li>
            ))}
          </ul>
        </div>
        <div className="rounded-lg border border-line bg-surface p-4">
          <div className="mb-2 flex items-center gap-2 text-[13px] font-semibold text-ink">
            <AlertCircle size={14} className="text-warn" /> Limits of the evidence
          </div>
          {x.limits.length ? (
            <ul className="space-y-1 text-[12.5px] text-ink2">
              {x.limits.map((l) => (
                <li key={l}>· {l}</li>
              ))}
            </ul>
          ) : (
            <p className="text-[12.5px] text-ink2">Session fully observed — no known gaps.</p>
          )}
        </div>
      </div>

      {x.ml_context && (
        <div className="rounded-lg border border-accent/30 bg-accent/5 p-4">
          <div className="mb-1 flex items-center gap-2 text-[13px] font-semibold text-ink">
            <Brain size={14} className="text-accent" /> What the AI layer adds
          </div>
          <p className="text-[12.5px] text-ink2">{x.ml_context.role}</p>
          <div className="mt-2 flex flex-wrap gap-2 text-[12px]">
            {x.ml_context.anomaly_score !== null && (
              <Pill>anomaly score {x.ml_context.anomaly_score.toFixed(2)}{x.ml_context.is_anomalous ? " · outlier" : ""}</Pill>
            )}
            {x.ml_context.baseline_deviation_score !== null && <Pill>baseline deviation {x.ml_context.baseline_deviation_score.toFixed(2)}</Pill>}
          </div>
          {x.ml_context.baseline_deviations.map((d) => (
            <div key={d.label} className="mt-1 text-[12.5px] text-ink2">
              {d.label}: expected <Mono>{d.expected}</Mono> observed <Mono>{d.observed}</Mono>
            </div>
          ))}
          {x.ml_context.attribution.length > 0 && (
            <div className="mt-2 text-[12px] text-ink2">
              Top contributing features: {x.ml_context.attribution.slice(0, 4).map((a) => a.feature).join(", ")}
            </div>
          )}
        </div>
      )}

      {(x.posture_impact.length > 0 || x.blast_radius) && (
        <div className="rounded-lg border border-line bg-surface p-4">
          <div className="mb-2 flex items-center gap-2 text-[13px] font-semibold text-ink">
            <Target size={14} className="text-accent" /> Impact
          </div>
          <ul className="space-y-1 text-[12.5px] text-ink2">
            {x.posture_impact.map((p) => (
              <li key={p.dimension}>· {p.text}</li>
            ))}
            {x.blast_radius && (
              <li>
                · Blast radius: {x.blast_radius.direct_sessions} session(s) directly, {x.blast_radius.dependent_clients} client(s) depend on{" "}
                {x.blast_radius.servers.length} affected server(s) — {fmtPct(x.blast_radius.clients_pct)} of observed clients.
              </li>
            )}
          </ul>
        </div>
      )}

      {x.finding.recommendation && (
        <div className="rounded-lg border border-good/30 bg-good/5 p-4">
          <div className="mb-1 text-[13px] font-semibold text-ink">Recommended fix</div>
          <p className="text-[13px] leading-relaxed text-ink2">{x.finding.recommendation}</p>
          {x.finding.standard_refs.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1">
              {x.finding.standard_refs.map((s) => (
                <Pill key={s}>{s}</Pill>
              ))}
            </div>
          )}
        </div>
      )}

      <div className="rounded-lg border border-line bg-surface p-4">
        <div className="mb-2 text-[13px] font-semibold text-ink">Verify it yourself</div>
        <p className="mb-3 text-[12.5px] text-ink2">{x.verification.how}</p>
        {x.verification.wireshark_filter && (
          <div className="mb-3">
            <div className="mb-1 flex items-center justify-between text-[12px] text-muted">
              Wireshark display filter <CopyButton text={x.verification.wireshark_filter} />
            </div>
            <pre className="overflow-x-auto rounded-md bg-raised p-2.5 font-mono text-[12px] text-ink ring-1 ring-inset ring-line">
              {x.verification.wireshark_filter}
            </pre>
          </div>
        )}
        <div className="flex flex-wrap items-center gap-3">
          {x.verification.wireshark_filter && (
            <a
              href={x.verification.pcap_url}
              className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-2 text-[13px] font-medium text-white hover:brightness-110"
            >
              <Download size={14} /> Download evidence slice
            </a>
          )}
          <span className="font-mono text-[11px] text-muted">
            parent {x.verification.capture_ref} · {x.verification.capture_sha256.slice(0, 20)}…
          </span>
        </div>
      </div>
    </div>
  );
}

export function FindingsPage() {
  const { captureId } = useParams();
  const res = useApi<Finding[]>(`/api/captures/${captureId}/findings`);
  const [severity, setSeverity] = useState<string>("ALL");
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState<Finding | null>(null);

  const filtered = useMemo(() => {
    const q = query.toLowerCase();
    return (res.data ?? []).filter(
      (f) =>
        (severity === "ALL" || f.severity === severity) &&
        (!q || [f.title, f.description, f.category, f.session_ref ?? "", f.ref].some((s) => s.toLowerCase().includes(q))),
    );
  }, [res.data, severity, query]);

  if (res.error) return <ErrorState error={res.error} onRetry={res.reload} />;
  if (!res.data) return <Spinner />;

  const counts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, res.data!.filter((f) => f.severity === s).length]));

  return (
    <>
      <PageHeader
        eyebrow="Evidence"
        title="Findings"
        description="Every finding opens into its evidence chain: the exact frames observed, the policy rule applied, what the ML layer adds as context, the limits of the evidence, and a filter to verify it in Wireshark."
      />

      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <Tabs
          value={severity}
          onChange={setSeverity}
          items={[
            { value: "ALL", label: `All ${res.data.length}` },
            ...SEVERITY_ORDER.filter((s) => counts[s]).map((s) => ({ value: s, label: `${humanize(s)} ${counts[s]}` })),
          ]}
        />
        <label className="relative w-full sm:w-72">
          <Search size={15} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search findings…"
            className="w-full rounded-lg border border-line bg-surface py-2 pl-9 pr-3 text-[13px] text-ink placeholder:text-muted focus:outline-none focus:ring-2 focus:ring-accent/40"
          />
        </label>
      </div>

      {filtered.length === 0 ? (
        <Empty icon={<FileSearch size={28} />} title="No findings match" />
      ) : (
        <div className="space-y-2">
          {filtered.map((f) => (
            <button
              key={f.ref}
              onClick={() => setOpen(f)}
              className="group flex w-full items-start gap-4 rounded-xl border border-line bg-surface p-4 text-left shadow-card transition hover:border-accent/40"
            >
              <div className="pt-0.5">
                <SeverityBadge severity={f.severity} />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[14px] font-semibold text-ink">{f.title}</span>
                  {f.verdict === "UNKNOWN" && <Pill>UNKNOWN</Pill>}
                </div>
                <p className="mt-1 line-clamp-2 text-[13px] text-ink2">{f.description}</p>
                <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[12px] text-muted">
                  <span className="font-mono">{f.ref}</span>
                  {f.session_ref && <span className="font-mono">{f.session_ref}</span>}
                  <span>{f.affected_sessions} session(s)</span>
                  <span>confidence {fmtPct(f.confidence * 100)}</span>
                  <span className={clsx(f.detection_method !== "deterministic" && "text-accent")}>{f.detection_method}</span>
                </div>
              </div>
              <ChevronRight size={18} className="mt-1 shrink-0 text-muted transition group-hover:translate-x-0.5 group-hover:text-accent" />
            </button>
          ))}
        </div>
      )}

      <Drawer
        open={open !== null}
        onClose={() => setOpen(null)}
        title={
          open && (
            <div>
              <div className="flex items-center gap-2">
                <SeverityBadge severity={open.severity} />
                <span className="font-mono text-[12px] text-muted">{open.ref}</span>
              </div>
              <div className="mt-1.5 text-[16px] font-semibold leading-snug text-ink">{open.title}</div>
            </div>
          )
        }
      >
        {open && captureId && <ExplainPanel captureId={captureId} finding={open} />}
      </Drawer>

      <Card className="mt-6" title="How to read a finding">
        <p className="text-[13px] leading-relaxed text-ink2">
          Verdicts are PASS, FAIL or <strong className="text-ink">UNKNOWN</strong> — a capture that cannot support a conclusion never produces an optimistic PASS.
          Detection is deterministic; the anomaly model contributes context on the evidence chain but never creates or changes a verdict.
        </p>
      </Card>
    </>
  );
}
