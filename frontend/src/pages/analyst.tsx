import { ArrowRight, ArrowUp, Check, ExternalLink, Loader2, X } from "lucide-react";
import { Fragment, useEffect, useRef, useState } from "react";
import { CartesianGrid, Scatter, ScatterChart, Tooltip as RTooltip, XAxis, YAxis, ZAxis } from "recharts";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";

import { Dot, Empty, ErrorState, InfoTip, Loading, Meter, Panel, Tag } from "@/components/common";
import { Button } from "@/components/ui/button";
import { ChartContainer, type ChartConfig } from "@/components/ui/chart";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { askAnalyst, useAssistantCard, useAttackPaths, useBrief, useFingerprints } from "@/lib/api";
import type { AskAnswer, AttackScenario } from "@/lib/types";
import { cn } from "@/lib/utils";

const REF = /(F-\d{4}|(?:SMTP|IMAP|POP3)-\d{4})/;
const IS_REF = /^(F-\d{4}|(?:SMTP|IMAP|POP3)-\d{4})$/;

/** Text with finding and session refs turned into links. */
function RefText({ text, captureId }: { text: string; captureId: string }) {
  const parts = text.split(REF);
  return (
    <>
      {parts.map((p, i) =>
        IS_REF.test(p) ? (
          <Link
            key={i}
            to={`/c/${captureId}/${p.startsWith("F-") ? "findings" : "sessions"}/${p}`}
            className="rounded bg-muted px-1 font-mono text-[0.92em] underline-offset-2 hover:underline"
          >
            {p}
          </Link>
        ) : (
          <Fragment key={i}>{p}</Fragment>
        ),
      )}
    </>
  );
}

const KIND_COLOR: Record<string, string> = {
  fact: "hsl(var(--muted-foreground))",
  assessment: "hsl(var(--foreground))",
  risk: "hsl(var(--sev-critical))",
  pqc: "hsl(var(--chart-3))",
  anomaly: "hsl(var(--sev-medium))",
  action: "hsl(var(--sev-ok))",
};

function BriefPanel({ captureId }: { captureId: string }) {
  const { data, error } = useBrief(captureId);
  return (
    <Panel
      title="Analyst brief"
      info="Written from computed results only. Each sentence states a fact the platform derived, and every reference links to the evidence behind it."
    >
      {error ? (
        <ErrorState error={error} />
      ) : !data ? (
        <Loading rows={1} />
      ) : (
        <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_320px]">
          <div className="space-y-2.5">
            {data.sentences.map((s, i) => (
              <p key={i} className="flex gap-2.5 text-sm leading-relaxed">
                <Dot color={KIND_COLOR[s.kind] ?? KIND_COLOR.fact} className="mt-[7px] size-1.5" />
                <span>
                  <RefText text={s.text} captureId={captureId} />
                </span>
              </p>
            ))}
          </div>
          <div className="space-y-2 lg:border-l lg:pl-6">
            <div className="text-xs font-medium text-muted-foreground">Recommended next steps</div>
            {data.actions.length ? (
              <ol className="space-y-2">
                {data.actions.map((a, i) => (
                  <li key={a.fix_id} className="grid grid-cols-[18px_1fr] gap-2 text-sm">
                    <span className="font-mono text-xs text-muted-foreground">{i + 1}.</span>
                    <div>
                      <div>{a.title}</div>
                      <div className="text-xs text-muted-foreground">
                        Projected posture {a.score_after ?? "—"} · closes {a.addresses.join(", ")}
                      </div>
                    </div>
                  </li>
                ))}
              </ol>
            ) : (
              <div className="text-sm text-muted-foreground">No changes required.</div>
            )}
            {data.actions.length > 0 && (
              <Button asChild size="sm" variant="outline" className="mt-2 h-7 text-xs">
                <Link to={`/c/${captureId}/remediation`}>
                  Open remediation <ArrowRight className="size-3" />
                </Link>
              </Button>
            )}
          </div>
        </div>
      )}
    </Panel>
  );
}

type Message = { role: "user"; text: string } | { role: "assistant"; answer: AskAnswer } | { role: "error"; text: string };

function AnswerView({ a, captureId, onAsk }: { a: AskAnswer; captureId: string; onAsk: (q: string) => void }) {
  const navigate = useNavigate();
  return (
    <div className="space-y-3">
      <div className="space-y-1.5 text-sm leading-relaxed">
        {a.text.map((t, i) => (
          <p key={i}>
            <RefText text={t} captureId={captureId} />
          </p>
        ))}
      </div>
      {a.table && a.table.rows.length > 0 && (
        <div className="max-h-64 overflow-auto rounded-md border">
          <Table>
            <TableHeader className="bg-muted/40">
              <TableRow className="hover:bg-transparent">
                {a.table.columns.map((c) => (
                  <TableHead key={c} className="h-8 text-xs">
                    {c}
                  </TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {a.table.rows.map((r, i) => (
                <TableRow key={i} className="hover:bg-transparent">
                  {r.map((c, j) => (
                    <TableCell key={j} className="py-1.5 text-xs">
                      <RefText text={c} captureId={captureId} />
                    </TableCell>
                  ))}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      {(a.actions.length > 0 || a.followups.length > 0) && (
        <div className="flex flex-wrap gap-1.5">
          {a.actions.map((act) => (
            <Button key={act.label} size="sm" variant="outline" className="h-7 text-xs" onClick={() => navigate(`/c/${captureId}${act.to ? `/${act.to}` : ""}`)}>
              {act.label} <ArrowRight className="size-3" />
            </Button>
          ))}
          {a.followups.map((f) => (
            <button key={f} type="button" onClick={() => onAsk(f)} className="h-7 rounded-md border border-dashed px-2.5 text-xs text-muted-foreground hover:border-solid hover:text-foreground">
              {f}
            </button>
          ))}
        </div>
      )}
      <div className="text-[11px] text-muted-foreground">
        Intent <span className="font-mono">{a.intent}</span> · {Math.round(a.confidence * 100)}% confidence
      </div>
    </div>
  );
}

function AskPanel({ captureId, initial }: { captureId: string; initial?: string | null }) {
  const card = useAssistantCard();
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const scroller = useRef<HTMLDivElement>(null);
  const asked = useRef<string | null>(null);

  const ask = async (q: string) => {
    const question = q.trim();
    if (!question || busy) return;
    setInput("");
    setMessages((m) => [...m, { role: "user", text: question }]);
    setBusy(true);
    try {
      const answer = await askAnalyst(captureId, question);
      setMessages((m) => [...m, { role: "assistant", answer }]);
    } catch (e) {
      setMessages((m) => [...m, { role: "error", text: e instanceof Error ? e.message : String(e) }]);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    if (initial && asked.current !== initial) {
      asked.current = initial;
      ask(initial);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initial]);

  useEffect(() => {
    scroller.current?.scrollTo({ top: scroller.current.scrollHeight, behavior: "smooth" });
  }, [messages, busy]);

  return (
    <Panel
      title="Ask the analyst"
      flush
      info={
        card.data
          ? `Runs locally. Questions are classified by ${card.data.algorithm} (${card.data.training_examples} training examples, ${Math.round(card.data.cv_accuracy * 100)}% cross-validated accuracy) and answered by computing over this capture's evidence. No text is generated freely.`
          : "Runs locally against this capture's evidence."
      }
      actions={
        messages.length > 0 && (
          <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => setMessages([])}>
            <X className="size-3" /> Clear
          </Button>
        )
      }
    >
      <div className="flex h-[560px] flex-col">
        <div ref={scroller} className="flex-1 space-y-4 overflow-y-auto p-4">
          {!messages.length && (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">Ask about findings, sessions, certificates, post-quantum readiness or attack scenarios, or ask what a change would do before you make it.</p>
              <div className="flex flex-wrap gap-1.5">
                {(card.data?.examples ?? []).map((e) => (
                  <button key={e} type="button" onClick={() => ask(e)} className="rounded-md border px-2.5 py-1 text-xs hover:bg-muted">
                    {e}
                  </button>
                ))}
              </div>
            </div>
          )}
          {messages.map((m, i) =>
            m.role === "user" ? (
              <div key={i} className="flex justify-end">
                <div className="max-w-[80%] rounded-lg bg-primary px-3 py-2 text-sm text-primary-foreground">{m.text}</div>
              </div>
            ) : m.role === "error" ? (
              <div key={i} className="text-sm text-destructive">{m.text}</div>
            ) : (
              <div key={i} className="rounded-lg border bg-background p-3">
                <AnswerView a={m.answer} captureId={captureId} onAsk={ask} />
              </div>
            ),
          )}
          {busy && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="size-3.5 animate-spin" /> Analysing evidence…
            </div>
          )}
        </div>
        <form
          className="flex gap-2 border-t p-3"
          onSubmit={(e) => {
            e.preventDefault();
            ask(input);
          }}
        >
          <Input value={input} onChange={(e) => setInput(e.target.value)} placeholder="e.g. What if we disable TLS 1.0?" className="h-9" />
          <Button type="submit" size="icon" className="size-9 shrink-0" disabled={busy || !input.trim()} aria-label="Ask">
            <ArrowUp className="size-4" />
          </Button>
        </form>
      </div>
    </Panel>
  );
}

const LEVEL_COLOR: Record<string, string> = {
  High: "hsl(var(--sev-critical))",
  Elevated: "hsl(var(--sev-high))",
  Low: "hsl(var(--sev-medium))",
};

function ScenarioDetail({ s, captureId }: { s: AttackScenario; captureId: string }) {
  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">{s.summary}</p>
      <div className="overflow-x-auto">
        <div className="flex min-w-max items-stretch gap-1">
          {s.stages.map((st, i) => (
            <div key={st.stage} className="flex items-stretch">
              <div className="w-[180px] rounded-md border p-2.5">
                <div className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  {i + 1}. {st.stage}
                </div>
                <div className="mt-1 text-xs leading-snug">{st.description}</div>
                <div className="mt-2 flex flex-wrap gap-1">
                  {st.techniques.map((t) => (
                    <a key={t.id} href={t.url} target="_blank" rel="noreferrer" title={t.name} className="inline-flex items-center gap-0.5 rounded border bg-muted/40 px-1 font-mono text-[10.5px] hover:bg-muted">
                      {t.id}
                      <ExternalLink className="size-2.5 opacity-60" />
                    </a>
                  ))}
                </div>
              </div>
              {i < s.stages.length - 1 && <ArrowRight className="mx-0.5 size-3.5 self-center text-muted-foreground" />}
            </div>
          ))}
        </div>
      </div>
      <div>
        <div className="mb-1.5 text-xs font-medium text-muted-foreground">Indicators</div>
        <div className="divide-y rounded-md border">
          {s.indicators.map((ind) => (
            <div key={ind.label} className="flex items-center gap-3 px-3 py-2 text-sm">
              {ind.observed ? <Check className="size-3.5 shrink-0 text-sev-critical" /> : <X className="size-3.5 shrink-0 text-muted-foreground/50" />}
              <span className={cn("flex-1", !ind.observed && "text-muted-foreground")}>
                {ind.label}
                {ind.required && <span className="ml-1.5 text-[11px] text-muted-foreground">(required)</span>}
              </span>
              <span className="flex gap-1">
                {ind.findings.slice(0, 3).map((f) => (
                  <Link key={f} to={`/c/${captureId}/findings/${f}`} className="font-mono text-xs underline-offset-2 hover:underline">
                    {f}
                  </Link>
                ))}
              </span>
              <span className="tabular w-16 text-right text-xs text-muted-foreground">w {ind.weight.toFixed(2)}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <span>Mitigated by:</span>
        {s.mitigations.map((m) => (
          <Link key={m} to={`/c/${captureId}/remediation?fix=${m}`} className="rounded border px-1.5 py-0.5 hover:bg-muted">
            {m.replace(/_/g, " ")}
          </Link>
        ))}
      </div>
    </div>
  );
}

function AttackPanel({ captureId }: { captureId: string }) {
  const { data, error } = useAttackPaths(captureId);
  const [sel, setSel] = useState(0);
  if (error) return <ErrorState error={error} />;
  return (
    <Panel title="Attack paths" info={data?.method}>
      {!data ? (
        <Loading rows={2} />
      ) : !data.scenarios.length ? (
        <Empty title="No attack scenario is supported by the findings" />
      ) : (
        <div className="space-y-4">
          <div className="space-y-1">
            {data.scenarios.map((s, i) => (
              <button
                key={s.key}
                type="button"
                onClick={() => setSel(i)}
                className={cn("grid w-full grid-cols-[1fr_120px_60px] items-center gap-3 rounded-md px-2.5 py-2 text-left text-sm hover:bg-muted/60", sel === i && "bg-muted")}
              >
                <span className="flex min-w-0 items-center gap-2">
                  <Dot color={LEVEL_COLOR[s.level]} />
                  <span className="truncate">{s.title}</span>
                </span>
                <Meter value={s.likelihood * 100} color={LEVEL_COLOR[s.level]} />
                <span className="tabular text-right text-xs text-muted-foreground">{Math.round(s.likelihood * 100)}%</span>
              </button>
            ))}
          </div>
          <div className="border-t pt-4">
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <span className="font-medium">{data.scenarios[sel].title}</span>
              <Tag>{data.scenarios[sel].impact_label}</Tag>
              <span className="text-xs text-muted-foreground">exposure {data.scenarios[sel].exposure_pct}% of sessions</span>
            </div>
            <ScenarioDetail s={data.scenarios[sel]} captureId={captureId} />
          </div>
        </div>
      )}
    </Panel>
  );
}

const PALETTE = ["hsl(var(--chart-1))", "hsl(var(--chart-2))", "hsl(var(--chart-3))", "hsl(var(--chart-4))", "hsl(var(--chart-5))"];

function FingerprintPanel({ captureId }: { captureId: string }) {
  const { data, error } = useFingerprints(captureId);
  const navigate = useNavigate();
  if (error) return <ErrorState error={error} />;
  if (!data) return <Loading rows={1} />;
  const clusterIds = [...new Set(data.points.map((p) => p.cluster))];
  // Identical handshakes share coordinates: aggregate them and size by count.
  const agg = new Map<string, (typeof data.points)[number] & { count: number; refs: string[] }>();
  for (const p of data.points) {
    const k = `${p.cluster}|${p.x}|${p.y}`;
    const e = agg.get(k);
    if (e) {
      e.count++;
      e.refs.push(p.ref);
    } else agg.set(k, { ...p, count: 1, refs: [p.ref] });
  }
  const points = [...agg.values()];
  const novelIds = new Set(data.clusters.filter((c) => c.novel).map((c) => c.id));
  const normalIds = clusterIds.filter((x) => !novelIds.has(x));
  const color = (c: string) => (novelIds.has(c) ? "hsl(var(--sev-critical))" : PALETTE[Math.max(normalIds.indexOf(c), 0) % PALETTE.length]);
  const config = Object.fromEntries(clusterIds.map((c) => [c, { label: c, color: color(c) }])) satisfies ChartConfig;

  return (
    <Panel
      title="Client TLS fingerprints"
      info={data.method ?? data.reason}
      description={data.available ? `${data.cluster_count} client stack${data.cluster_count === 1 ? "" : "s"} · ${data.novel_count} novel handshake${data.novel_count === 1 ? "" : "s"}` : undefined}
    >
      {!data.available ? (
        <div className="text-sm text-muted-foreground">{data.reason}</div>
      ) : (
        <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
          <ChartContainer config={config} className="h-[280px] w-full">
            <ScatterChart margin={{ top: 10, right: 10, bottom: 10, left: 0 }}>
              <CartesianGrid />
              <XAxis type="number" dataKey="x" name="PC1" tickLine={false} axisLine={false} fontSize={10} />
              <YAxis type="number" dataKey="y" name="PC2" tickLine={false} axisLine={false} fontSize={10} width={30} />
              <ZAxis type="number" dataKey="count" range={[60, 600]} />
              <RTooltip
                cursor={false}
                content={({ payload }) => {
                  const p = payload?.[0]?.payload as (typeof points)[number] | undefined;
                  return p ? (
                    <div className="rounded-md border bg-popover px-2.5 py-1.5 text-xs shadow">
                      <div className="font-mono">
                        {p.count > 1 ? `${p.count} handshakes · ${p.refs.slice(0, 3).join(", ")}…` : p.ref}
                      </div>
                      <div className="text-muted-foreground">
                        {p.cluster} · {p.client}
                      </div>
                      <div className="font-mono text-[10px] text-muted-foreground">{p.ja4}</div>
                    </div>
                  ) : null;
                }}
              />
              {clusterIds.map((c) => (
                <Scatter
                  key={c}
                  data={points.filter((p) => p.cluster === c)}
                  fill={color(c)}
                  shape={novelIds.has(c) ? "diamond" : "circle"}
                  isAnimationActive={false}
                  onClick={(p: { ref?: string }) => p?.ref && navigate(`/c/${captureId}/sessions/${p.ref}`)}
                />
              ))}
            </ScatterChart>
          </ChartContainer>
          <div className="max-h-[280px] overflow-auto rounded-md border">
            <Table>
              <TableHeader className="bg-muted/40">
                <TableRow className="hover:bg-transparent">
                  <TableHead className="h-8 text-xs">Stack</TableHead>
                  <TableHead className="h-8 text-xs">Sessions</TableHead>
                  <TableHead className="h-8 text-xs">Max TLS</TableHead>
                  <TableHead className="h-8 text-xs">PQC</TableHead>
                  <TableHead className="h-8 text-xs">JA4</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.clusters.map((c) => (
                  <TableRow key={c.id} className="hover:bg-transparent">
                    <TableCell className="py-1.5">
                      <span className="inline-flex items-center gap-1.5 text-xs">
                        <Dot color={color(c.id)} className="size-1.5" />
                        {c.novel ? "Novel" : c.id}
                      </span>
                    </TableCell>
                    <TableCell className="tabular py-1.5 text-xs">
                      {c.size} <span className="text-muted-foreground">({c.share_pct}%)</span>
                    </TableCell>
                    <TableCell className="py-1.5 text-xs">{c.profile.max_version ?? "—"}</TableCell>
                    <TableCell className="py-1.5 text-xs">{c.profile.offers_pqc ? "Offered" : "—"}</TableCell>
                    <TableCell className="max-w-[220px] truncate py-1.5 font-mono text-[11px]">{c.ja4}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </div>
      )}
    </Panel>
  );
}

export function AnalystPage() {
  const { captureId } = useParams();
  const [params] = useSearchParams();
  const q = params.get("q");
  return (
    <>
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="space-y-1">
          <h1 className="text-lg font-semibold tracking-tight">AI Analyst</h1>
          <p className="text-sm text-muted-foreground">Evidence-grounded summaries, questions, attack scenarios and client behaviour analysis. All models run locally.</p>
        </div>
        <InfoTip>
          Models: session risk classifier (gradient-boosted trees), anomaly detection (Isolation Forest), client stack clustering (DBSCAN), question intent (TF-IDF + logistic regression). Verdicts remain with the deterministic rules.
        </InfoTip>
      </div>
      <BriefPanel captureId={captureId!} />
      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <AskPanel captureId={captureId!} initial={q} />
        <AttackPanel captureId={captureId!} />
      </div>
      <FingerprintPanel captureId={captureId!} />
    </>
  );
}

