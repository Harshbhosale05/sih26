import { Fragment } from "react";

import { Empty, ErrorState, Loading, Meter, PageHeader, Panel, Stat } from "@/components/common";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useFixCatalogue, useModelCard } from "@/lib/api";
import { riskColor } from "@/lib/format";

export function ModelPage() {
  const { data: card, error } = useModelCard();
  const fixes = useFixCatalogue();

  if (error) return <ErrorState error={error} />;
  if (!card) return <Loading rows={3} />;
  if (!card.available || !card.evaluation) return <Empty title="Risk model not trained">{card.reason}</Empty>;

  const ev = card.evaluation;
  const cm = ev.confusion_matrix;
  const maxCell = Math.max(...cm.matrix.flat());
  const importance = (card.feature_importance ?? []).slice(0, 12);
  const maxImp = Math.max(...importance.map((f) => f.permutation_importance), 0.001);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Risk model"
        description="SecureMailScope's own session risk classifier — trained in-house, runs locally, no external AI service. It ranks and explains; every verdict still comes from a deterministic rule."
      />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat label="Held-out accuracy" value={`${(ev.holdout_accuracy * 100).toFixed(1)}%`} sub={`${ev.holdout_rows} unseen sessions`} />
        <Stat label="Held-out macro-F1" value={ev.holdout_macro_f1.toFixed(3)} />
        <Stat label="5-fold CV macro-F1" value={ev.cv_macro_f1_mean.toFixed(3)} sub={`± ${ev.cv_macro_f1_std.toFixed(3)}`} />
        <Stat label="Training sessions" value={card.training_rows} sub={`${card.features} features`} />
        <Stat label="Model" value="GBDT" sub={card.algorithm?.replace(/\(.*\)/, "").trim()} />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Confusion matrix (held-out)" description="Rows are the true class, columns the prediction.">
          <div className="grid gap-1" style={{ gridTemplateColumns: `90px repeat(${cm.labels.length}, 1fr)` }}>
            <div />
            {cm.labels.map((l) => (
              <div key={l} className="pb-1 text-center text-[11px] text-muted-foreground">
                {l}
              </div>
            ))}
            {cm.matrix.map((row, i) => (
              <Fragment key={i}>
                <div className="flex items-center text-xs font-medium" style={{ color: riskColor(cm.labels[i]) }}>
                  {cm.labels[i]}
                </div>
                {row.map((v, j) => (
                  <div
                    key={j}
                    className="tabular grid h-11 place-items-center rounded text-sm font-medium"
                    style={{
                      background: i === j ? `hsl(var(--sev-ok) / ${0.12 + (0.6 * v) / maxCell})` : v ? `hsl(var(--sev-critical) / ${0.15 + (0.5 * v) / maxCell})` : "hsl(var(--muted) / 0.5)",
                    }}
                  >
                    {v}
                  </div>
                ))}
              </Fragment>
            ))}
          </div>
        </Panel>

        <Panel title="What the model relies on" description="Permutation importance on held-out data: the drop in macro-F1 when a feature is shuffled.">
          <div className="space-y-2">
            {importance.map((f) => (
              <div key={f.feature} className="flex items-center gap-3 text-xs">
                <span className="w-48 shrink-0 truncate">{f.label}</span>
                <Meter value={(100 * f.permutation_importance) / maxImp} color="hsl(var(--chart-3))" />
                <span className="tabular w-12 shrink-0 text-right text-muted-foreground">{f.permutation_importance.toFixed(3)}</span>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Per-class performance">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Class</TableHead>
                <TableHead className="text-right">Precision</TableHead>
                <TableHead className="text-right">Recall</TableHead>
                <TableHead className="text-right">F1</TableHead>
                <TableHead className="text-right">Support</TableHead>
                <TableHead className="text-right">Training rows</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {Object.entries(ev.per_class).map(([k, v]) => (
                <TableRow key={k}>
                  <TableCell className="font-medium" style={{ color: riskColor(k) }}>
                    {k}
                  </TableCell>
                  <TableCell className="tabular text-right">{v.precision.toFixed(3)}</TableCell>
                  <TableCell className="tabular text-right">{v.recall.toFixed(3)}</TableCell>
                  <TableCell className="tabular text-right">{v["f1-score"].toFixed(3)}</TableCell>
                  <TableCell className="tabular text-right">{v.support}</TableCell>
                  <TableCell className="tabular text-right">{card.class_counts?.[k] ?? "—"}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Panel>
        <Panel title="How it was built">
          <div className="space-y-3 text-sm">
            <p>
              <b>Labels.</b> <span className="text-muted-foreground">{card.labelling}</span>
            </p>
            <p>
              <b>Explanations.</b> <span className="text-muted-foreground">{card.explanation_method}</span>
            </p>
            <div>
              <b>Limitations.</b>
              <ul className="mt-1 list-disc space-y-1 pl-4 text-muted-foreground">
                {card.limitations?.map((l) => (
                  <li key={l}>{l}</li>
                ))}
              </ul>
            </div>
            <p className="text-xs text-muted-foreground">
              Retrain with <code className="rounded bg-muted px-1 font-mono">make train</code> · scikit-learn {card.sklearn_version} · version {card.version}
            </p>
          </div>
        </Panel>
      </div>

      {fixes.data && (
        <Panel title="Remediation knowledge base" description="Playbooks the planner and simulator use — each written against the product's documented configuration syntax.">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Fix</TableHead>
                <TableHead>Resolves</TableHead>
                <TableHead>Software-specific config</TableHead>
                <TableHead className="text-right">Effort</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {fixes.data.map((f) => (
                <TableRow key={f.id}>
                  <TableCell>
                    <div className="font-medium">{f.title}</div>
                    <div className="text-xs text-muted-foreground">{f.standards.join(" · ")}</div>
                  </TableCell>
                  <TableCell className="max-w-[320px] text-xs text-muted-foreground">{f.resolves.map((r) => r.replace(/_/g, " ")).join(", ")}</TableCell>
                  <TableCell className="text-xs">{f.software.join(", ") || "all (DNS / shell)"}</TableCell>
                  <TableCell className="tabular text-right">{f.effort}/3</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Panel>
      )}
    </div>
  );
}
