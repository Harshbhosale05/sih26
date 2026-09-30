import { motion } from "framer-motion";

import { scoreColor } from "@/lib/format";
import type { Dimension } from "@/lib/types";

/** Six posture dimensions: score bar, coverage, weight. `after` overlays a projected score. */
export function PostureDimensions({ dimensions, after }: { dimensions: Dimension[]; after?: Dimension[] }) {
  const byKey = new Map((after ?? []).map((d) => [d.key, d]));
  return (
    <div className="space-y-3">
      {dimensions.map((d, i) => {
        const next = byKey.get(d.key);
        const changed = next && next.score !== d.score;
        return (
          <div key={d.key} className="space-y-1">
            <div className="flex items-baseline justify-between gap-3 text-xs">
              <div className="min-w-0">
                <span className="font-medium">{d.label}</span>
                <span className="ml-2 text-muted-foreground">{Math.round(d.weight * 100)}% weight</span>
              </div>
              <div className="tabular shrink-0 text-right">
                {d.score == null ? (
                  <span className="text-[10.5px] font-semibold uppercase tracking-wide text-muted-foreground">Not assessed</span>
                ) : (
                  <>
                    <span className="font-semibold" style={{ color: scoreColor(d.score) }}>
                      {d.score}
                    </span>
                    {changed && next && (
                      <>
                        <span className="mx-1 text-muted-foreground">→</span>
                        <span className="font-semibold" style={{ color: scoreColor(next.score) }}>
                          {next.score ?? "—"}
                        </span>
                      </>
                    )}
                  </>
                )}
                <span className="ml-2 text-muted-foreground">cov {d.coverage_pct == null ? "—" : `${Math.round(d.coverage_pct)}%`}</span>
              </div>
            </div>
            <div className="relative h-2 overflow-hidden rounded-full bg-muted">
              {changed && next?.score != null && (
                <motion.div
                  className="absolute inset-y-0 left-0 rounded-full"
                  style={{ background: scoreColor(next.score), opacity: 0.35 }}
                  initial={{ width: 0 }}
                  animate={{ width: `${next.score}%` }}
                  transition={{ duration: 0.7, delay: 0.1 * i }}
                />
              )}
              <motion.div
                className="absolute inset-y-0 left-0 rounded-full"
                style={{ background: scoreColor(d.score) }}
                initial={{ width: 0 }}
                animate={{ width: `${d.score ?? 0}%` }}
                transition={{ duration: 0.7, delay: 0.05 * i }}
              />
            </div>
            {d.contributors.length > 0 && !after && (
              <div className="text-[11px] text-muted-foreground">{d.contributors.slice(0, 2).join(" · ")}</div>
            )}
          </div>
        );
      })}
    </div>
  );
}
