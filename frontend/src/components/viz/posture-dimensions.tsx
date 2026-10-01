import { motion } from "framer-motion";

import { InfoTip } from "@/components/common";
import { scoreColor } from "@/lib/format";
import type { Dimension } from "@/lib/types";

/** Posture dimensions: score bar and coverage. `after` overlays a projected score. */
export function PostureDimensions({ dimensions, after }: { dimensions: Dimension[]; after?: Dimension[] }) {
  const byKey = new Map((after ?? []).map((d) => [d.key, d]));
  return (
    <div className="space-y-3.5">
      {dimensions.map((d, i) => {
        const next = byKey.get(d.key);
        const changed = next && next.score !== d.score;
        return (
          <div key={d.key} className="space-y-1.5">
            <div className="flex items-center justify-between gap-3 text-[13px]">
              <div className="flex min-w-0 items-center gap-1.5">
                <span className="truncate">{d.label}</span>
                <InfoTip>
                  <div className="space-y-1">
                    <div>{d.standard}</div>
                    <div className="text-muted-foreground">Weight {Math.round(d.weight * 100)}% · coverage {d.coverage_pct == null ? "—" : `${Math.round(d.coverage_pct)}%`}</div>
                    {(d.contributors.length ? d.contributors : [d.detail]).map((c) => (
                      <div key={c}>· {c}</div>
                    ))}
                  </div>
                </InfoTip>
              </div>
              <div className="tabular shrink-0 text-right">
                {d.score == null ? (
                  <span className="text-xs text-muted-foreground">Not assessed</span>
                ) : (
                  <>
                    <span className="font-medium">{d.score}</span>
                    {changed && next && (
                      <>
                        <span className="mx-1 text-muted-foreground">→</span>
                        <span className="font-medium" style={{ color: scoreColor(next.score) }}>
                          {next.score ?? "—"}
                        </span>
                      </>
                    )}
                  </>
                )}
              </div>
            </div>
            <div className="relative h-1.5 overflow-hidden rounded-full bg-muted">
              {changed && next?.score != null && (
                <motion.div
                  className="absolute inset-y-0 left-0 rounded-full"
                  style={{ background: scoreColor(next.score), opacity: 0.35 }}
                  initial={{ width: 0 }}
                  animate={{ width: `${next.score}%` }}
                  transition={{ duration: 0.6, delay: 0.05 * i }}
                />
              )}
              <motion.div
                className="absolute inset-y-0 left-0 rounded-full"
                style={{ background: d.score == null ? "transparent" : scoreColor(d.score) }}
                initial={{ width: 0 }}
                animate={{ width: `${d.score ?? 0}%` }}
                transition={{ duration: 0.6, delay: 0.04 * i }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}
