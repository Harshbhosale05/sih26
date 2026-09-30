import { motion } from "framer-motion";

import { RiskBadge } from "@/components/common";
import { RISK_CLASSES, riskColor } from "@/lib/format";
import type { RiskDetail } from "@/lib/types";

const LEVELS = ["minimal", "low", "medium", "high", "critical"];

/**
 * Shapley waterfall: the session's healthy baseline, then each risk-factor
 * group's exact contribution, ending at the model's expected severity.
 */
export function RiskDrivers({ risk }: { risk: RiskDetail }) {
  const baseline = risk.baseline_severity ?? 0;
  const final = (risk.score / 100) * 4;
  const drivers = [...risk.drivers].sort((a, b) => b.impact - a.impact);
  const x = (v: number) => `${(Math.max(0, Math.min(4, v)) / 4) * 100}%`;

  let cursor = baseline;
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <RiskBadge risk={risk.risk_class} score={risk.score} />
        <span className="text-muted-foreground">
          {Math.round(risk.confidence * 100)}% model confidence · baseline for this session type is <b className="text-foreground">{risk.baseline_class}</b>
        </span>
      </div>

      <div className="space-y-1.5">
        <div className="relative ml-[180px] h-4 text-[10px] text-muted-foreground">
          {LEVELS.map((l, i) => (
            <span key={l} className="absolute -translate-x-1/2" style={{ left: `${(i / 4) * 100}%` }}>
              {l}
            </span>
          ))}
        </div>
        <Bar label="Healthy baseline" sub="same session, every risk factor reset" from={0} to={baseline} color="hsl(var(--muted-foreground) / 0.45)" x={x} value={baseline} />
        {drivers.map((d, i) => {
          const from = cursor;
          cursor += d.impact;
          return (
            <Bar
              key={d.feature}
              label={d.label}
              sub={d.detail}
              from={from}
              to={cursor}
              color={d.impact >= 0 ? "hsl(var(--sev-critical))" : "hsl(var(--sev-ok))"}
              x={x}
              value={d.impact}
              signed
              delay={0.08 * (i + 1)}
            />
          );
        })}
        <Bar label="Model output" sub={`expected severity ${final.toFixed(2)} of 4`} from={0} to={final} color={riskColor(risk.risk_class)} x={x} value={final} bold />
      </div>

      <div className="flex flex-wrap gap-3 text-[11px] text-muted-foreground">
        {RISK_CLASSES.slice().reverse().map((c) => (
          <span key={c} className="tabular">
            P({c}) <b className="text-foreground">{Math.round((risk.probabilities[c] ?? 0) * 100)}%</b>
          </span>
        ))}
      </div>
    </div>
  );
}

function Bar({
  label,
  sub,
  from,
  to,
  color,
  x,
  value,
  signed,
  bold,
  delay = 0,
}: {
  label: string;
  sub?: string;
  from: number;
  to: number;
  color: string;
  x: (v: number) => string;
  value: number;
  signed?: boolean;
  bold?: boolean;
  delay?: number;
}) {
  const lo = Math.min(from, to);
  const hi = Math.max(from, to);
  return (
    <div className="flex items-center gap-3">
      <div className="w-[168px] shrink-0 leading-tight">
        <div className={bold ? "text-xs font-semibold" : "text-xs font-medium"}>{label}</div>
        {sub && <div className="truncate text-[10.5px] text-muted-foreground">{sub}</div>}
      </div>
      <div className="relative h-5 flex-1 rounded bg-muted/50">
        {[1, 2, 3].map((g) => (
          <div key={g} className="absolute inset-y-0 w-px bg-border" style={{ left: `${(g / 4) * 100}%` }} />
        ))}
        <motion.div
          className="absolute inset-y-0.5 rounded-sm"
          style={{ background: color, left: x(lo) }}
          initial={{ width: 0 }}
          animate={{ width: `calc(${x(hi)} - ${x(lo)})` }}
          transition={{ duration: 0.5, delay }}
        />
      </div>
      <div className="tabular w-12 shrink-0 text-right text-xs font-medium">
        {signed && value > 0 ? "+" : ""}
        {value.toFixed(2)}
      </div>
    </div>
  );
}
