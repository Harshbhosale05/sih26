import { animate, motion, useMotionValue, useTransform } from "framer-motion";
import { useEffect } from "react";

import { scoreColor } from "@/lib/format";

/** Semicircular 0–100 gauge. `ghost` draws a second, faded value (e.g. the before-fix score). */
export function ScoreGauge({
  score,
  ghost,
  size = 180,
  label,
  sub,
}: {
  score: number | null | undefined;
  ghost?: number | null;
  size?: number;
  label?: string;
  sub?: string;
}) {
  const stroke = Math.round(size / 13);
  const r = (size - stroke) / 2;
  const cx = size / 2;
  const cy = size / 2;
  const length = Math.PI * r;
  const arc = `M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`;

  const mv = useMotionValue(0);
  const text = useTransform(mv, (v) => Math.round(v).toString());
  useEffect(() => {
    const controls = animate(mv, score ?? 0, { duration: 0.9, ease: "easeOut" });
    return () => controls.stop();
  }, [score, mv]);

  const color = scoreColor(score);
  return (
    <div className="relative flex flex-col items-center" style={{ width: size, paddingBottom: label ? 22 : 8 }}>
      <svg width={size} height={size / 2 + stroke / 2} viewBox={`0 0 ${size} ${size / 2 + stroke / 2}`} aria-hidden>
        <path d={arc} fill="none" stroke="hsl(var(--muted))" strokeWidth={stroke} strokeLinecap="round" />
        {ghost != null && (
          <path
            d={arc}
            fill="none"
            stroke={scoreColor(ghost)}
            strokeOpacity={0.28}
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={`${(length * ghost) / 100} ${length}`}
          />
        )}
        {score != null && (
          <motion.path
            d={arc}
            fill="none"
            stroke={color}
            strokeWidth={stroke}
            strokeLinecap="round"
            initial={{ strokeDasharray: `0 ${length}` }}
            animate={{ strokeDasharray: `${(length * score) / 100} ${length}` }}
            transition={{ duration: 0.9, ease: "easeOut" }}
          />
        )}
      </svg>
      <div className="absolute inset-x-0 flex flex-col items-center" style={{ top: size * 0.2 }}>
        <div className="tabular flex items-baseline gap-0.5 font-semibold tracking-tight" style={{ color, fontSize: size / 4.2 }}>
          {score == null ? "—" : <motion.span>{text}</motion.span>}
          <span className="text-sm font-medium text-muted-foreground">/100</span>
        </div>
        {label && <div className="text-xs font-medium text-muted-foreground">{label}</div>}
      </div>
      {sub && <div className="mt-1 text-center text-xs text-muted-foreground">{sub}</div>}
    </div>
  );
}
