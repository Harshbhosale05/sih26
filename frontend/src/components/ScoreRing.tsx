import { scoreStatus } from "../lib/format";

const STROKE: Record<string, string> = {
  good: "rgb(var(--good))",
  warn: "rgb(var(--warn))",
  serious: "rgb(var(--serious))",
  crit: "rgb(var(--crit))",
  none: "rgb(var(--muted))",
};

/** A single headline score. Not a chart: one number, one ring, one label. */
export function ScoreRing({
  score,
  size = 132,
  label,
  sublabel,
}: {
  score: number | null;
  size?: number;
  label?: string;
  sublabel?: string;
}) {
  const stroke = 10;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const status = scoreStatus(score);
  const offset = score === null ? c : c * (1 - score / 100);

  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgb(var(--line))" strokeWidth={stroke} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={STROKE[status]}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 700ms ease" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
        <span className="text-[34px] font-semibold leading-none tracking-tight text-ink">
          {score === null ? "—" : score}
        </span>
        {label && <span className="mt-1 text-[11px] font-medium uppercase tracking-wider text-muted">{label}</span>}
        {sublabel && <span className="text-[11px] text-ink2">{sublabel}</span>}
      </div>
    </div>
  );
}
