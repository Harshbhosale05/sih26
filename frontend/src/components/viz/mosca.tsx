import type { QuantumForecast } from "@/lib/types";

/**
 * Mosca timeline: how long captured mail must stay confidential (X), how long
 * migration takes (Y), and when a quantum computer may arrive (Z, three
 * scenarios). Where the confidentiality bar crosses a Z line, today's
 * classical traffic is still sensitive when it becomes decryptable.
 */
export function MoscaTimeline({ f }: { f: QuantumForecast }) {
  const now = new Date();
  const today = now.getFullYear() + now.getMonth() / 12;
  const start = Math.floor(Math.min(f.captured_year, today));
  const end = Math.max(2050, Math.ceil(f.confidential_until + 1), Math.ceil(today + f.migration_years + 1));
  const W = 900;
  const L = 170;
  const x = (yr: number) => L + ((yr - start) / (end - start)) * (W - L - 20);
  const rows = [
    { label: "Mail stays confidential", from: f.captured_year, to: f.confidential_until, color: "hsl(var(--sev-medium))", note: `X = ${f.shelf_life_years} y` },
    { label: "Migration to quantum-safe", from: today, to: today + f.migration_years, color: "hsl(var(--chart-1))", note: `Y ≈ ${f.migration_years} y` },
  ];
  const H = 150;
  const ticks = [];
  for (let y = Math.ceil(start / 5) * 5; y <= end; y += 5) ticks.push(y);

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label="Quantum risk timeline">
      {ticks.map((t) => (
        <g key={t}>
          <line x1={x(t)} x2={x(t)} y1={18} y2={H - 22} stroke="hsl(var(--grid-line))" />
          <text x={x(t)} y={H - 6} fontSize={11} textAnchor="middle" fill="hsl(var(--muted-foreground))">
            {t}
          </text>
        </g>
      ))}
      {rows.map((r, i) => (
        <g key={r.label}>
          <text x={0} y={46 + i * 38} fontSize={12} fill="hsl(var(--foreground))">
            {r.label}
          </text>
          <rect x={x(r.from)} y={34 + i * 38} width={Math.max(x(r.to) - x(r.from), 3)} height={16} rx={3} fill={r.color} opacity={0.85} />
          <text x={x(r.to) + 6} y={46 + i * 38} fontSize={11} fill="hsl(var(--muted-foreground))">
            {r.note}
          </text>
        </g>
      ))}
      {f.scenarios.map((s) => {
        const risk = s.captured_traffic_at_risk;
        const color = risk ? "hsl(var(--sev-critical))" : "hsl(var(--sev-ok))";
        return (
          <g key={s.key}>
            <line x1={x(s.year)} x2={x(s.year)} y1={14} y2={H - 22} stroke={color} strokeWidth={1.5} strokeDasharray="4 3" />
            <text x={x(s.year)} y={11} fontSize={10.5} textAnchor="middle" fill={color} fontWeight={600}>
              Z {s.label} {s.year}
            </text>
          </g>
        );
      })}
      <line x1={x(today)} x2={x(today)} y1={18} y2={H - 22} stroke="hsl(var(--foreground))" strokeWidth={1} />
      <text x={x(today) + 4} y={H - 26} fontSize={10} fill="hsl(var(--muted-foreground))">
        today
      </text>
    </svg>
  );
}
