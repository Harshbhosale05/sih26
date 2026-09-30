import { useMemo, useState } from "react";

import { stateLabel, stateTone, toneColor } from "@/lib/format";
import type { Session } from "@/lib/types";

/**
 * Three-column flow: protocol → encryption outcome → negotiated TLS version.
 * Band width is session count. Built as plain SVG so labels, colours and
 * hover behaviour stay exact.
 */
export function OutcomeFlow({ sessions, height = 300 }: { sessions: Session[]; height?: number }) {
  const [hover, setHover] = useState<string | null>(null);

  const model = useMemo(() => {
    const email = sessions.filter((s) => s.protocol);
    const cols: string[][] = [[], [], []];
    const key = (s: Session) => [s.protocol!, s.encryption_state, s.tls_version ?? "No TLS"];
    const links = new Map<string, number>();
    const counts = [new Map<string, number>(), new Map<string, number>(), new Map<string, number>()];
    for (const s of email) {
      const [a, b, c] = key(s);
      [a, b, c].forEach((v, i) => counts[i].set(v, (counts[i].get(v) ?? 0) + 1));
      links.set(`0|${a}|1|${b}`, (links.get(`0|${a}|1|${b}`) ?? 0) + 1);
      links.set(`1|${b}|2|${c}`, (links.get(`1|${b}|2|${c}`) ?? 0) + 1);
    }
    const order = [
      (a: string, b: string) => a.localeCompare(b),
      (a: string, b: string) => stateTone(a).localeCompare(stateTone(b)) || a.localeCompare(b),
      (a: string, b: string) => b.localeCompare(a),
    ];
    counts.forEach((m, i) => (cols[i] = [...m.keys()].sort(order[i])));
    return { total: email.length, cols, counts, links };
  }, [sessions]);

  if (!model.total) return <div className="text-sm text-muted-foreground">No email sessions.</div>;

  const W = 900;
  const H = height;
  const NODE_W = 12;
  const GAP = 18;
  const colX = [150, W / 2 - NODE_W / 2, W - 150 - NODE_W];
  const scale = (H - 20 - GAP * Math.max(...model.cols.map((c) => c.length))) / model.total;

  const pos: Record<string, { y: number; h: number; outY: number; inY: number }> = {};
  model.cols.forEach((col, ci) => {
    let y = 10;
    for (const v of col) {
      const h = Math.max((model.counts[ci].get(v) ?? 0) * scale, 3);
      pos[`${ci}|${v}`] = { y, h, outY: y, inY: y };
      y += h + GAP;
    }
  });

  const colorOf = (ci: number, v: string) =>
    ci === 1
      ? toneColor(stateTone(v))
      : ci === 2
        ? v === "No TLS"
          ? "hsl(var(--sev-high))"
          : v === "TLS 1.3"
            ? "hsl(var(--sev-ok))"
            : v === "TLS 1.2"
              ? "hsl(var(--sev-low))"
              : "hsl(var(--sev-critical))"
        : "hsl(var(--chart-3))";

  const paths = [...model.links.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([k, n]) => {
      const [c1, v1, c2, v2] = k.split("|");
      const a = pos[`${c1}|${v1}`];
      const b = pos[`${c2}|${v2}`];
      const h = n * scale;
      const x1 = colX[+c1] + NODE_W;
      const x2 = colX[+c2];
      const y1 = a.outY + h / 2;
      const y2 = b.inY + h / 2;
      a.outY += h;
      b.inY += h;
      const mx = (x1 + x2) / 2;
      return {
        k,
        d: `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`,
        h: Math.max(h, 1),
        color: colorOf(+c2, v2),
        n,
        label: `${c1 === "0" ? v1 : stateLabel(v1)} → ${c2 === "1" ? stateLabel(v2) : v2}`,
        touches: [`${c1}|${v1}`, `${c2}|${v2}`],
      };
    });

  return (
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label="Protocol to encryption outcome to TLS version">
        {paths.map((p) => (
          <path
            key={p.k}
            d={p.d}
            fill="none"
            stroke={p.color}
            strokeOpacity={hover ? (p.touches.includes(hover) || hover === p.k ? 0.55 : 0.06) : 0.28}
            strokeWidth={p.h}
            onMouseEnter={() => setHover(p.k)}
            onMouseLeave={() => setHover(null)}
            style={{ transition: "stroke-opacity .2s" }}
          >
            <title>
              {p.label}: {p.n} session(s)
            </title>
          </path>
        ))}
        {model.cols.map((col, ci) =>
          col.map((v) => {
            const p = pos[`${ci}|${v}`];
            const color = colorOf(ci, v);
            const n = model.counts[ci].get(v) ?? 0;
            const label = ci === 1 ? stateLabel(v) : v;
            const anchor = ci === 0 ? "end" : ci === 2 ? "start" : "middle";
            const tx = ci === 0 ? colX[0] - 8 : ci === 2 ? colX[2] + NODE_W + 8 : colX[1] + NODE_W / 2;
            return (
              <g key={`${ci}|${v}`} onMouseEnter={() => setHover(`${ci}|${v}`)} onMouseLeave={() => setHover(null)} className="cursor-default">
                <rect x={colX[ci]} y={p.y} width={NODE_W} height={p.h} rx={2} fill={color} />
                {ci === 1 ? (
                  <text x={tx} y={p.y - 3} textAnchor={anchor} fontSize={10.5} fill="hsl(var(--foreground))">
                    {label} <tspan fill="hsl(var(--muted-foreground))">{n}</tspan>
                  </text>
                ) : (
                  <text x={tx} y={p.y + p.h / 2 + 4} textAnchor={anchor} fontSize={11.5} fill="hsl(var(--foreground))">
                    {label} <tspan fill="hsl(var(--muted-foreground))">{n}</tspan>
                  </text>
                )}
              </g>
            );
          }),
        )}
        {["Protocol", "Encryption outcome", "Negotiated TLS"].map((t, i) => (
          <text key={t} x={i === 0 ? colX[0] + NODE_W : i === 2 ? colX[2] : colX[1] + NODE_W / 2} y={H - 2} textAnchor={i === 0 ? "end" : i === 2 ? "start" : "middle"} fontSize={10} fill="hsl(var(--muted-foreground))" letterSpacing={0.5}>
            {t.toUpperCase()}
          </text>
        ))}
      </svg>
    </div>
  );
}
