import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

import { riskColor, stateLabel, stateTone, toneColor } from "@/lib/format";
import type { Session } from "@/lib/types";

/**
 * Capture timeline: one bar per session, one lane per server, coloured by how
 * the session ended up (or by model risk). Shows when cleartext happened, not
 * just that it did — a burst of failed upgrades at one moment reads as an
 * incident, a steady trickle as a configuration problem.
 */
export function SessionTimeline({ captureId, sessions, colorBy = "state" }: { captureId: string; sessions: Session[]; colorBy?: "state" | "risk" }) {
  const navigate = useNavigate();
  const [hover, setHover] = useState<Session | null>(null);

  const { lanes, t0, span } = useMemo(() => {
    const email = sessions.filter((s) => s.protocol && s.start_time != null);
    const t0 = Math.min(...email.map((s) => s.start_time!));
    const t1 = Math.max(...email.map((s) => s.end_time ?? s.start_time!));
    const byServer = new Map<string, Session[]>();
    for (const s of email) {
      const k = `${s.server_ip}:${s.server_port}`;
      byServer.set(k, [...(byServer.get(k) ?? []), s]);
    }
    const lanes = [...byServer.entries()].sort((a, b) => a[0].localeCompare(b[0]));
    return { lanes, t0, span: Math.max(t1 - t0, 0.001) };
  }, [sessions]);

  if (!lanes.length) return <div className="text-sm text-muted-foreground">No sessions with timing information.</div>;

  const W = 1000;
  const LABEL = 150;
  const LANE = 26;
  const H = lanes.length * LANE + 30;
  const x = (t: number) => LABEL + ((t - t0) / span) * (W - LABEL - 10);
  const ticks = Array.from({ length: 6 }, (_, i) => (span * i) / 5);

  return (
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label="Session timeline">
        {ticks.map((t) => (
          <g key={t}>
            <line x1={x(t0 + t)} x2={x(t0 + t)} y1={0} y2={H - 18} stroke="hsl(var(--grid-line))" />
            <text x={x(t0 + t)} y={H - 4} fontSize={10} textAnchor="middle" fill="hsl(var(--muted-foreground))">
              {t < 1 ? `${(t * 1000).toFixed(0)}ms` : `${t.toFixed(1)}s`}
            </text>
          </g>
        ))}
        {lanes.map(([server, rows], i) => (
          <g key={server}>
            <text x={0} y={i * LANE + 17} fontSize={10.5} fontFamily="JetBrains Mono Variable, monospace" fill="hsl(var(--muted-foreground))">
              {server}
            </text>
            <line x1={LABEL} x2={W - 10} y1={i * LANE + 13} y2={i * LANE + 13} stroke="hsl(var(--grid-line))" strokeDasharray="2 4" />
            {rows.map((s) => {
              const color = colorBy === "risk" ? riskColor(s.risk_class ?? "info") : toneColor(stateTone(s.encryption_state));
              const left = x(s.start_time!);
              const width = Math.max(x(s.end_time ?? s.start_time!) - left, 5);
              return (
                <rect
                  key={s.ref}
                  x={left}
                  y={i * LANE + 5}
                  width={width}
                  height={16}
                  rx={3}
                  fill={color}
                  fillOpacity={hover?.ref === s.ref ? 1 : 0.8}
                  stroke={hover?.ref === s.ref ? "hsl(var(--foreground))" : "none"}
                  className="cursor-pointer"
                  onMouseEnter={() => setHover(s)}
                  onMouseLeave={() => setHover(null)}
                  onClick={() => navigate(`/c/${captureId}/sessions/${s.ref}`)}
                />
              );
            })}
          </g>
        ))}
      </svg>
      {hover && (
        <div className="pointer-events-none absolute right-2 top-2 rounded-md border bg-popover px-3 py-2 text-xs shadow-md">
          <div className="font-mono font-medium">
            {hover.ref} · {hover.protocol}
          </div>
          <div className="text-muted-foreground">
            {hover.client_ip} → {hover.server_ip}:{hover.server_port}
          </div>
          <div>
            {stateLabel(hover.encryption_state)}
            {hover.tls_version ? ` · ${hover.tls_version}` : ""}
            {hover.risk_class ? ` · risk ${hover.risk_class}` : ""}
          </div>
        </div>
      )}
    </div>
  );
}
