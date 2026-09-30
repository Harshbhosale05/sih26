import { motion } from "framer-motion";
import { useMemo } from "react";

import type { ProtocolEvent, StateTransition } from "@/lib/types";
import { cn } from "@/lib/utils";

/**
 * Message-sequence ("ladder") diagram of one reconstructed session.
 *
 * Two lifelines, one arrow per protocol event, each labelled with the frame that
 * carried it. Background bands show the encryption phase the session was in at
 * that moment — plaintext, TLS handshake, encrypted — so a STARTTLS upgrade, a
 * refused upgrade or a credential sent in the clear is visible at a glance.
 */

type Phase = "plaintext" | "handshake" | "encrypted";

const PHASE_STYLE: Record<Phase, { fill: string; label: string; ink: string }> = {
  plaintext: { fill: "hsl(var(--sev-medium) / 0.07)", ink: "hsl(var(--sev-medium))", label: "PLAINTEXT" },
  handshake: { fill: "hsl(var(--primary) / 0.07)", ink: "hsl(var(--primary))", label: "TLS HANDSHAKE" },
  encrypted: { fill: "hsl(var(--sev-ok) / 0.07)", ink: "hsl(var(--sev-ok))", label: "ENCRYPTED" },
};

interface Row {
  frame: number;
  t: number;
  dir: "c2s" | "s2c" | "none";
  text: string;
  sub?: string;
  kind: string;
  tone: "normal" | "danger" | "warn" | "tls" | "muted" | "ok";
  phase: Phase;
}

function describe(e: ProtocolEvent, tls?: { version?: string | null; cipher?: string | null; offered?: string[] }): Pick<Row, "text" | "sub" | "tone"> {
  const m = (e.metadata ?? {}) as Record<string, unknown>;
  switch (e.kind) {
    case "tls_client_hello":
      return { text: "TLS ClientHello", sub: tls?.offered?.length ? `offers ${tls.offered.join(", ")}` : undefined, tone: "tls" };
    case "tls_server_hello":
      return { text: "TLS ServerHello", sub: [tls?.version, tls?.cipher?.replace(/^TLS_/, "")].filter(Boolean).join(" · ") || undefined, tone: "tls" };
    case "tls_application_data":
      return { text: "Encrypted application data", tone: "ok" };
    case "auth_credential":
      return {
        text: `${String(m.mechanism ?? "AUTH")} ${String(m.field ?? "credential")} in cleartext`,
        sub: `${m.username_redacted ? `${m.username_redacted} · ` : ""}${m.credential_length ?? "?"} chars · sha256 ${m.credential_sha256_prefix ?? ""}… · not stored`,
        tone: "danger",
      };
    case "auth_requested":
      return { text: e.detail, sub: "authentication requested", tone: "warn" };
    case "upgrade_advertised_mangled":
      return { text: e.detail, sub: `capability token altered in transit (expected STARTTLS)`, tone: "danger" };
    case "upgrade_rejected":
      return { text: e.detail, sub: "upgrade refused", tone: "danger" };
    case "upgrade_advertised":
      return { text: e.detail, sub: "TLS upgrade offered", tone: "tls" };
    case "upgrade_requested":
      return { text: e.detail, sub: "client requests TLS", tone: "tls" };
    case "upgrade_accepted":
      return { text: e.detail, sub: "server accepts upgrade", tone: "tls" };
    case "mail_transaction":
    case "mailbox_access":
      return { text: e.detail, sub: "message / mailbox data", tone: "normal" };
    default:
      return { text: e.detail || e.kind, tone: "normal" };
  }
}

const TONE: Record<Row["tone"], string> = {
  normal: "hsl(var(--foreground) / 0.75)",
  muted: "hsl(var(--muted-foreground))",
  tls: "hsl(var(--primary))",
  ok: "hsl(var(--sev-ok))",
  warn: "hsl(var(--sev-medium))",
  danger: "hsl(var(--sev-critical))",
};

export function Ladder({
  events,
  transitions,
  client,
  server,
  firstFrame,
  lastFrame,
  implicit,
  highlight = [],
  tls,
  collapseEncrypted = true,
  className,
}: {
  events: ProtocolEvent[];
  transitions: StateTransition[];
  client: string;
  server: string;
  firstFrame: number;
  lastFrame: number;
  implicit?: boolean;
  highlight?: number[];
  tls?: { version?: string | null; cipher?: string | null; offered?: string[] };
  collapseEncrypted?: boolean;
  className?: string;
}) {
  const rows = useMemo<Row[]>(() => {
    const negotiationFrame =
      transitions.find((t) => t.to === "TLS_NEGOTIATION")?.frame ??
      (implicit ? firstFrame : undefined);
    const establishedFrame = transitions.find((t) => t.to === "TLS_ESTABLISHED" || t.to === "IMPLICIT_TLS")?.frame;

    const phaseOf = (frame: number, kind: string): Phase => {
      if (kind === "tls_application_data") return "encrypted";
      if (establishedFrame != null && frame >= establishedFrame) return "encrypted";
      if (negotiationFrame != null && frame >= negotiationFrame) return "handshake";
      if (kind.startsWith("tls_")) return "handshake";
      return "plaintext";
    };

    const sorted = [...events].sort((a, b) => a.frame - b.frame || a.timestamp - b.timestamp);
    const t0 = sorted[0]?.timestamp ?? 0;
    const out: Row[] = [
      { frame: firstFrame, t: t0, dir: "none", text: "TCP connection opened", kind: "tcp_open", tone: "muted", phase: implicit ? "handshake" : "plaintext" },
    ];
    let appData = 0;
    for (const e of sorted) {
      if (e.kind === "tls_application_data" && collapseEncrypted) {
        appData++;
        if (appData > 2) continue;
      }
      out.push({
        frame: e.frame,
        t: e.timestamp,
        dir: e.direction === "s2c" ? "s2c" : "c2s",
        kind: e.kind,
        phase: phaseOf(e.frame, e.kind),
        ...describe(e, tls),
      });
    }
    if (appData > 2) {
      const last = out[out.length - 1];
      out.push({ frame: last.frame, t: last.t, dir: "none", text: `… ${appData - 2} more encrypted record(s) — contents unreadable, as intended`, kind: "collapsed", tone: "muted", phase: "encrypted" });
    }
    const end = out[out.length - 1];
    out.push({ frame: lastFrame, t: end.t, dir: "none", text: "Connection closed", kind: "tcp_close", tone: "muted", phase: end.phase });
    return out.map((r) => ({ ...r, t: r.t - t0 }));
  }, [events, transitions, firstFrame, lastFrame, implicit, tls, collapseEncrypted]);

  const hl = new Set(highlight);
  const W = 860;
  const ROW = 40;
  const TOP = 56;
  const H = TOP + rows.length * ROW + 16;
  const xc = 230;
  const xs = 700;
  const mid = (xc + xs) / 2;

  // Phase bands: contiguous runs of the same phase.
  const bands: { phase: Phase; from: number; to: number }[] = [];
  rows.forEach((r, i) => {
    const last = bands[bands.length - 1];
    if (last && last.phase === r.phase) last.to = i;
    else bands.push({ phase: r.phase, from: i, to: i });
  });

  return (
    <div className={cn("w-full overflow-x-auto", className)}>
      <svg viewBox={`0 0 ${W} ${H}`} className="min-w-[720px]" role="img" aria-label="Session message sequence">
        <defs>
          {Object.entries(TONE).map(([k, c]) => (
            <marker key={k} id={`arrow-${k}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill={c} />
            </marker>
          ))}
        </defs>

        {bands.map((b, i) => (
          <g key={i}>
            <rect x={150} y={TOP + b.from * ROW - 6} width={W - 150} height={(b.to - b.from + 1) * ROW} fill={PHASE_STYLE[b.phase].fill} />
            <text
              x={W - 8}
              y={TOP + b.from * ROW + 8}
              textAnchor="end"
              fontSize={9.5}
              fontWeight={600}
              letterSpacing={1}
              fill={PHASE_STYLE[b.phase].ink}
            >
              {PHASE_STYLE[b.phase].label}
            </text>
          </g>
        ))}

        {/* lifelines */}
        {[{ x: xc, label: "Client", sub: client }, { x: xs, label: "Server", sub: server }].map((l) => (
          <g key={l.label}>
            <rect x={l.x - 78} y={6} width={156} height={36} rx={7} fill="hsl(var(--card))" stroke="hsl(var(--border))" />
            <text x={l.x} y={21} textAnchor="middle" fontSize={11} fontWeight={600} fill="hsl(var(--foreground))">
              {l.label}
            </text>
            <text x={l.x} y={35} textAnchor="middle" fontSize={10} fill="hsl(var(--muted-foreground))" fontFamily="JetBrains Mono Variable, monospace">
              {l.sub}
            </text>
            <line x1={l.x} x2={l.x} y1={42} y2={H - 8} stroke="hsl(var(--border))" strokeWidth={1.5} strokeDasharray="3 4" />
          </g>
        ))}

        {rows.map((r, i) => {
          const y = TOP + i * ROW + 14;
          const color = TONE[r.tone];
          const isHl = hl.has(r.frame) && r.kind !== "tcp_open" && r.kind !== "tcp_close";
          const from = r.dir === "s2c" ? xs : xc;
          const to = r.dir === "s2c" ? xc : xs;
          return (
            <motion.g key={`${r.frame}-${i}`} initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: Math.min(i * 0.025, 0.8) }}>
              {isHl && <rect x={150} y={y - 20} width={W - 150} height={ROW - 2} fill="hsl(var(--sev-critical) / 0.08)" stroke="hsl(var(--sev-critical) / 0.5)" strokeDasharray="3 3" rx={4} />}
              <text x={10} y={y + 1} fontSize={10.5} fontFamily="JetBrains Mono Variable, monospace" fill={isHl ? "hsl(var(--sev-critical))" : "hsl(var(--muted-foreground))"} fontWeight={isHl ? 700 : 400}>
                #{r.frame}
              </text>
              <text x={62} y={y + 1} fontSize={10} fontFamily="JetBrains Mono Variable, monospace" fill="hsl(var(--muted-foreground) / 0.8)">
                +{(r.t * 1000).toFixed(1)}ms
              </text>
              {isHl && (
                <text x={10} y={y + 13} fontSize={8.5} fontWeight={700} letterSpacing={0.6} fill="hsl(var(--sev-critical))">
                  EVIDENCE
                </text>
              )}
              {r.dir === "none" ? (
                <text x={mid} y={y + 2} textAnchor="middle" fontSize={10.5} fill={color} fontStyle="italic">
                  {r.text}
                </text>
              ) : (
                <>
                  <line x1={from} x2={to + (r.dir === "s2c" ? 3 : -3)} y1={y + 4} y2={y + 4} stroke={color} strokeWidth={r.tone === "danger" ? 2 : 1.4} markerEnd={`url(#arrow-${r.tone})`} />
                  <text x={mid} y={y - 1} textAnchor="middle" fontSize={11.5} fontFamily="JetBrains Mono Variable, monospace" fill={color} fontWeight={r.tone === "danger" ? 700 : 500}>
                    {r.text.length > 58 ? `${r.text.slice(0, 56)}…` : r.text}
                  </text>
                  {r.sub && (
                    <text x={mid} y={y + 17} textAnchor="middle" fontSize={9.5} fill="hsl(var(--muted-foreground))">
                      {r.sub.length > 80 ? `${r.sub.slice(0, 78)}…` : r.sub}
                    </text>
                  )}
                </>
              )}
            </motion.g>
          );
        })}
      </svg>
    </div>
  );
}
