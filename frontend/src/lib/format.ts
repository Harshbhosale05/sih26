import type { RiskClass, Severity } from "./types";

export const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
export const RISK_CLASSES: RiskClass[] = ["critical", "high", "medium", "low", "minimal"];

/** CSS colour for a severity, from the theme tokens. */
export const sevColor = (s: string | null | undefined) =>
  ({
    CRITICAL: "hsl(var(--sev-critical))",
    HIGH: "hsl(var(--sev-high))",
    MEDIUM: "hsl(var(--sev-medium))",
    LOW: "hsl(var(--sev-low))",
    INFO: "hsl(var(--sev-info))",
  })[(s ?? "INFO").toUpperCase()] ?? "hsl(var(--sev-info))";

export const riskColor = (r: string | null | undefined) =>
  ({
    critical: "hsl(var(--sev-critical))",
    high: "hsl(var(--sev-high))",
    medium: "hsl(var(--sev-medium))",
    low: "hsl(var(--sev-low))",
    minimal: "hsl(var(--sev-ok))",
    quantum: "hsl(var(--chart-3))",
    info: "hsl(var(--sev-info))",
    ok: "hsl(var(--sev-ok))",
  })[r ?? "info"] ?? "hsl(var(--sev-info))";

/** Score band colour: the same thresholds the report uses. */
export const scoreColor = (score: number | null | undefined) =>
  score == null
    ? "hsl(var(--muted-foreground))"
    : score >= 80
      ? "hsl(var(--sev-ok))"
      : score >= 60
        ? "hsl(var(--sev-medium))"
        : score >= 40
          ? "hsl(var(--sev-high))"
          : "hsl(var(--sev-critical))";

export const scoreLabel = (score: number | null | undefined, critical = 0) =>
  score == null
    ? "Not assessable"
    : critical
      ? "Action required"
      : score >= 80
        ? "Strong"
        : score >= 60
          ? "Moderate"
          : score >= 40
            ? "Weak"
            : "Critical";

// Encryption states -------------------------------------------------------------

export const PROTECTED_STATES = new Set(["TLS_ESTABLISHED", "IMPLICIT_TLS"]);
export const CLEARTEXT_STATES = new Set([
  "PLAINTEXT_THROUGHOUT",
  "PLAINTEXT_AFTER_FAILURE",
  "STARTTLS_ADVERTISED_NOT_USED",
  "STARTTLS_NOT_ADVERTISED",
  "STARTTLS_REJECTED",
  "STARTTLS_NEGOTIATION_FAILED",
]);

const STATE_LABELS: Record<string, string> = {
  TLS_ESTABLISHED: "STARTTLS → TLS",
  IMPLICIT_TLS: "Implicit TLS",
  STARTTLS_ADVERTISED_NOT_USED: "Offered, not used",
  STARTTLS_NOT_ADVERTISED: "Not offered",
  STARTTLS_REJECTED: "Upgrade refused",
  STARTTLS_NEGOTIATION_FAILED: "Handshake failed",
  PLAINTEXT_AFTER_FAILURE: "Cleartext after failure",
  PLAINTEXT_THROUGHOUT: "Cleartext throughout",
  TRUNCATED: "Truncated",
  UNKNOWN: "Unknown",
};

export const stateLabel = (s: string) => STATE_LABELS[s] ?? s.replace(/_/g, " ").toLowerCase();

export type Tone = "ok" | "warn" | "bad" | "critical" | "neutral";

export const stateTone = (s: string): Tone =>
  PROTECTED_STATES.has(s)
    ? "ok"
    : s === "PLAINTEXT_AFTER_FAILURE"
      ? "critical"
      : CLEARTEXT_STATES.has(s)
        ? "bad"
        : "neutral";

export const toneColor = (t: Tone) =>
  ({
    ok: "hsl(var(--sev-ok))",
    warn: "hsl(var(--sev-medium))",
    bad: "hsl(var(--sev-high))",
    critical: "hsl(var(--sev-critical))",
    neutral: "hsl(var(--sev-info))",
  })[t];

// Numbers, sizes, dates ------------------------------------------------------------

export const fmtBytes = (n: number | null | undefined) => {
  if (n == null) return "—";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
};

export const fmtNum = (n: number | null | undefined) => (n == null ? "—" : n.toLocaleString());

export const fmtPct = (n: number | null | undefined, digits = 0) => (n == null ? "—" : `${n.toFixed(digits)}%`);

export const fmtDate = (iso: string | null | undefined) =>
  iso
    ? new Date(iso).toLocaleString(undefined, {
        year: "numeric",
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      })
    : "—";

export const fmtDuration = (s: number | null | undefined) => {
  if (s == null) return "—";
  if (s < 1) return `${Math.round(s * 1000)} ms`;
  if (s < 120) return `${s.toFixed(1)} s`;
  if (s < 7200) return `${Math.round(s / 60)} min`;
  return `${(s / 3600).toFixed(1)} h`;
};

export const shortHash = (h: string | null | undefined, n = 12) => (h ? `${h.slice(0, n)}…` : "—");

export const titleCase = (s: string) => s.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

export const categoryLabel = (c: string) =>
  c.replace(/_/g, " ").replace(/^\w/, (x) => x.toUpperCase()).replace(/\btls\b/gi, "TLS").replace(/\bpqc\b/gi, "PQC")
    .replace(/\bmta sts\b/gi, "MTA-STS").replace(/\bdmarc\b/gi, "DMARC").replace(/\bstarttls\b/gi, "STARTTLS");
