export const fmtNum = (n: number | null | undefined) =>
  n === null || n === undefined ? "—" : n.toLocaleString();

export const fmtPct = (n: number | null | undefined, digits = 0) =>
  n === null || n === undefined ? "—" : `${n.toFixed(digits)}%`;

export function fmtBytes(n: number | null | undefined) {
  if (n === null || n === undefined) return "—";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 && i ? 1 : 0)} ${units[i]}`;
}

export function fmtDate(iso: string | null | undefined) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export const humanize = (s: string) =>
  s.replace(/_/g, " ").toLowerCase().replace(/^\w/, (c) => c.toUpperCase());

/** Map a 0–100 score to a status role. */
export function scoreStatus(score: number | null | undefined): "good" | "warn" | "serious" | "crit" | "none" {
  if (score === null || score === undefined) return "none";
  if (score >= 80) return "good";
  if (score >= 60) return "warn";
  if (score >= 40) return "serious";
  return "crit";
}

export const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;

export const SECURE_STATES = new Set(["TLS_ESTABLISHED", "IMPLICIT_TLS"]);
export const UNKNOWN_STATES = new Set(["UNKNOWN", "TRUNCATED"]);
