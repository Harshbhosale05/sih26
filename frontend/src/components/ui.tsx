import clsx from "clsx";
import {
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  CircleHelp,
  Info,
  Loader2,
  ShieldAlert,
  X,
} from "lucide-react";
import { ButtonHTMLAttributes, ReactNode, useEffect } from "react";
import { scoreStatus } from "../lib/format";

export function Card({
  title,
  subtitle,
  action,
  children,
  className,
  padded = true,
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  padded?: boolean;
}) {
  return (
    <section className={clsx("rounded-xl border border-line bg-surface shadow-card", className)}>
      {(title || action) && (
        <header className="flex flex-wrap items-start justify-between gap-3 border-b border-line px-5 py-4">
          <div className="min-w-0">
            {title && <h2 className="text-[15px] font-semibold text-ink">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-[13px] text-ink2">{subtitle}</p>}
          </div>
          {action}
        </header>
      )}
      <div className={clsx(padded && "p-5")}>{children}</div>
    </section>
  );
}

export function PageHeader({
  title,
  eyebrow,
  description,
  actions,
}: {
  title: ReactNode;
  eyebrow?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0 max-w-3xl">
        {eyebrow && (
          <div className="mb-1 text-xs font-semibold uppercase tracking-wider text-accent">{eyebrow}</div>
        )}
        <h1 className="text-2xl font-semibold tracking-tight text-ink">{title}</h1>
        {description && <p className="mt-1.5 text-[14px] leading-relaxed text-ink2">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}

export function Stat({
  label,
  value,
  hint,
  status,
  icon,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  status?: "good" | "warn" | "serious" | "crit" | "none";
  icon?: ReactNode;
}) {
  return (
    <div className="rounded-xl border border-line bg-surface p-4 shadow-card">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[13px] text-ink2">{label}</span>
        {icon && <span className="text-muted">{icon}</span>}
      </div>
      <div className="mt-2 flex items-baseline gap-2">
        {status && status !== "none" && <StatusDot status={status} />}
        <span className="text-[26px] font-semibold leading-none tracking-tight text-ink">{value}</span>
      </div>
      {hint && <div className="mt-2 text-xs text-muted">{hint}</div>}
    </div>
  );
}

const STATUS_BG: Record<string, string> = {
  good: "bg-good",
  warn: "bg-warn",
  serious: "bg-serious",
  crit: "bg-crit",
  none: "bg-muted",
};

export function StatusDot({ status }: { status: string }) {
  return <span className={clsx("inline-block h-2.5 w-2.5 shrink-0 rounded-full", STATUS_BG[status] ?? "bg-muted")} />;
}

const SEVERITY_STYLE: Record<string, { cls: string; icon: typeof Info }> = {
  CRITICAL: { cls: "border-crit/40 bg-crit/10", icon: AlertOctagon },
  HIGH: { cls: "border-serious/50 bg-serious/10", icon: ShieldAlert },
  MEDIUM: { cls: "border-warn/60 bg-warn/10", icon: AlertTriangle },
  LOW: { cls: "border-accent/40 bg-accent/10", icon: Info },
  INFO: { cls: "border-line bg-raised", icon: Info },
};

const SEVERITY_ICON_COLOR: Record<string, string> = {
  CRITICAL: "text-crit",
  HIGH: "text-serious",
  MEDIUM: "text-warn",
  LOW: "text-accent",
  INFO: "text-muted",
};

export function SeverityBadge({ severity, compact }: { severity: string; compact?: boolean }) {
  const style = SEVERITY_STYLE[severity] ?? SEVERITY_STYLE.INFO;
  const Icon = style.icon;
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-ink",
        style.cls,
      )}
    >
      <Icon size={12} className={SEVERITY_ICON_COLOR[severity]} />
      {!compact && severity}
    </span>
  );
}

const RISK_TO_SEVERITY: Record<string, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  quantum: "INFO",
  info: "INFO",
  unknown: "INFO",
};

export function RiskBadge({ risk, label }: { risk: string; label?: string }) {
  if (risk === "ok") {
    return (
      <span className="inline-flex items-center gap-1 rounded-md border border-good/40 bg-good/10 px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-ink">
        <CheckCircle2 size={12} className="text-good" />
        {label ?? "OK"}
      </span>
    );
  }
  const sev = RISK_TO_SEVERITY[risk] ?? "INFO";
  const style = SEVERITY_STYLE[sev];
  const Icon = risk === "unknown" ? CircleHelp : style.icon;
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-ink",
        style.cls,
      )}
    >
      <Icon size={12} className={SEVERITY_ICON_COLOR[sev]} />
      {label ?? risk}
    </span>
  );
}

export function Pill({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "accent" }) {
  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium",
        tone === "accent" ? "bg-accent/10 text-accent" : "bg-raised text-ink2 ring-1 ring-inset ring-line",
      )}
    >
      {children}
    </span>
  );
}

export function Meter({ value, status }: { value: number | null; status?: string }) {
  const s = status ?? scoreStatus(value);
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-line/70">
      {value !== null && (
        <div
          className={clsx("h-full rounded-full transition-[width] duration-500", STATUS_BG[s] ?? "bg-accent")}
          style={{ width: `${Math.max(2, Math.min(100, value))}%` }}
        />
      )}
    </div>
  );
}

export function Spinner({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-16 text-ink2">
      <Loader2 className="animate-spin" size={18} />
      <span>{label}</span>
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: Error; onRetry?: () => void }) {
  return (
    <div className="rounded-xl border border-crit/30 bg-crit/5 p-5 text-[14px]">
      <div className="flex items-center gap-2 font-semibold text-ink">
        <AlertOctagon size={16} className="text-crit" /> Could not load this view
      </div>
      <p className="mt-1 text-ink2">{error.message}</p>
      {onRetry && (
        <button onClick={onRetry} className="mt-3 text-[13px] font-medium text-accent hover:underline">
          Try again
        </button>
      )}
    </div>
  );
}

export function Empty({ icon, title, children }: { icon?: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-line px-6 py-12 text-center">
      {icon && <div className="mb-3 text-muted">{icon}</div>}
      <div className="font-medium text-ink">{title}</div>
      {children && <div className="mt-1 max-w-md text-[13px] text-ink2">{children}</div>}
    </div>
  );
}

export function Button({
  children,
  variant = "secondary",
  className,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "ghost" }) {
  return (
    <button
      {...props}
      className={clsx(
        "inline-flex items-center justify-center gap-1.5 rounded-lg px-3 py-2 text-[13px] font-medium transition disabled:cursor-not-allowed disabled:opacity-50",
        variant === "primary" && "bg-accent text-white hover:brightness-110",
        variant === "secondary" && "border border-line bg-surface text-ink hover:bg-raised",
        variant === "ghost" && "text-ink2 hover:bg-raised hover:text-ink",
        className,
      )}
    >
      {children}
    </button>
  );
}

export function LinkButton({
  href,
  children,
  download,
}: {
  href: string;
  children: ReactNode;
  download?: boolean;
}) {
  return (
    <a
      href={href}
      target={download ? undefined : "_blank"}
      rel="noreferrer"
      download={download}
      className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-surface px-3 py-2 text-[13px] font-medium text-ink transition hover:bg-raised"
    >
      {children}
    </a>
  );
}

export function Drawer({
  open,
  onClose,
  title,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
    };
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/40 backdrop-blur-[1px]" onClick={onClose} />
      <aside className="relative flex h-full w-full max-w-2xl flex-col border-l border-line bg-page shadow-2xl">
        <header className="flex items-start justify-between gap-4 border-b border-line bg-surface px-5 py-4">
          <div className="min-w-0 flex-1">{title}</div>
          <button onClick={onClose} className="rounded-md p-1 text-ink2 hover:bg-raised" aria-label="Close">
            <X size={18} />
          </button>
        </header>
        <div className="flex-1 overflow-y-auto p-5">{children}</div>
      </aside>
    </div>
  );
}

export function Tabs<T extends string>({
  value,
  onChange,
  items,
}: {
  value: T;
  onChange: (v: T) => void;
  items: { value: T; label: ReactNode }[];
}) {
  return (
    <div className="inline-flex flex-wrap gap-1 rounded-lg border border-line bg-surface p-1">
      {items.map((it) => (
        <button
          key={it.value}
          onClick={() => onChange(it.value)}
          className={clsx(
            "rounded-md px-3 py-1.5 text-[13px] font-medium transition",
            value === it.value ? "bg-accent/10 text-accent" : "text-ink2 hover:text-ink",
          )}
        >
          {it.label}
        </button>
      ))}
    </div>
  );
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <code className={clsx("rounded bg-raised px-1.5 py-0.5 font-mono text-[12px] text-ink ring-1 ring-inset ring-line", className)}>{children}</code>;
}

export function Table({ children }: { children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[640px] border-collapse text-left text-[13px]">{children}</table>
    </div>
  );
}

export function Th({ children, className }: { children?: ReactNode; className?: string }) {
  return (
    <th className={clsx("border-b border-line px-4 py-2.5 text-xs font-medium uppercase tracking-wide text-muted", className)}>
      {children}
    </th>
  );
}

export function Td({ children, className }: { children?: ReactNode; className?: string }) {
  return <td className={clsx("border-b border-line/70 px-4 py-3 align-top text-ink", className)}>{children}</td>;
}

/** Chart tooltip body shared by every Recharts chart. */
export function ChartTooltip({
  active,
  label,
  rows,
}: {
  active?: boolean;
  label?: ReactNode;
  rows: { color?: string; name: string; value: ReactNode }[];
}) {
  if (!active) return null;
  return (
    <div className="min-w-[160px] rounded-lg border border-line bg-surface px-3 py-2 text-[12px] shadow-lg">
      {label !== undefined && <div className="mb-1 font-medium text-ink">{label}</div>}
      {rows.map((r) => (
        <div key={r.name} className="flex items-center justify-between gap-4 py-0.5">
          <span className="flex items-center gap-1.5 text-ink2">
            {r.color && <span className="h-2 w-2 rounded-sm" style={{ background: r.color }} />}
            {r.name}
          </span>
          <span className="tabular font-medium text-ink">{r.value}</span>
        </div>
      ))}
    </div>
  );
}
