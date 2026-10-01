import { AlertTriangle, Check, Copy, Info } from "lucide-react";
import { useState, type ReactNode } from "react";

import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { riskColor, sevColor, stateLabel, stateTone, toneColor } from "@/lib/format";
import { cn } from "@/lib/utils";

// ---------------------------------------------------------------- status labels
// Neutral outline with a coloured dot: colour carries the signal, not the fill.

export function Dot({ color, className }: { color: string; className?: string }) {
  return <span className={cn("inline-block size-2 shrink-0 rounded-full", className)} style={{ background: color }} />;
}

function Label({ color, children, className, mono }: { color: string; children: ReactNode; className?: string; mono?: boolean }) {
  return (
    <span
      className={cn(
        "inline-flex h-6 items-center gap-1.5 whitespace-nowrap rounded-md border bg-background px-2 text-xs font-medium text-foreground/90",
        mono && "font-mono",
        className,
      )}
    >
      <Dot color={color} className="size-1.5" />
      {children}
    </span>
  );
}

const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1).toLowerCase();

export function SeverityBadge({ severity, className }: { severity: string; className?: string }) {
  return (
    <Label color={sevColor(severity)} className={className}>
      {cap(severity)}
    </Label>
  );
}

export function RiskBadge({ risk, score, className }: { risk: string | null | undefined; score?: number | null; className?: string }) {
  if (!risk) return <span className="text-xs text-muted-foreground">—</span>;
  return (
    <Label color={riskColor(risk)} className={className}>
      {cap(risk)}
      {score != null && <span className="tabular text-muted-foreground">{Math.round(score)}</span>}
    </Label>
  );
}

export function StateBadge({ state, className }: { state: string; className?: string }) {
  return (
    <Label color={toneColor(stateTone(state))} className={className}>
      {stateLabel(state)}
    </Label>
  );
}

export function VerdictBadge({ verdict }: { verdict: string }) {
  const color = verdict === "FAIL" ? "hsl(var(--sev-critical))" : verdict === "PASS" ? "hsl(var(--sev-ok))" : "hsl(var(--sev-info))";
  return <Label color={color}>{cap(verdict)}</Label>;
}

const TIER_COLOR: Record<string, string> = {
  P1: "hsl(var(--sev-critical))",
  P2: "hsl(var(--sev-high))",
  P3: "hsl(var(--sev-medium))",
  P4: "hsl(var(--sev-info))",
};

export function TierBadge({ tier, score }: { tier: string; score?: number }) {
  return (
    <Label color={TIER_COLOR[tier] ?? TIER_COLOR.P4} mono>
      {tier}
      {score != null && <span className="tabular text-muted-foreground">{Math.round(score)}</span>}
    </Label>
  );
}

export function Tag({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span className={cn("inline-flex items-center rounded border bg-muted/40 px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground", className)}>
      {children}
    </span>
  );
}

// ---------------------------------------------------------------- layout

export function InfoTip({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button type="button" className={cn("inline-flex text-muted-foreground/70 hover:text-foreground", className)} aria-label="More information">
          <Info className="size-3.5" />
        </button>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs text-xs leading-relaxed">{children}</TooltipContent>
    </Tooltip>
  );
}

export function PageHeader({ title, description, actions }: { title: ReactNode; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0 space-y-1">
        <h1 className="text-lg font-semibold tracking-tight">{title}</h1>
        {description && <p className="text-sm text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Panel({
  title,
  info,
  description,
  actions,
  children,
  className,
  contentClassName,
  flush,
}: {
  title?: ReactNode;
  info?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  contentClassName?: string;
  flush?: boolean;
}) {
  return (
    <section className={cn("rounded-lg border bg-card text-card-foreground", className)}>
      {(title || actions) && (
        <header className="flex min-h-11 items-center justify-between gap-3 border-b px-4 py-2">
          <div className="flex min-w-0 items-center gap-1.5">
            {title && <h2 className="truncate text-sm font-medium">{title}</h2>}
            {info && <InfoTip>{info}</InfoTip>}
            {description && <span className="ml-1 truncate text-xs text-muted-foreground">{description}</span>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={cn(!flush && "p-4", contentClassName)}>{children}</div>
    </section>
  );
}

export interface StatItem {
  label: ReactNode;
  value: ReactNode;
  sub?: ReactNode;
  info?: ReactNode;
  accent?: string;
}

/** One bordered strip of metrics separated by dividers. */
export function StatStrip({ items, className }: { items: StatItem[]; className?: string }) {
  return (
    <div className={cn("grid overflow-hidden rounded-lg border bg-card", className)} style={{ gridTemplateColumns: `repeat(${items.length}, minmax(0, 1fr))` }}>
      {items.map((s, i) => (
        <div key={i} className={cn("min-w-0 px-4 py-3", i > 0 && "border-l")}>
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            {s.accent && <Dot color={s.accent} className="size-1.5" />}
            <span className="truncate">{s.label}</span>
            {s.info && <InfoTip>{s.info}</InfoTip>}
          </div>
          <div className="tabular mt-1 truncate text-xl font-semibold tracking-tight">{s.value}</div>
          {s.sub && <div className="mt-0.5 truncate text-xs text-muted-foreground">{s.sub}</div>}
        </div>
      ))}
    </div>
  );
}

export function Stat({ label, value, sub, className }: { label: ReactNode; value: ReactNode; sub?: ReactNode; color?: string; icon?: ReactNode; className?: string }) {
  return (
    <div className={cn("rounded-lg border bg-card px-4 py-3", className)}>
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="tabular mt-1 text-xl font-semibold tracking-tight">{value}</div>
      {sub && <div className="mt-0.5 text-xs text-muted-foreground">{sub}</div>}
    </div>
  );
}

/** Vertical property list, as in an inspector panel. */
export function Properties({ rows, className }: { rows: [ReactNode, ReactNode][]; className?: string }) {
  return (
    <dl className={cn("divide-y text-sm", className)}>
      {rows.map(([k, v], i) => (
        <div key={i} className="grid grid-cols-[120px_1fr] gap-3 py-2 first:pt-0 last:pb-0">
          <dt className="text-muted-foreground">{k}</dt>
          <dd className="min-w-0 break-words">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export const KeyValue = Properties;

export function CopyButton({ text, className, label }: { text: string; className?: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          type="button"
          variant={label ? "outline" : "ghost"}
          size={label ? "sm" : "icon"}
          className={cn(label ? "h-8 gap-1.5" : "size-7 text-muted-foreground", className)}
          onClick={(e) => {
            e.stopPropagation();
            navigator.clipboard?.writeText(text).then(() => {
              setDone(true);
              setTimeout(() => setDone(false), 1200);
            });
          }}
        >
          {done ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
          {label}
        </Button>
      </TooltipTrigger>
      <TooltipContent>{done ? "Copied" : "Copy to clipboard"}</TooltipContent>
    </Tooltip>
  );
}

export function CodeLine({ children, copy = true }: { children: string; copy?: boolean }) {
  return (
    <div className="group flex items-start gap-2 rounded-md border bg-muted/40 px-3 py-2 font-mono text-xs">
      <code className="min-w-0 flex-1 whitespace-pre-wrap break-all">{children}</code>
      {copy && <CopyButton text={children} className="-my-1 -mr-1.5 size-6" />}
    </div>
  );
}

export function Meter({ value, color, className }: { value: number | null | undefined; color?: string; className?: string }) {
  return (
    <div className={cn("h-1.5 w-full overflow-hidden rounded-full bg-muted", className)}>
      <div
        className="h-full rounded-full transition-[width] duration-500 ease-out"
        style={{ width: `${Math.max(0, Math.min(100, value ?? 0))}%`, background: color ?? "hsl(var(--primary))" }}
      />
    </div>
  );
}

// ---------------------------------------------------------------- states

export function Loading({ className, rows = 3 }: { className?: string; rows?: number }) {
  return (
    <div className={cn("space-y-3", className)}>
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} className="h-24 w-full" />
      ))}
    </div>
  );
}

export function ErrorState({ error }: { error: unknown }) {
  return (
    <div className="flex items-start gap-3 rounded-lg border border-destructive/40 bg-destructive/5 p-4 text-sm">
      <AlertTriangle className="mt-0.5 size-4 shrink-0 text-destructive" />
      <div>
        <div className="font-medium">Could not load this view</div>
        <div className="text-muted-foreground">{error instanceof Error ? error.message : String(error)}</div>
      </div>
    </div>
  );
}

export function Empty({ title, children, icon, className }: { title: string; children?: ReactNode; icon?: ReactNode; className?: string }) {
  return (
    <div className={cn("flex flex-col items-center justify-center gap-2 px-6 py-10 text-center", className)}>
      {icon && <div className="text-muted-foreground">{icon}</div>}
      <div className="text-sm font-medium">{title}</div>
      {children && <div className="max-w-md text-sm text-muted-foreground">{children}</div>}
    </div>
  );
}
