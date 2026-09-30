import { AlertTriangle, Check, Copy, Inbox } from "lucide-react";
import { useState, type ReactNode } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { riskColor, sevColor, stateLabel, stateTone, toneColor } from "@/lib/format";
import { cn } from "@/lib/utils";

// ---------------------------------------------------------------- badges

function Pill({ color, children, className, solid }: { color: string; children: ReactNode; className?: string; solid?: boolean }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 whitespace-nowrap rounded-md border px-1.5 py-0.5 text-[11px] font-medium leading-4",
        className,
      )}
      style={
        solid
          ? { background: color, borderColor: color, color: "white" }
          : { borderColor: `color-mix(in srgb, ${color} 35%, transparent)`, background: `color-mix(in srgb, ${color} 12%, transparent)`, color }
      }
    >
      {children}
    </span>
  );
}

export function SeverityBadge({ severity, className }: { severity: string; className?: string }) {
  return (
    <Pill color={sevColor(severity)} className={cn("uppercase tracking-wide", className)}>
      {severity.toLowerCase()}
    </Pill>
  );
}

export function RiskBadge({ risk, score, className }: { risk: string | null | undefined; score?: number | null; className?: string }) {
  if (!risk) return <span className="text-xs text-muted-foreground">—</span>;
  return (
    <Pill color={riskColor(risk)} className={className}>
      <span className="size-1.5 rounded-full" style={{ background: riskColor(risk) }} />
      {risk}
      {score != null && <span className="tabular opacity-70">{Math.round(score)}</span>}
    </Pill>
  );
}

export function StateBadge({ state, className }: { state: string; className?: string }) {
  const color = toneColor(stateTone(state));
  return (
    <Pill color={color} className={className}>
      <span className="size-1.5 rounded-full" style={{ background: color }} />
      {stateLabel(state)}
    </Pill>
  );
}

export function VerdictBadge({ verdict }: { verdict: string }) {
  const color = verdict === "FAIL" ? "hsl(var(--sev-critical))" : verdict === "PASS" ? "hsl(var(--sev-ok))" : "hsl(var(--sev-info))";
  return <Pill color={color}>{verdict}</Pill>;
}

export function TierBadge({ tier }: { tier: string }) {
  const color = { P1: "hsl(var(--sev-critical))", P2: "hsl(var(--sev-high))", P3: "hsl(var(--sev-medium))", P4: "hsl(var(--sev-info))" }[tier] ?? "hsl(var(--sev-info))";
  return (
    <Pill color={color} solid className="font-semibold">
      {tier}
    </Pill>
  );
}

export function Tag({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span className={cn("inline-flex items-center rounded border bg-muted/50 px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground", className)}>
      {children}
    </span>
  );
}

// ---------------------------------------------------------------- layout helpers

export function PageHeader({ title, description, actions, eyebrow }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; eyebrow?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0 space-y-1">
        {eyebrow && <div className="text-xs font-medium uppercase tracking-wider text-muted-foreground">{eyebrow}</div>}
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {description && <p className="max-w-3xl text-sm text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Panel({
  title,
  description,
  actions,
  children,
  className,
  contentClassName,
}: {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  contentClassName?: string;
}) {
  return (
    <Card className={cn("shadow-none", className)}>
      {(title || actions) && (
        <CardHeader className="flex flex-row items-start justify-between gap-4 space-y-0 p-4 pb-3">
          <div className="min-w-0 space-y-1">
            {title && <CardTitle className="text-sm font-semibold">{title}</CardTitle>}
            {description && <CardDescription className="text-xs">{description}</CardDescription>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </CardHeader>
      )}
      <CardContent className={cn("p-4 pt-0", !title && !actions && "pt-4", contentClassName)}>{children}</CardContent>
    </Card>
  );
}

export function Stat({
  label,
  value,
  sub,
  color,
  icon,
  className,
}: {
  label: ReactNode;
  value: ReactNode;
  sub?: ReactNode;
  color?: string;
  icon?: ReactNode;
  className?: string;
}) {
  return (
    <Card className={cn("shadow-none", className)}>
      <CardContent className="space-y-1.5 p-4">
        <div className="flex items-center justify-between text-xs font-medium text-muted-foreground">
          <span>{label}</span>
          {icon && <span className="text-muted-foreground/70">{icon}</span>}
        </div>
        <div className="tabular text-2xl font-semibold tracking-tight" style={color ? { color } : undefined}>
          {value}
        </div>
        {sub && <div className="text-xs text-muted-foreground">{sub}</div>}
      </CardContent>
    </Card>
  );
}

export function KeyValue({ rows, className }: { rows: [ReactNode, ReactNode][]; className?: string }) {
  return (
    <dl className={cn("grid grid-cols-[minmax(110px,auto)_1fr] gap-x-4 gap-y-2 text-sm", className)}>
      {rows.map(([k, v], i) => (
        <div key={i} className="contents">
          <dt className="text-muted-foreground">{k}</dt>
          <dd className="min-w-0 break-words">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function CopyButton({ text, className, label }: { text: string; className?: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          type="button"
          variant="ghost"
          size={label ? "sm" : "icon"}
          className={cn(label ? "h-7 gap-1.5 px-2 text-xs" : "size-7", className)}
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
      <TooltipContent>{done ? "Copied" : "Copy"}</TooltipContent>
    </Tooltip>
  );
}

export function CodeLine({ children, copy = true }: { children: string; copy?: boolean }) {
  return (
    <div className="group flex items-start gap-2 rounded-md border bg-muted/40 px-3 py-2 font-mono text-xs">
      <code className="min-w-0 flex-1 whitespace-pre-wrap break-all">{children}</code>
      {copy && <CopyButton text={children} className="-my-1 -mr-1.5 opacity-60 group-hover:opacity-100" />}
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

export function Empty({ title, children, icon }: { title: string; children?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed px-6 py-10 text-center">
      <div className="text-muted-foreground">{icon ?? <Inbox className="size-6" />}</div>
      <div className="text-sm font-medium">{title}</div>
      {children && <div className="max-w-md text-sm text-muted-foreground">{children}</div>}
    </div>
  );
}

export function Meter({ value, color, className }: { value: number | null | undefined; color?: string; className?: string }) {
  return (
    <div className={cn("h-1.5 w-full overflow-hidden rounded-full bg-muted", className)}>
      <div
        className="h-full rounded-full transition-[width] duration-700 ease-out"
        style={{ width: `${Math.max(0, Math.min(100, value ?? 0))}%`, background: color ?? "hsl(var(--primary))" }}
      />
    </div>
  );
}
