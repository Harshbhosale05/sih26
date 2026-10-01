import {
  Activity,
  BrainCircuit,
  Atom,
  ChevronDown,
  FileDown,
  FileText,
  KeyRound,
  LayoutDashboard,
  ListChecks,
  Loader2,
  Network,
  RefreshCw,
  Wrench,
} from "lucide-react";
import { NavLink, Outlet, useParams } from "react-router-dom";
import { toast } from "sonner";

import { CopyButton, Dot, ErrorState } from "@/components/common";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Skeleton } from "@/components/ui/skeleton";
import { exportUrl, useAnalyze, useCapture, useOverview } from "@/lib/api";
import { fmtBytes, fmtDate, fmtDuration, fmtNum, shortHash } from "@/lib/format";
import { cn } from "@/lib/utils";

// eslint-disable-next-line react-refresh/only-export-components
export const CAPTURE_TABS = [
  { to: "", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "analyst", label: "AI Analyst", icon: BrainCircuit },
  { to: "findings", label: "Findings", icon: ListChecks },
  { to: "sessions", label: "Sessions", icon: Network },
  { to: "crypto", label: "Cryptography", icon: KeyRound },
  { to: "pqc", label: "Post-Quantum", icon: Atom },
  { to: "starttls", label: "STARTTLS", icon: Activity },
  { to: "remediation", label: "Remediation", icon: Wrench },
  { to: "reports", label: "Report", icon: FileText },
];

function ExportMenu({ id }: { id: string }) {
  const items: [string, "report.pdf" | "report.html" | "report.json" | "cbom", string][] = [
    ["Assessment report (PDF)", "report.pdf", "Formal forensic report"],
    ["Assessment report (HTML)", "report.html", "Self-contained web page"],
    ["Findings and sessions (JSON)", "report.json", "For SIEM ingestion"],
    ["Cryptographic BOM (CycloneDX)", "cbom", "PQC migration inventory"],
  ];
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button size="sm" className="h-8">
          <FileDown className="size-3.5" />
          Export
          <ChevronDown className="size-3.5 opacity-70" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-64">
        <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">Export this assessment</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {items.map(([label, kind, sub]) => (
          <DropdownMenuItem key={kind} asChild>
            <a href={exportUrl(id, kind)} download className="flex flex-col items-start gap-0">
              <span>{label}</span>
              <span className="text-xs text-muted-foreground">{sub}</span>
            </a>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function CaptureLayout() {
  const { captureId } = useParams();
  const capture = useCapture(captureId);
  const overview = useOverview(captureId);
  const analyze = useAnalyze();
  const c = capture.data;
  const failing = overview.data
    ? Object.entries(overview.data.findings.by_severity).filter(([s]) => s !== "INFO").reduce((a, [, n]) => a + n, 0)
    : null;
  const counts: Record<string, number | null | undefined> = {
    findings: failing,
    sessions: overview.data?.sessions.total,
  };

  if (capture.error) return <ErrorState error={capture.error} />;

  return (
    <div className="flex min-h-full flex-col">
      <div className="border-b bg-background px-4 pt-4 md:px-6">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            {c ? (
              <>
                <div className="flex items-center gap-2">
                  <h1 className="truncate text-lg font-semibold tracking-tight">{c.original_filename}</h1>
                  <span className="inline-flex items-center gap-1.5 rounded-md border px-1.5 py-0.5 text-xs text-muted-foreground">
                    <Dot color={c.status === "complete" ? "hsl(var(--sev-ok))" : c.status === "failed" ? "hsl(var(--sev-critical))" : "hsl(var(--sev-medium))"} className="size-1.5" />
                    {c.status === "complete" ? "Analysed" : c.status}
                  </span>
                </div>
                <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
                  <span className="font-mono">{c.ref}</span>
                  <span>{fmtNum(c.packet_count)} packets</span>
                  <span>{fmtBytes(c.size_bytes)}</span>
                  <span>{fmtDuration(c.duration_seconds)}</span>
                  <span>Captured {fmtDate(c.first_packet_at)}</span>
                  <span className="inline-flex items-center gap-0.5 font-mono">
                    SHA-256 {shortHash(c.sha256, 12)}
                    <CopyButton text={c.sha256} className="size-6" />
                  </span>
                </div>
              </>
            ) : (
              <div className="space-y-2">
                <Skeleton className="h-6 w-64" />
                <Skeleton className="h-4 w-96" />
              </div>
            )}
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              className="h-8"
              disabled={analyze.isPending || !captureId}
              onClick={() =>
                analyze.mutate(captureId!, {
                  onSuccess: () => toast.success("Analysis re-run with the current rules and model"),
                  onError: (e) => toast.error("Analysis failed", { description: String(e) }),
                })
              }
            >
              {analyze.isPending ? <Loader2 className="size-3.5 animate-spin" /> : <RefreshCw className="size-3.5" />}
              Re-analyse
            </Button>
            {captureId && <ExportMenu id={captureId} />}
          </div>
        </div>

        <nav className="-mb-px mt-4 flex gap-1 overflow-x-auto" aria-label="Capture sections">
          {CAPTURE_TABS.map((t) => (
            <NavLink
              key={t.to}
              to={`/c/${captureId}${t.to ? `/${t.to}` : ""}`}
              end={t.end}
              className={({ isActive }) =>
                cn(
                  "inline-flex h-9 items-center gap-1.5 whitespace-nowrap border-b-2 px-2.5 text-sm transition-colors",
                  isActive ? "border-foreground font-medium text-foreground" : "border-transparent text-muted-foreground hover:text-foreground",
                )
              }
            >
              <t.icon className="size-3.5" />
              {t.label}
              {counts[t.to] != null && (
                <span className="rounded bg-muted px-1.5 font-mono text-[11px] text-muted-foreground">{counts[t.to]}</span>
              )}
            </NavLink>
          ))}
        </nav>
      </div>
      <div className="mx-auto w-full max-w-[1600px] flex-1 space-y-5 p-4 md:p-6">
        <Outlet />
      </div>
    </div>
  );
}
