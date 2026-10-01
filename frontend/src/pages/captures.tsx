import { useQueryClient } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { CheckCircle2, CircleDashed, FileUp, Loader2, Plus, XCircle } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { toast } from "sonner";

import { CopyButton, Dot, Empty, ErrorState, Loading, PageHeader } from "@/components/common";
import { DataTable, SortHeader, multiFilter } from "@/components/data-table";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Progress } from "@/components/ui/progress";
import { api, useAnalyze, useCaptures } from "@/lib/api";
import { fmtBytes, fmtDate, fmtDuration, fmtNum, shortHash } from "@/lib/format";
import type { CaptureDetail, CaptureSummary } from "@/lib/types";
import { cn } from "@/lib/utils";

type StageState = "pending" | "active" | "done" | "error";

interface AnalysisResult {
  total_packets: number;
  total_flows: number;
  candidate_flows: number;
  sessions: number;
  by_protocol: Record<string, number>;
  findings: number;
  by_severity: Record<string, number>;
  cleartext_credential_sessions: number;
}

const STAGES = [
  { key: "upload", label: "Upload and hash evidence" },
  { key: "manifest", label: "Validate capture and build evidence manifest" },
  { key: "reconstruct", label: "Reassemble TCP streams and reconstruct sessions" },
  { key: "detect", label: "Analyse TLS and certificates, score and classify" },
];

interface Pipeline {
  file: string;
  upload: number;
  stages: { key: string; label: string; state: StageState; detail?: string }[];
  error?: string;
}

function StageIcon({ state }: { state: StageState }) {
  if (state === "done") return <CheckCircle2 className="size-4 text-sev-ok" />;
  if (state === "active") return <Loader2 className="size-4 animate-spin text-foreground" />;
  if (state === "error") return <XCircle className="size-4 text-sev-critical" />;
  return <CircleDashed className="size-4 text-muted-foreground/50" />;
}

function UploadDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const input = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);
  const [pipe, setPipe] = useState<Pipeline | null>(null);
  const busy = !!pipe && !pipe.error && pipe.stages.some((s) => s.state !== "done");

  useEffect(() => {
    if (!open && !busy) setPipe(null);
  }, [open, busy]);

  const set = (key: string, state: StageState, detail?: string) =>
    setPipe((p) => (p ? { ...p, stages: p.stages.map((s) => (s.key === key ? { ...s, state, detail: detail ?? s.detail } : s)) } : p));

  const run = useCallback(
    async (file: File) => {
      setPipe({ file: file.name, upload: 0, stages: STAGES.map((s, i) => ({ ...s, state: i === 0 ? "active" : "pending" })) });
      try {
        const m = await api.upload<CaptureDetail>("/api/captures", file, (pct) => setPipe((p) => (p ? { ...p, upload: pct } : p)));
        set("upload", "done", `${fmtBytes(m.size_bytes)} · SHA-256 ${shortHash(m.sha256, 16)}`);
        if (m.status === "failed") throw new Error(m.error_message ?? "Evidence validation failed");
        set("manifest", "done", `${m.ref} · ${fmtNum(m.packet_count)} packets · ${fmtDuration(m.duration_seconds)}`);
        set("reconstruct", "active");
        const r = await api.post<AnalysisResult>(`/api/captures/${m.capture_id}/analyze`);
        set("reconstruct", "done", `${r.total_flows} TCP flows · ${r.sessions} sessions (${Object.entries(r.by_protocol).map(([k, v]) => `${k} ${v}`).join(", ") || "none"})`);
        set("detect", "done", `${r.findings} findings${r.by_severity.CRITICAL ? ` · ${r.by_severity.CRITICAL} critical` : ""}`);
        qc.invalidateQueries();
        toast.success(`${m.ref} analysed`, { description: `${r.sessions} sessions · ${r.findings} findings` });
        setTimeout(() => {
          onOpenChange(false);
          navigate(`/c/${m.capture_id}`);
        }, 700);
      } catch (e) {
        const message = e instanceof Error ? e.message : String(e);
        setPipe((p) => (p ? { ...p, error: message, stages: p.stages.map((s) => (s.state === "active" ? { ...s, state: "error" } : s)) } : p));
      }
    },
    [navigate, onOpenChange, qc],
  );

  return (
    <Dialog open={open} onOpenChange={(o) => !busy && onOpenChange(o)}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>New analysis</DialogTitle>
          <DialogDescription>Upload a packet capture containing SMTP, IMAP or POP3 traffic.</DialogDescription>
        </DialogHeader>
        {!pipe ? (
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setOver(true);
            }}
            onDragLeave={() => setOver(false)}
            onDrop={(e) => {
              e.preventDefault();
              setOver(false);
              const f = e.dataTransfer.files?.[0];
              if (f) run(f);
            }}
            onClick={() => input.current?.click()}
            className={cn(
              "flex cursor-pointer flex-col items-center justify-center gap-3 rounded-lg border border-dashed px-6 py-10 text-center transition-colors",
              over ? "border-foreground/40 bg-muted/60" : "hover:bg-muted/40",
            )}
          >
            <FileUp className="size-6 text-muted-foreground" />
            <div>
              <div className="text-sm font-medium">Drop a capture file or click to browse</div>
              <div className="mt-1 text-xs text-muted-foreground">.pcap, .pcapng or gzip · up to 2 GB</div>
            </div>
            <input
              ref={input}
              type="file"
              accept=".pcap,.pcapng,.cap,.gz"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) run(f);
                e.target.value = "";
              }}
            />
          </div>
        ) : (
          <div className="space-y-4">
            <div className="truncate font-mono text-xs text-muted-foreground">{pipe.file}</div>
            <ol className="space-y-3">
              {pipe.stages.map((s) => (
                <li key={s.key} className="flex gap-3">
                  <StageIcon state={s.state} />
                  <div className="min-w-0 flex-1">
                    <div className={cn("text-sm", s.state === "pending" && "text-muted-foreground")}>{s.label}</div>
                    {s.key === "upload" && s.state === "active" && <Progress value={pipe.upload} className="mt-2 h-1" />}
                    {s.detail && <div className="mt-0.5 break-words font-mono text-[11.5px] text-muted-foreground">{s.detail}</div>}
                  </div>
                </li>
              ))}
            </ol>
            {pipe.error && (
              <div className="flex items-center justify-between gap-3 rounded-md border border-destructive/40 bg-destructive/5 p-2.5 text-xs text-destructive">
                {pipe.error}
                <Button size="sm" variant="outline" className="h-7" onClick={() => setPipe(null)}>
                  Try again
                </Button>
              </div>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

const STATUS_COLOR: Record<string, string> = {
  complete: "hsl(var(--sev-ok))",
  failed: "hsl(var(--sev-critical))",
  analyzing: "hsl(var(--sev-medium))",
  validated: "hsl(var(--sev-info))",
  uploaded: "hsl(var(--sev-info))",
};

const columns: ColumnDef<CaptureSummary, unknown>[] = [
  { accessorKey: "ref", header: ({ column }) => <SortHeader column={column} title="Ref" />, cell: ({ row }) => <span className="font-mono text-xs">{row.original.ref}</span>, size: 90 },
  {
    accessorKey: "original_filename",
    header: ({ column }) => <SortHeader column={column} title="File" />,
    cell: ({ row }) => <span className="font-medium">{row.original.original_filename}</span>,
  },
  {
    accessorKey: "packet_count",
    header: ({ column }) => <SortHeader column={column} title="Packets" />,
    cell: ({ row }) => <span className="tabular">{fmtNum(row.original.packet_count)}</span>,
    size: 100,
  },
  {
    accessorKey: "size_bytes",
    header: ({ column }) => <SortHeader column={column} title="Size" />,
    cell: ({ row }) => <span className="tabular text-muted-foreground">{fmtBytes(row.original.size_bytes)}</span>,
    size: 90,
  },
  {
    accessorKey: "first_packet_at",
    header: ({ column }) => <SortHeader column={column} title="Traffic captured" />,
    cell: ({ row }) => <span className="text-muted-foreground">{fmtDate(row.original.first_packet_at)}</span>,
    size: 200,
  },
  {
    accessorKey: "sha256",
    header: "SHA-256",
    cell: ({ row }) => (
      <span className="inline-flex items-center gap-0.5 font-mono text-xs text-muted-foreground">
        {shortHash(row.original.sha256, 12)}
        <CopyButton text={row.original.sha256} className="size-6" />
      </span>
    ),
    enableSorting: false,
    size: 170,
  },
  {
    accessorKey: "status",
    header: "Status",
    filterFn: multiFilter,
    cell: ({ row }) => (
      <span className="inline-flex items-center gap-1.5 text-xs">
        <Dot color={STATUS_COLOR[row.original.status] ?? STATUS_COLOR.uploaded} className="size-1.5" />
        {row.original.status === "complete" ? "Analysed" : row.original.status.charAt(0).toUpperCase() + row.original.status.slice(1)}
      </span>
    ),
    size: 110,
  },
];

export function CapturesPage() {
  const { data, isLoading, error } = useCaptures();
  const navigate = useNavigate();
  const analyze = useAnalyze();
  const [params, setParams] = useSearchParams();
  const [open, setOpen] = useState(params.get("upload") === "1");

  useEffect(() => {
    if (params.get("upload") === "1") {
      setOpen(true);
      setParams({}, { replace: true });
    }
  }, [params, setParams]);

  return (
    <>
      <PageHeader
        title="Captures"
        description="Packet captures submitted for passive analysis. Evidence is identified by its SHA-256 digest."
        actions={
          <Button size="sm" onClick={() => setOpen(true)}>
            <Plus className="size-3.5" />
            New analysis
          </Button>
        }
      />
      {isLoading ? (
        <Loading rows={2} />
      ) : error ? (
        <ErrorState error={error} />
      ) : !data?.items.length ? (
        <div className="rounded-lg border bg-card">
          <Empty title="No captures yet" icon={<FileUp className="size-6" />}>
            <Button size="sm" className="mt-2" onClick={() => setOpen(true)}>
              Upload your first capture
            </Button>
          </Empty>
        </div>
      ) : (
        <DataTable
          columns={columns}
          data={data.items}
          searchPlaceholder="Search captures"
          facets={[{ column: "status", title: "Status" }]}
          initialSorting={[{ id: "ref", desc: true }]}
          onRowClick={(c) => {
            if (c.status === "complete") return navigate(`/c/${c.capture_id}`);
            toast.promise(analyze.mutateAsync(c.capture_id), {
              loading: `Analysing ${c.ref}…`,
              success: () => {
                navigate(`/c/${c.capture_id}`);
                return `${c.ref} analysed`;
              },
              error: (e) => `Analysis failed: ${e}`,
            });
          }}
        />
      )}
      <UploadDialog open={open} onOpenChange={setOpen} />
    </>
  );
}
