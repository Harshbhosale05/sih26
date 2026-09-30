import { useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { CheckCircle2, CircleDashed, FileUp, Loader2, RefreshCw, XCircle } from "lucide-react";
import { useCallback, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";

import { CopyButton, Empty, ErrorState, Loading, PageHeader, Panel } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, useAnalyze, useCaptures } from "@/lib/api";
import { fmtBytes, fmtDate, fmtDuration, fmtNum, shortHash } from "@/lib/format";
import type { CaptureDetail } from "@/lib/types";
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

interface Pipeline {
  file: string;
  upload: number;
  stages: { key: string; label: string; state: StageState; detail?: string }[];
  captureId?: string;
  error?: string;
}

const STAGES = [
  { key: "upload", label: "Upload & hash evidence" },
  { key: "manifest", label: "Validate container, build evidence manifest" },
  { key: "reconstruct", label: "Index flows, reassemble TCP, reconstruct sessions" },
  { key: "detect", label: "TLS / X.509 analysis, rules, risk model, posture" },
];

function StageIcon({ state }: { state: StageState }) {
  if (state === "done") return <CheckCircle2 className="size-4 text-sev-ok" />;
  if (state === "active") return <Loader2 className="size-4 animate-spin text-primary" />;
  if (state === "error") return <XCircle className="size-4 text-sev-critical" />;
  return <CircleDashed className="size-4 text-muted-foreground/60" />;
}

function Dropzone({ onFile, busy }: { onFile: (f: File) => void; busy: boolean }) {
  const [over, setOver] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  return (
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
        if (f && !busy) onFile(f);
      }}
      onClick={() => !busy && input.current?.click()}
      className={cn(
        "flex cursor-pointer flex-col items-center justify-center gap-3 rounded-lg border-2 border-dashed px-6 py-10 text-center transition-colors",
        over ? "border-primary bg-primary/5" : "border-border hover:border-muted-foreground/40 hover:bg-muted/30",
        busy && "pointer-events-none opacity-60",
      )}
    >
      <div className="grid size-11 place-items-center rounded-full bg-muted">
        <FileUp className="size-5 text-muted-foreground" />
      </div>
      <div>
        <div className="text-sm font-medium">Drop a packet capture here, or click to browse</div>
        <div className="mt-1 text-xs text-muted-foreground">.pcap · .pcapng · gzip-compressed · up to 2 GB. The file is hashed on arrival and never modified.</div>
      </div>
      <input
        ref={input}
        type="file"
        accept=".pcap,.pcapng,.cap,.gz"
        className="hidden"
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) onFile(f);
          e.target.value = "";
        }}
      />
    </div>
  );
}

export function CapturesPage() {
  const { data, isLoading, error } = useCaptures();
  const analyze = useAnalyze();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [pipe, setPipe] = useState<Pipeline | null>(null);

  const set = (key: string, state: StageState, detail?: string) =>
    setPipe((p) => (p ? { ...p, stages: p.stages.map((s) => (s.key === key ? { ...s, state, detail: detail ?? s.detail } : s)) } : p));

  const run = useCallback(
    async (file: File) => {
      setPipe({ file: file.name, upload: 0, stages: STAGES.map((s, i) => ({ ...s, state: i === 0 ? "active" : "pending" })) });
      try {
        const manifest = await api.upload<CaptureDetail>("/api/captures", file, (pct) => setPipe((p) => (p ? { ...p, upload: pct } : p)));
        set("upload", "done", `${fmtBytes(manifest.size_bytes)} · sha256 ${shortHash(manifest.sha256, 16)}`);
        if (manifest.status === "failed") throw new Error(manifest.error_message ?? "Evidence validation failed");
        set(
          "manifest",
          "done",
          `${manifest.ref} · ${manifest.container_format ?? "capture"} · ${fmtNum(manifest.packet_count)} packets · ${fmtDuration(manifest.duration_seconds)}${manifest.snaplen_truncated ? " · snaplen-truncated" : ""}`,
        );
        setPipe((p) => (p ? { ...p, captureId: manifest.capture_id } : p));
        set("reconstruct", "active");
        const result = await api.post<AnalysisResult>(`/api/captures/${manifest.capture_id}/analyze`);
        set(
          "reconstruct",
          "done",
          `${fmtNum(result.total_packets)} packets · ${result.total_flows} TCP flows · ${result.candidate_flows} email flows · ${result.sessions} sessions (${Object.entries(result.by_protocol).map(([k, v]) => `${k} ${v}`).join(", ") || "none"})`,
        );
        set(
          "detect",
          "done",
          `${result.findings} findings${result.by_severity.CRITICAL ? ` · ${result.by_severity.CRITICAL} critical` : ""}${result.cleartext_credential_sessions ? ` · ${result.cleartext_credential_sessions} session(s) exposed credentials` : ""}`,
        );
        qc.invalidateQueries();
        toast.success(`${manifest.ref} analysed`, { description: `${result.sessions} sessions, ${result.findings} findings` });
        setTimeout(() => navigate(`/c/${manifest.capture_id}`), 900);
      } catch (e) {
        const message = e instanceof Error ? e.message : String(e);
        setPipe((p) =>
          p ? { ...p, error: message, stages: p.stages.map((s) => (s.state === "active" ? { ...s, state: "error" } : s)) } : p,
        );
        toast.error("Analysis failed", { description: message });
      }
    },
    [navigate, qc],
  );

  const busy = !!pipe && !pipe.error && pipe.stages.some((s) => s.state !== "done");

  return (
    <div className="space-y-6">
      <PageHeader
        title="Evidence"
        description="Upload a packet capture of SMTP, IMAP or POP3 traffic. SecureMailScope reconstructs every email session, analyses the TLS negotiation and certificates, and scores the cryptographic posture — passively, without contacting any server."
      />

      <div className="grid gap-4 lg:grid-cols-[1.1fr_1fr]">
        <Panel title="New assessment">
          <Dropzone onFile={run} busy={busy} />
        </Panel>
        <Panel title="Analysis pipeline" description={pipe ? pipe.file : "Each stage reports what it actually produced."}>
          <ol className="space-y-3">
            {(pipe?.stages ?? STAGES.map((s) => ({ ...s, state: "pending" as StageState, detail: undefined }))).map((s, i) => (
              <motion.li key={s.key} initial={false} animate={{ opacity: s.state === "pending" ? 0.55 : 1 }} className="flex gap-3">
                <div className="flex flex-col items-center">
                  <StageIcon state={s.state} />
                  {i < STAGES.length - 1 && <div className="mt-1 w-px flex-1 bg-border" />}
                </div>
                <div className="min-w-0 flex-1 pb-1">
                  <div className="text-sm font-medium">{s.label}</div>
                  {s.key === "upload" && pipe && s.state === "active" && <Progress value={pipe.upload} className="mt-2 h-1.5" />}
                  {s.detail && <div className="mt-0.5 break-words font-mono text-[11.5px] text-muted-foreground">{s.detail}</div>}
                </div>
              </motion.li>
            ))}
          </ol>
          {pipe?.error && <div className="mt-3 rounded-md border border-destructive/40 bg-destructive/5 p-2.5 text-xs text-destructive">{pipe.error}</div>}
        </Panel>
      </div>

      <Panel title="Captures" description="Evidence is identified by SHA-256: uploading the same file again reopens the existing assessment.">
        {isLoading ? (
          <Loading rows={2} />
        ) : error ? (
          <ErrorState error={error} />
        ) : !data?.items.length ? (
          <Empty title="No captures yet">Upload a capture above to start an assessment.</Empty>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[90px]">Ref</TableHead>
                <TableHead>File</TableHead>
                <TableHead className="text-right">Packets</TableHead>
                <TableHead className="text-right">Size</TableHead>
                <TableHead>Traffic observed</TableHead>
                <TableHead>SHA-256</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="w-[110px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.items.map((c) => (
                <TableRow
                  key={c.capture_id}
                  className={cn(c.status === "complete" && "cursor-pointer")}
                  onClick={() => c.status === "complete" && navigate(`/c/${c.capture_id}`)}
                >
                  <TableCell className="font-mono text-xs">{c.ref}</TableCell>
                  <TableCell className="max-w-[320px] truncate font-medium">{c.original_filename}</TableCell>
                  <TableCell className="tabular text-right">{fmtNum(c.packet_count)}</TableCell>
                  <TableCell className="tabular text-right">{fmtBytes(c.size_bytes)}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{fmtDate(c.first_packet_at)}</TableCell>
                  <TableCell>
                    <span className="flex items-center gap-1 font-mono text-xs text-muted-foreground">
                      {shortHash(c.sha256, 10)}
                      <CopyButton text={c.sha256} className="size-6" />
                    </span>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className={cn("font-normal", c.status === "complete" && "border-sev-ok/40 text-sev-ok", c.status === "failed" && "border-sev-critical/40 text-sev-critical")}>
                      {c.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    {c.status !== "complete" ? (
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-7 text-xs"
                        disabled={analyze.isPending}
                        onClick={(e) => {
                          e.stopPropagation();
                          analyze.mutate(c.capture_id, {
                            onSuccess: () => navigate(`/c/${c.capture_id}`),
                            onError: (err) => toast.error("Analysis failed", { description: String(err) }),
                          });
                        }}
                      >
                        {analyze.isPending && analyze.variables === c.capture_id ? <Loader2 className="size-3.5 animate-spin" /> : <RefreshCw className="size-3.5" />}
                        Analyse
                      </Button>
                    ) : (
                      <Button size="sm" variant="ghost" className="h-7 text-xs">
                        Open
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Panel>
    </div>
  );
}
