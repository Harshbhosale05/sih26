import clsx from "clsx";
import { ArrowRight, CheckCircle2, FileUp, Loader2, Play, RefreshCw, UploadCloud, XCircle } from "lucide-react";
import { useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Button, Card, Empty, ErrorState, PageHeader, Spinner, Table, Td, Th } from "../components/ui";
import { api, useApi } from "../lib/api";
import { fmtBytes, fmtDate, fmtNum } from "../lib/format";
import type { CaptureList, CaptureSummary } from "../lib/types";

type Phase = { kind: "idle" } | { kind: "uploading"; pct: number; name: string } | { kind: "analyzing"; name: string } | { kind: "error"; message: string };

function StatusChip({ status }: { status: CaptureSummary["status"] }) {
  const map = {
    complete: { icon: CheckCircle2, cls: "text-good", label: "Analysed" },
    failed: { icon: XCircle, cls: "text-crit", label: "Failed" },
    analyzing: { icon: Loader2, cls: "text-accent animate-spin", label: "Analysing" },
    validated: { icon: CheckCircle2, cls: "text-muted", label: "Ready to analyse" },
    uploaded: { icon: FileUp, cls: "text-muted", label: "Uploaded" },
  }[status];
  const Icon = map.icon;
  return (
    <span className="inline-flex items-center gap-1.5 text-[13px] text-ink">
      <Icon size={14} className={map.cls} />
      {map.label}
    </span>
  );
}

export function CapturesPage() {
  const captures = useApi<CaptureList>("/api/captures?limit=200");
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  async function handle(file: File) {
    try {
      setPhase({ kind: "uploading", pct: 0, name: file.name });
      const manifest = await api.upload<{ capture_id: string; status: string }>("/api/captures", file, (pct) =>
        setPhase({ kind: "uploading", pct, name: file.name }),
      );
      if (manifest.status === "failed") throw new Error("The capture could not be validated.");
      setPhase({ kind: "analyzing", name: file.name });
      await api.post(`/api/captures/${manifest.capture_id}/analyze`);
      setPhase({ kind: "idle" });
      navigate(`/c/${manifest.capture_id}`);
    } catch (e) {
      setPhase({ kind: "error", message: (e as Error).message });
      captures.reload();
    }
  }

  async function analyse(id: string) {
    setBusy(id);
    try {
      await api.post(`/api/captures/${id}/analyze`);
      navigate(`/c/${id}`);
    } catch (e) {
      setPhase({ kind: "error", message: (e as Error).message });
      captures.reload();
    } finally {
      setBusy(null);
    }
  }

  const working = phase.kind === "uploading" || phase.kind === "analyzing";

  return (
    <>
      <PageHeader
        eyebrow="Evidence intake"
        title="Captures"
        description="Upload a PCAP or PCAPNG of SMTP, IMAP or POP3 traffic. It is hashed on arrival, analysed passively, and every finding stays traceable to its frames."
      />

      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          const file = e.dataTransfer.files[0];
          if (file && !working) handle(file);
        }}
        onClick={() => !working && input.current?.click()}
        className={clsx(
          "mb-8 flex cursor-pointer flex-col items-center justify-center rounded-2xl border-2 border-dashed px-6 py-10 text-center transition",
          dragging ? "border-accent bg-accent/5" : "border-line bg-surface hover:border-accent/50",
          working && "cursor-progress",
        )}
      >
        <input
          ref={input}
          type="file"
          accept=".pcap,.pcapng,.cap,.gz"
          className="hidden"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) handle(file);
            e.target.value = "";
          }}
        />
        {phase.kind === "uploading" ? (
          <div className="w-full max-w-sm">
            <div className="mb-2 text-[14px] font-medium text-ink">Uploading {phase.name}</div>
            <div className="h-2 overflow-hidden rounded-full bg-line">
              <div className="h-full rounded-full bg-accent transition-all" style={{ width: `${phase.pct}%` }} />
            </div>
            <div className="mt-2 text-[12px] text-muted">{phase.pct}% · hashing as it streams</div>
          </div>
        ) : phase.kind === "analyzing" ? (
          <div className="flex flex-col items-center gap-2">
            <Loader2 className="animate-spin text-accent" size={28} />
            <div className="text-[14px] font-medium text-ink">Analysing {phase.name}</div>
            <div className="text-[12px] text-muted">Reconstructing sessions, parsing handshakes, running detectors…</div>
          </div>
        ) : (
          <>
            <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-xl bg-accent/10 text-accent">
              <UploadCloud size={24} />
            </div>
            <div className="text-[15px] font-medium text-ink">Drop a capture here, or click to browse</div>
            <div className="mt-1 text-[13px] text-ink2">.pcap · .pcapng · .gz — analysed automatically after upload</div>
          </>
        )}
      </div>

      {phase.kind === "error" && (
        <div className="mb-6">
          <ErrorState error={new Error(phase.message)} onRetry={() => setPhase({ kind: "idle" })} />
        </div>
      )}

      <Card
        title="Uploaded captures"
        subtitle={captures.data ? `${captures.data.total} capture(s)` : undefined}
        action={
          <Button variant="ghost" onClick={captures.reload}>
            <RefreshCw size={14} /> Refresh
          </Button>
        }
        padded={false}
      >
        {captures.loading && !captures.data ? (
          <Spinner />
        ) : captures.error ? (
          <div className="p-5">
            <ErrorState error={captures.error} onRetry={captures.reload} />
          </div>
        ) : !captures.data?.items.length ? (
          <div className="p-5">
            <Empty icon={<FileUp size={28} />} title="No captures yet">
              Generate labelled test captures with <code>python -m testbed.synthetic.generate --all</code> and upload one.
            </Empty>
          </div>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Capture</Th>
                <Th>Traffic window</Th>
                <Th className="text-right">Packets</Th>
                <Th className="text-right">Size</Th>
                <Th>Status</Th>
                <Th />
              </tr>
            </thead>
            <tbody>
              {captures.data.items.map((c) => (
                <tr key={c.capture_id} className="hover:bg-raised/60">
                  <Td>
                    <div className="font-medium">{c.original_filename}</div>
                    <div className="mt-0.5 font-mono text-[11px] text-muted">
                      {c.ref} · {c.sha256.slice(0, 16)}…
                    </div>
                  </Td>
                  <Td className="text-ink2">{fmtDate(c.first_packet_at)}</Td>
                  <Td className="tabular text-right">{fmtNum(c.packet_count)}</Td>
                  <Td className="tabular text-right">{fmtBytes(c.size_bytes)}</Td>
                  <Td>
                    <StatusChip status={c.status} />
                  </Td>
                  <Td className="text-right">
                    {c.status === "complete" ? (
                      <Link
                        to={`/c/${c.capture_id}`}
                        className="inline-flex items-center gap-1 text-[13px] font-medium text-accent hover:underline"
                      >
                        Open <ArrowRight size={14} />
                      </Link>
                    ) : c.status === "validated" || c.status === "failed" ? (
                      <Button onClick={() => analyse(c.capture_id)} disabled={busy === c.capture_id}>
                        {busy === c.capture_id ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
                        {c.status === "failed" ? "Retry" : "Analyse"}
                      </Button>
                    ) : null}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </>
  );
}
