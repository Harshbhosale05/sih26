import { Braces, Download, ExternalLink, FileText, FileType2, Network } from "lucide-react";
import { useParams } from "react-router-dom";

import { PageHeader, Panel } from "@/components/common";
import { Button } from "@/components/ui/button";
import { exportUrl, useCapture } from "@/lib/api";

const EXPORTS = [
  {
    kind: "report.pdf" as const,
    icon: FileType2,
    title: "Forensic report · PDF",
    body: "Formal assessment for the record: executive summary, evidence manifest, posture calculation, every finding with its frames and Wireshark filter, prioritisation, our model's risk classification and the remediation plan. Rendered server-side from the HTML report.",
  },
  {
    kind: "report.html" as const,
    icon: FileText,
    title: "Forensic report · HTML",
    body: "The same report as a self-contained page — no external assets, safe to email and open offline.",
  },
  {
    kind: "report.json" as const,
    icon: Braces,
    title: "Machine-readable · JSON",
    body: "The full payload behind both reports: sessions, findings with evidence chains, posture terms, risk results, priorities and the plan. For SIEM ingestion and scripting.",
  },
  {
    kind: "cbom" as const,
    icon: Network,
    title: "Cryptographic bill of materials · CycloneDX",
    body: "CycloneDX 1.6 CBOM of every algorithm, protocol and certificate observed — the inventory for post-quantum migration planning.",
  },
];

export function ReportsPage() {
  const { captureId } = useParams();
  const { data: capture } = useCapture(captureId);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Reports & exports"
        description={`Every export is generated from one payload, so JSON, HTML and PDF can never disagree. Each carries the capture's SHA-256${capture ? ` (${capture.sha256.slice(0, 16)}…)` : ""} as its chain-of-custody anchor.`}
      />
      <div className="grid gap-4 md:grid-cols-2">
        {EXPORTS.map((e) => (
          <Panel key={e.kind}>
            <div className="flex gap-4">
              <div className="grid size-10 shrink-0 place-items-center rounded-lg bg-muted">
                <e.icon className="size-5 text-muted-foreground" />
              </div>
              <div className="min-w-0 flex-1 space-y-2">
                <div className="font-medium">{e.title}</div>
                <p className="text-sm text-muted-foreground">{e.body}</p>
                <div className="flex gap-2">
                  <Button asChild size="sm">
                    <a href={exportUrl(captureId!, e.kind)} download>
                      <Download className="size-3.5" /> Download
                    </a>
                  </Button>
                  {e.kind !== "report.pdf" && (
                    <Button asChild size="sm" variant="outline">
                      <a href={exportUrl(captureId!, e.kind)} target="_blank" rel="noreferrer">
                        <ExternalLink className="size-3.5" /> Open
                      </a>
                    </Button>
                  )}
                </div>
              </div>
            </div>
          </Panel>
        ))}
      </div>
      <Panel title="Preview" description="The HTML report, exactly as exported.">
        <iframe title="Report preview" src={exportUrl(captureId!, "report.html")} className="h-[760px] w-full rounded-md border bg-white" />
      </Panel>
    </div>
  );
}
