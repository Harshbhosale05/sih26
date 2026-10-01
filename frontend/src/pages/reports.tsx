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
    body: "Formal assessment report with document control, methodology, chain of custody, detailed findings and remediation plan.",
  },
  {
    kind: "report.html" as const,
    icon: FileText,
    title: "Forensic report · HTML",
    body: "The same report as a self-contained web page that opens offline.",
  },
  {
    kind: "report.json" as const,
    icon: Braces,
    title: "Machine-readable · JSON",
    body: "Sessions, findings with evidence references, scores, priorities and the remediation plan, for SIEM ingestion.",
  },
  {
    kind: "cbom" as const,
    icon: Network,
    title: "Cryptographic bill of materials · CycloneDX",
    body: "CycloneDX 1.6 inventory of observed algorithms, protocols and certificates, for post-quantum migration planning.",
  },
];

export function ReportsPage() {
  const { captureId } = useParams();
  const { data: capture } = useCapture(captureId);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Report"
        description={`All exports are generated from the same assessment data and reference evidence SHA-256 ${capture ? capture.sha256.slice(0, 16) + "…" : ""}`}
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
      <Panel title="Preview" flush>
        <iframe title="Report preview" src={exportUrl(captureId!, "report.html")} className="h-[820px] w-full bg-[#e5e7eb]" />
      </Panel>
    </div>
  );
}
