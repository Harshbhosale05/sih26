import { FileCode2, Info, Terminal } from "lucide-react";

import { CodeLine, CopyButton } from "@/components/common";
import type { Playbook } from "@/lib/types";
import { cn } from "@/lib/utils";

export function Snippet({ snippet }: { snippet: Playbook["snippets"][number] }) {
  const added = snippet.lines.filter((l) => l.op !== "-").map((l) => l.text).join("\n");
  return (
    <div className="overflow-hidden rounded-lg border">
      <div className="flex items-center gap-2 border-b bg-muted/50 px-3 py-1.5">
        <FileCode2 className="size-3.5 text-muted-foreground" />
        <span className="min-w-0 flex-1 truncate font-mono text-xs">{snippet.file}</span>
        <CopyButton text={added} label="Copy" />
      </div>
      <pre className="overflow-x-auto bg-card py-2 font-mono text-[12px] leading-[1.55]">
        {snippet.lines.map((l, i) => (
          <div
            key={i}
            className={cn(
              "flex px-3",
              l.op === "+" && "bg-sev-ok/10 text-sev-ok",
              l.op === "-" && "bg-sev-critical/10 text-sev-critical line-through decoration-sev-critical/40",
            )}
          >
            <span className="w-4 shrink-0 select-none opacity-60">{l.op === " " ? "" : l.op}</span>
            <span className="whitespace-pre">{l.text}</span>
          </div>
        ))}
      </pre>
      {(snippet.apply.length > 0 || snippet.note) && (
        <div className="space-y-1.5 border-t bg-muted/30 px-3 py-2">
          {snippet.apply.map((a) => (
            <div key={a} className="flex items-center gap-2 font-mono text-[11.5px] text-muted-foreground">
              <Terminal className="size-3 shrink-0" />
              {a}
            </div>
          ))}
          {snippet.note && (
            <div className="flex items-start gap-2 text-[11.5px] text-muted-foreground">
              <Info className="mt-0.5 size-3 shrink-0" />
              {snippet.note}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function PlaybookView({ playbook, compact }: { playbook: Playbook; compact?: boolean }) {
  return (
    <div className="space-y-4">
      {!compact && (
        <div className="space-y-1">
          <div className="text-sm">{playbook.summary}</div>
          <div className="text-xs text-muted-foreground">{playbook.rationale}</div>
        </div>
      )}
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <span className="rounded-md border px-2 py-0.5">
          Written for <b className="text-foreground">{playbook.software.name ?? "generic server"}</b>
          {playbook.software.version ? ` ${playbook.software.version}` : ""}
          {playbook.software.specific ? "" : " (generic guidance)"}
        </span>
        {playbook.software.evidence && (
          <span className="truncate">
            identified from banner <span className="font-mono">“{playbook.software.evidence}”</span>
          </span>
        )}
      </div>
      <div className="space-y-3">
        {playbook.snippets.map((s, i) => (
          <Snippet key={i} snippet={s} />
        ))}
      </div>
      <div className="space-y-1.5">
        <div className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Verify the change</div>
        {playbook.verify.slice(0, -1).map((v) => (
          <CodeLine key={v}>{v}</CodeLine>
        ))}
        <div className="text-xs text-muted-foreground">{playbook.verify[playbook.verify.length - 1]}</div>
      </div>
      <div className="flex flex-wrap gap-1.5 text-[11px] text-muted-foreground">
        {playbook.standards.map((s) => (
          <span key={s} className="rounded border px-1.5 py-0.5">
            {s}
          </span>
        ))}
      </div>
      {playbook.caution && <div className="rounded-md border border-sev-medium/40 bg-sev-medium/10 p-2.5 text-xs">{playbook.caution}</div>}
    </div>
  );
}
