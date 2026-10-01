import { BrainCircuit, FileText, FolderArchive, GitCompareArrows, ListChecks, Network, Sigma } from "lucide-react";
import { useEffect, useState } from "react";
import { useMatch, useNavigate } from "react-router-dom";

import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
  CommandShortcut,
} from "@/components/ui/command";
import { CAPTURE_TABS } from "@/components/capture-layout";
import { useCaptures, useFindings, useSessions } from "@/lib/api";

export function useCommandMenu() {
  const [open, setOpen] = useState(false);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((o) => !o);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);
  return { open, setOpen };
}

export function CommandMenu({ open, setOpen }: { open: boolean; setOpen: (o: boolean) => void }) {
  const navigate = useNavigate();
  const match = useMatch("/c/:captureId/*");
  const captureId = match?.params.captureId;
  const captures = useCaptures();
  const findings = useFindings(captureId);
  const sessions = useSessions(captureId);
  const [query, setQuery] = useState("");

  const go = (to: string) => {
    setOpen(false);
    setQuery("");
    navigate(to);
  };

  return (
    <CommandDialog open={open} onOpenChange={setOpen}>
      <CommandInput placeholder="Jump to anything, or ask the analyst a question…" value={query} onValueChange={setQuery} />
      <CommandList>
        <CommandEmpty>No results found.</CommandEmpty>
        {captureId && query.trim().length > 2 && (
          <CommandGroup heading="AI Analyst">
            <CommandItem value={`ask ${query}`} onSelect={() => go(`/c/${captureId}/analyst?q=${encodeURIComponent(query.trim())}`)}>
              <BrainCircuit />
              Ask: <span className="truncate font-medium">{query.trim()}</span>
            </CommandItem>
          </CommandGroup>
        )}
        {captureId && (
          <CommandGroup heading="This capture">
            {CAPTURE_TABS.map((t) => (
              <CommandItem key={t.to} onSelect={() => go(`/c/${captureId}${t.to ? `/${t.to}` : ""}`)}>
                <t.icon />
                {t.label}
              </CommandItem>
            ))}
          </CommandGroup>
        )}
        {captureId && (findings.data?.length ?? 0) > 0 && (
          <CommandGroup heading="Findings">
            {findings.data!.filter((f) => f.severity !== "INFO").map((f) => (
              <CommandItem key={f.ref} value={`${f.ref} ${f.title}`} onSelect={() => go(`/c/${captureId}/findings/${f.ref}`)}>
                <ListChecks />
                <span className="font-mono text-xs text-muted-foreground">{f.ref}</span>
                {f.title}
              </CommandItem>
            ))}
          </CommandGroup>
        )}
        {captureId && (sessions.data?.length ?? 0) > 0 && (
          <CommandGroup heading="Sessions">
            {sessions.data!.filter((s) => s.protocol).slice(0, 50).map((s) => (
              <CommandItem key={s.ref} value={`${s.ref} ${s.server_ip}:${s.server_port} ${s.client_ip}`} onSelect={() => go(`/c/${captureId}/sessions/${s.ref}`)}>
                <Network />
                <span className="font-mono text-xs">{s.ref}</span>
                <span className="text-muted-foreground">
                  {s.client_ip} → {s.server_ip}:{s.server_port}
                </span>
              </CommandItem>
            ))}
          </CommandGroup>
        )}
        <CommandSeparator />
        <CommandGroup heading="Captures">
          {(captures.data?.items ?? [])
            .filter((c) => c.status === "complete")
            .map((c) => (
              <CommandItem key={c.capture_id} value={`${c.ref} ${c.original_filename}`} onSelect={() => go(`/c/${c.capture_id}`)}>
                <FileText />
                <span className="font-mono text-xs text-muted-foreground">{c.ref}</span>
                {c.original_filename}
              </CommandItem>
            ))}
        </CommandGroup>
        <CommandGroup heading="Workspace">
          <CommandItem onSelect={() => go("/")}>
            <FolderArchive />
            Captures
            <CommandShortcut>G C</CommandShortcut>
          </CommandItem>
          <CommandItem onSelect={() => go("/drift")}>
            <GitCompareArrows />
            Drift
          </CommandItem>
          <CommandItem onSelect={() => go("/model")}>
            <Sigma />
            Risk model
          </CommandItem>
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  );
}
