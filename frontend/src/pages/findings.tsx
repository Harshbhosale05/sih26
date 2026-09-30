import { ChevronRight, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";

import { Empty, ErrorState, Loading, Meter, PageHeader, Panel, SeverityBadge, TierBadge, VerdictBadge } from "@/components/common";
import { HoverCard, HoverCardContent, HoverCardTrigger } from "@/components/ui/hover-card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { useFindings, usePriorities } from "@/lib/api";
import { categoryLabel, sevColor } from "@/lib/format";
import type { Priority } from "@/lib/types";

const SOURCE_LABEL: Record<string, string> = {
  rule: "deterministic rule",
  evidence: "captured evidence",
  "dependency graph": "dependency graph",
  correlation: "cross-session correlation",
  ml: "our model",
};

function Factors({ p }: { p: Priority }) {
  return (
    <div className="space-y-2">
      <div className="text-xs font-medium">
        Priority {p.priority.toFixed(1)} · {p.tier} {p.tier_label}
      </div>
      {p.factors.map((f) => (
        <div key={f.factor} className="space-y-0.5">
          <div className="flex justify-between gap-3 text-xs">
            <span>{f.factor}</span>
            <span className="tabular font-medium">{f.points ? `+${f.points}` : ""}</span>
          </div>
          <div className="text-[11px] text-muted-foreground">
            {f.detail} · <i>{SOURCE_LABEL[f.source] ?? f.source}</i>
          </div>
        </div>
      ))}
    </div>
  );
}

export function FindingsPage() {
  const { captureId } = useParams();
  const navigate = useNavigate();
  const priorities = usePriorities(captureId);
  const findings = useFindings(captureId);
  const [tier, setTier] = useState("all");
  const [verdict, setVerdict] = useState("FAIL");
  const [q, setQ] = useState("");

  const byRef = useMemo(() => new Map((findings.data ?? []).map((f) => [f.ref, f])), [findings.data]);
  const rows = useMemo(
    () =>
      (priorities.data ?? []).filter(
        (p) =>
          (tier === "all" || p.tier === tier) &&
          (verdict === "all" || p.verdict === verdict) &&
          (!q || `${p.ref} ${p.title} ${p.category} ${p.session_ref ?? ""}`.toLowerCase().includes(q.toLowerCase())),
      ),
    [priorities.data, tier, verdict, q],
  );

  if (priorities.error) return <ErrorState error={priorities.error} />;
  if (!priorities.data) return <Loading rows={3} />;

  const counts = { P1: 0, P2: 0, P3: 0, P4: 0 } as Record<string, number>;
  priorities.data.filter((p) => p.verdict === "FAIL").forEach((p) => counts[p.tier]++);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Findings & traceability"
        description="Every verdict comes from a deterministic, standards-cited rule. Priority adds context — exposure, blast radius, our risk model — to decide what to fix first. Open a finding to trace it from the packet bytes to the fix."
      />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {(["P1", "P2", "P3", "P4"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTier(tier === t ? "all" : t)}
            className={`rounded-lg border p-3 text-left transition-colors hover:bg-muted/40 ${tier === t ? "border-primary ring-1 ring-primary" : ""}`}
          >
            <div className="flex items-center justify-between">
              <TierBadge tier={t} />
              <span className="tabular text-2xl font-semibold">{counts[t]}</span>
            </div>
            <div className="mt-1 text-xs text-muted-foreground">{{ P1: "Act now · ≥ 70", P2: "This week · ≥ 50", P3: "Planned · ≥ 30", P4: "Backlog" }[t]}</div>
          </button>
        ))}
      </div>

      <Panel
        title={`${rows.length} finding${rows.length === 1 ? "" : "s"}`}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="absolute left-2 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search findings" className="h-8 w-[200px] pl-7 text-xs" />
            </div>
            <ToggleGroup type="single" value={verdict} onValueChange={(v) => v && setVerdict(v)} variant="outline" size="sm">
              <ToggleGroupItem value="FAIL" className="h-8 px-2.5 text-xs">
                Failing
              </ToggleGroupItem>
              <ToggleGroupItem value="UNKNOWN" className="h-8 px-2.5 text-xs">
                Undetermined
              </ToggleGroupItem>
              <ToggleGroupItem value="all" className="h-8 px-2.5 text-xs">
                All
              </ToggleGroupItem>
            </ToggleGroup>
          </div>
        }
      >
        {!rows.length ? (
          <Empty title="No findings match">Change the filters above.</Empty>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-10">#</TableHead>
                <TableHead className="w-14">Tier</TableHead>
                <TableHead className="w-[140px]">Priority</TableHead>
                <TableHead className="w-24">Severity</TableHead>
                <TableHead>Finding</TableHead>
                <TableHead>Session</TableHead>
                <TableHead>Verdict</TableHead>
                <TableHead className="w-8" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((p) => {
                const f = byRef.get(p.ref);
                return (
                  <TableRow key={p.ref} className="cursor-pointer" onClick={() => navigate(`/c/${captureId}/findings/${p.ref}`)}>
                    <TableCell className="tabular text-muted-foreground">{p.rank}</TableCell>
                    <TableCell>
                      <TierBadge tier={p.tier} />
                    </TableCell>
                    <TableCell>
                      <HoverCard openDelay={150}>
                        <HoverCardTrigger asChild>
                          <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                            <span className="tabular w-8 text-right text-xs font-medium">{Math.round(p.priority)}</span>
                            <Meter value={p.priority} color={sevColor(p.severity)} className="w-20" />
                          </div>
                        </HoverCardTrigger>
                        <HoverCardContent className="w-80">
                          <Factors p={p} />
                        </HoverCardContent>
                      </HoverCard>
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={p.severity} />
                    </TableCell>
                    <TableCell className="max-w-[520px]">
                      <div className="font-medium">{p.title}</div>
                      <div className="truncate text-xs text-muted-foreground">
                        <span className="font-mono">{p.ref}</span> · {categoryLabel(p.category)}
                        {f ? ` · ${f.description}` : ""}
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-xs">{p.session_ref ?? "capture-wide"}</TableCell>
                    <TableCell>
                      <VerdictBadge verdict={p.verdict} />
                    </TableCell>
                    <TableCell>
                      <ChevronRight className="size-4 text-muted-foreground" />
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </Panel>
    </div>
  );
}
