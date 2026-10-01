import type { ColumnDef } from "@tanstack/react-table";
import { useMemo } from "react";
import { useNavigate, useParams } from "react-router-dom";

import { ErrorState, Loading, PageHeader, SeverityBadge, TierBadge, VerdictBadge } from "@/components/common";
import { DataTable, SortHeader, multiFilter } from "@/components/data-table";
import { HoverCard, HoverCardContent, HoverCardTrigger } from "@/components/ui/hover-card";
import { useFindings, usePriorities } from "@/lib/api";
import { categoryLabel } from "@/lib/format";
import type { Finding, Priority } from "@/lib/types";

type Row = Priority & { description: string; asset: string };

const SEV_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

function asset(f?: Finding): string {
  const e = (f?.evidence ?? {}) as { server?: string; server_profile?: { server?: string } };
  return e.server ?? e.server_profile?.server ?? f?.session_ref ?? "Environment";
}

const columns: ColumnDef<Row, unknown>[] = [
  {
    accessorKey: "priority",
    header: ({ column }) => <SortHeader column={column} title="Priority" />,
    cell: ({ row }) => (
      <HoverCard openDelay={150}>
        <HoverCardTrigger asChild>
          <span onClick={(e) => e.stopPropagation()} className="inline-flex">
            <TierBadge tier={row.original.tier} score={row.original.priority} />
          </span>
        </HoverCardTrigger>
        <HoverCardContent className="w-80 text-xs" align="start">
          <div className="mb-2 font-medium">
            Priority {row.original.priority.toFixed(1)} · {row.original.tier_label}
          </div>
          <div className="space-y-1.5">
            {row.original.factors.map((f) => (
              <div key={f.factor} className="grid grid-cols-[1fr_auto] gap-x-3">
                <span>{f.factor}</span>
                <span className="tabular font-medium">{f.points ? `+${f.points}` : ""}</span>
                <span className="col-span-2 text-muted-foreground">{f.detail}</span>
              </div>
            ))}
          </div>
        </HoverCardContent>
      </HoverCard>
    ),
    size: 110,
  },
  {
    id: "tier",
    accessorKey: "tier",
    header: () => null,
    cell: () => null,
    filterFn: multiFilter,
    enableSorting: false,
    size: 0,
  },
  {
    accessorKey: "severity",
    header: ({ column }) => <SortHeader column={column} title="Severity" />,
    cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
    sortingFn: (a, b) => SEV_RANK[a.original.severity] - SEV_RANK[b.original.severity],
    filterFn: multiFilter,
    size: 120,
  },
  {
    accessorKey: "title",
    header: ({ column }) => <SortHeader column={column} title="Finding" />,
    cell: ({ row }) => (
      <div className="min-w-0 max-w-[560px]">
        <div className="truncate font-medium">{row.original.title}</div>
        <div className="truncate text-xs text-muted-foreground">
          <span className="font-mono">{row.original.ref}</span> · {categoryLabel(row.original.category)}
        </div>
      </div>
    ),
  },
  {
    accessorKey: "asset",
    header: ({ column }) => <SortHeader column={column} title="Asset" />,
    cell: ({ row }) => <span className="font-mono text-xs">{row.original.asset}</span>,
    size: 170,
  },
  {
    accessorKey: "session_ref",
    header: "Session",
    cell: ({ row }) => <span className="font-mono text-xs text-muted-foreground">{row.original.session_ref ?? "—"}</span>,
    size: 110,
  },
  {
    accessorKey: "verdict",
    header: "Verdict",
    cell: ({ row }) => <VerdictBadge verdict={row.original.verdict} />,
    filterFn: multiFilter,
    size: 100,
  },
];

export function FindingsPage() {
  const { captureId } = useParams();
  const navigate = useNavigate();
  const priorities = usePriorities(captureId);
  const findings = useFindings(captureId);

  const rows = useMemo<Row[]>(() => {
    const byRef = new Map((findings.data ?? []).map((f) => [f.ref, f]));
    return (priorities.data ?? []).map((p) => ({ ...p, description: byRef.get(p.ref)?.description ?? "", asset: asset(byRef.get(p.ref)) }));
  }, [priorities.data, findings.data]);

  if (priorities.error) return <ErrorState error={priorities.error} />;
  if (!priorities.data) return <Loading rows={3} />;

  return (
    <>
      <PageHeader
        title="Findings"
        description="Verdicts come from standards-based rules. Priority orders them by severity, exposure, extent of impact and model risk."
      />
      <DataTable
        columns={columns}
        data={rows}
        searchPlaceholder="Search findings"
        facets={[
          { column: "severity", title: "Severity", options: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((v) => ({ value: v, label: v.charAt(0) + v.slice(1).toLowerCase() })) },
          { column: "tier", title: "Priority", options: ["P1", "P2", "P3", "P4"].map((v) => ({ value: v, label: v })) },
          { column: "verdict", title: "Verdict", options: [{ value: "FAIL", label: "Fail" }, { value: "UNKNOWN", label: "Undetermined" }, { value: "PASS", label: "Pass" }] },
        ]}
        initialFilters={[{ id: "verdict", value: ["FAIL"] }]}
        initialSorting={[{ id: "priority", desc: true }]}
        hidden={["tier"]}
        onRowClick={(r) => navigate(`/c/${captureId}/findings/${r.ref}`)}
        empty="No findings match the current filters."
      />
    </>
  );
}
