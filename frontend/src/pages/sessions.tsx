import type { ColumnDef } from "@tanstack/react-table";
import { useMemo } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";

import { ErrorState, Loading, PageHeader, RiskBadge, StateBadge } from "@/components/common";
import { DataTable, SortHeader, multiFilter } from "@/components/data-table";
import { useSessions } from "@/lib/api";
import { stateLabel } from "@/lib/format";
import type { Session } from "@/lib/types";

type Row = Session & { server: string; outcome: string; risk: string; tls: string };

const RISK_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, minimal: 4, "—": 5 };

const columns: ColumnDef<Row, unknown>[] = [
  {
    accessorKey: "ref",
    header: ({ column }) => <SortHeader column={column} title="Session" />,
    cell: ({ row }) => (
      <div>
        <div className="font-mono text-xs font-medium">{row.original.ref}</div>
        <div className="font-mono text-[11px] text-muted-foreground">
          #{row.original.first_frame}–#{row.original.last_frame}
        </div>
      </div>
    ),
    size: 110,
  },
  { accessorKey: "protocol", header: "Protocol", filterFn: multiFilter, cell: ({ row }) => <span className="text-xs">{row.original.protocol}</span>, size: 80 },
  {
    accessorKey: "client_ip",
    header: ({ column }) => <SortHeader column={column} title="Client" />,
    cell: ({ row }) => <span className="font-mono text-xs">{row.original.client_ip}</span>,
    size: 130,
  },
  {
    accessorKey: "server",
    header: ({ column }) => <SortHeader column={column} title="Server" />,
    filterFn: multiFilter,
    cell: ({ row }) => <span className="font-mono text-xs">{row.original.server}</span>,
    size: 160,
  },
  {
    accessorKey: "outcome",
    header: "Encryption",
    filterFn: multiFilter,
    cell: ({ row }) => (
      <div className="flex flex-col items-start gap-1">
        <StateBadge state={row.original.encryption_state} />
        {row.original.cleartext_auth_observed && <span className="text-[11px] font-medium text-sev-critical">Credentials exposed</span>}
      </div>
    ),
    size: 200,
  },
  { accessorKey: "tls", header: "TLS", filterFn: multiFilter, cell: ({ row }) => <span className="text-xs">{row.original.tls}</span>, size: 80 },
  {
    accessorKey: "tls_cipher_suite",
    header: "Cipher suite",
    cell: ({ row }) => <span className="block max-w-[260px] truncate font-mono text-[11px]">{row.original.tls_cipher_suite?.replace(/^TLS_/, "") ?? "—"}</span>,
  },
  {
    id: "fs",
    header: "FS",
    cell: ({ row }) => (
      <span className="text-xs">{row.original.tls_forward_secrecy == null ? "—" : row.original.tls_forward_secrecy ? "Yes" : <span className="text-sev-critical">No</span>}</span>
    ),
    size: 50,
  },
  {
    id: "pqc",
    header: "PQC",
    cell: ({ row }) => (
      <span className="text-xs">
        {row.original.tls_pqc_selected ? <span className="text-sev-ok">Hybrid</span> : row.original.tls_pqc_offered ? <span className="text-sev-medium">Offered</span> : "—"}
      </span>
    ),
    size: 70,
  },
  {
    accessorKey: "risk",
    header: ({ column }) => <SortHeader column={column} title="Risk" />,
    filterFn: multiFilter,
    sortingFn: (a, b) => (RISK_RANK[a.original.risk] ?? 9) - (RISK_RANK[b.original.risk] ?? 9) || (b.original.risk_score ?? 0) - (a.original.risk_score ?? 0),
    cell: ({ row }) => <RiskBadge risk={row.original.risk_class} score={row.original.risk_score} />,
    size: 120,
  },
];

export function SessionsPage() {
  const { captureId } = useParams();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const { data, error } = useSessions(captureId);
  const server = params.get("server");

  const rows = useMemo<Row[]>(
    () =>
      (data ?? [])
        .filter((s) => s.protocol)
        .map((s) => ({
          ...s,
          server: `${s.server_ip}:${s.server_port}`,
          outcome: stateLabel(s.encryption_state),
          risk: s.risk_class ?? "—",
          tls: s.tls_version ?? "None",
        })),
    [data],
  );

  if (error) return <ErrorState error={error} />;
  if (!data) return <Loading rows={3} />;

  return (
    <>
      <PageHeader title="Sessions" description="Email sessions reconstructed from the capture, with their encryption outcome and negotiated cryptography." />
      <DataTable
        key={server ?? "all"}
        columns={columns}
        data={rows}
        searchPlaceholder="Search by session, IP or cipher"
        facets={[
          { column: "protocol", title: "Protocol" },
          { column: "outcome", title: "Encryption" },
          { column: "tls", title: "TLS" },
          { column: "risk", title: "Risk" },
          { column: "server", title: "Server" },
        ]}
        initialFilters={server ? [{ id: "server", value: [server] }] : []}
        initialSorting={[{ id: "risk", desc: false }]}
        onRowClick={(s) => navigate(`/c/${captureId}/sessions/${s.ref}`)}
        pageSize={25}
      />
    </>
  );
}
