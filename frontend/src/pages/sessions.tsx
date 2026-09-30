import { ChevronRight, Search, X } from "lucide-react";
import { useMemo, useState } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";

import { Empty, ErrorState, Loading, PageHeader, Panel, RiskBadge, StateBadge } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useSessions } from "@/lib/api";
import { CLEARTEXT_STATES, PROTECTED_STATES } from "@/lib/format";

export function SessionsPage() {
  const { captureId } = useParams();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const { data, error } = useSessions(captureId);
  const [q, setQ] = useState("");
  const [protocol, setProtocol] = useState("all");
  const [outcome, setOutcome] = useState("all");
  const server = params.get("server");

  const rows = useMemo(
    () =>
      (data ?? []).filter((s) => {
        if (!s.protocol) return false;
        if (protocol !== "all" && s.protocol !== protocol) return false;
        if (server && `${s.server_ip}:${s.server_port}` !== server) return false;
        if (outcome === "protected" && !PROTECTED_STATES.has(s.encryption_state)) return false;
        if (outcome === "cleartext" && !CLEARTEXT_STATES.has(s.encryption_state)) return false;
        if (outcome === "risky" && !["high", "critical"].includes(s.risk_class ?? "")) return false;
        if (outcome === "anomalous" && !s.is_anomalous) return false;
        if (q && !`${s.ref} ${s.client_ip} ${s.server_ip} ${s.tls_cipher_suite ?? ""} ${s.tls_sni ?? ""}`.toLowerCase().includes(q.toLowerCase())) return false;
        return true;
      }),
    [data, protocol, outcome, q, server],
  );

  if (error) return <ErrorState error={error} />;
  if (!data) return <Loading rows={3} />;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Reconstructed sessions"
        description="Every SMTP, IMAP and POP3 conversation rebuilt from the TCP streams, with its encryption outcome, negotiated cryptography and our model's risk class."
      />
      <Panel
        title={`${rows.length} of ${data.filter((s) => s.protocol).length} sessions`}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {server && (
              <Badge variant="secondary" className="gap-1 font-mono text-xs">
                {server}
                <button onClick={() => setParams({})} aria-label="Clear server filter">
                  <X className="size-3" />
                </button>
              </Badge>
            )}
            <div className="relative">
              <Search className="absolute left-2 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Ref, IP, cipher, SNI" className="h-8 w-[190px] pl-7 text-xs" />
            </div>
            <Select value={protocol} onValueChange={setProtocol}>
              <SelectTrigger className="h-8 w-[110px] text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All protocols</SelectItem>
                <SelectItem value="SMTP">SMTP</SelectItem>
                <SelectItem value="IMAP">IMAP</SelectItem>
                <SelectItem value="POP3">POP3</SelectItem>
              </SelectContent>
            </Select>
            <Select value={outcome} onValueChange={setOutcome}>
              <SelectTrigger className="h-8 w-[140px] text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All outcomes</SelectItem>
                <SelectItem value="protected">Encrypted</SelectItem>
                <SelectItem value="cleartext">Cleartext</SelectItem>
                <SelectItem value="risky">High / critical risk</SelectItem>
                <SelectItem value="anomalous">Behavioural outliers</SelectItem>
              </SelectContent>
            </Select>
          </div>
        }
      >
        {!rows.length ? (
          <Empty title="No sessions match">
            <Button variant="link" onClick={() => { setQ(""); setProtocol("all"); setOutcome("all"); setParams({}); }}>
              Clear filters
            </Button>
          </Empty>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Session</TableHead>
                <TableHead>Client → server</TableHead>
                <TableHead>Encryption</TableHead>
                <TableHead>TLS</TableHead>
                <TableHead>Cipher suite</TableHead>
                <TableHead className="text-center">FS</TableHead>
                <TableHead className="text-center">PQC</TableHead>
                <TableHead>Risk (model)</TableHead>
                <TableHead className="w-8" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((s) => (
                <TableRow key={s.ref} className="cursor-pointer" onClick={() => navigate(`/c/${captureId}/sessions/${s.ref}`)}>
                  <TableCell>
                    <div className="font-mono text-xs font-medium">{s.ref}</div>
                    <div className="text-[11px] text-muted-foreground">frames {s.first_frame}–{s.last_frame}</div>
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {s.client_ip}
                    <span className="text-muted-foreground"> → </span>
                    {s.server_ip}:{s.server_port}
                  </TableCell>
                  <TableCell>
                    <StateBadge state={s.encryption_state} />
                    {s.cleartext_auth_observed && <div className="mt-1 text-[11px] font-medium text-sev-critical">credentials exposed</div>}
                  </TableCell>
                  <TableCell className="text-xs">{s.tls_version ?? "—"}</TableCell>
                  <TableCell className="max-w-[260px] truncate font-mono text-[11px]">{s.tls_cipher_suite?.replace(/^TLS_/, "") ?? "—"}</TableCell>
                  <TableCell className="text-center text-xs">{s.tls_forward_secrecy == null ? "—" : s.tls_forward_secrecy ? "✓" : <span className="text-sev-critical">✗</span>}</TableCell>
                  <TableCell className="text-center text-xs">{s.tls_pqc_selected ? <span className="text-sev-ok">hybrid</span> : s.tls_pqc_offered ? <span className="text-sev-medium">offered</span> : "—"}</TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1.5">
                      <RiskBadge risk={s.risk_class} score={s.risk_score} />
                      {s.is_anomalous && <span className="rounded border border-chart-3/40 px-1 text-[10px] text-chart-3">outlier</span>}
                    </div>
                  </TableCell>
                  <TableCell>
                    <ChevronRight className="size-4 text-muted-foreground" />
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
