import { ArrowDown, BadgeCheck, CircleSlash, FileKey2, Landmark, ShieldAlert, ShieldQuestion } from "lucide-react";

import { Tag } from "@/components/common";
import type { CertificateDetail, CertLeaf } from "@/lib/types";
import { cn } from "@/lib/utils";

const TRUST: Record<string, { label: string; color: string; icon: typeof BadgeCheck }> = {
  TRUSTED: { label: "Trusted", color: "hsl(var(--sev-ok))", icon: BadgeCheck },
  UNTRUSTED_ANCHOR: { label: "Valid chain · root not in trust store", color: "hsl(var(--sev-medium))", icon: ShieldQuestion },
  INCOMPLETE: { label: "Incomplete — path to root cannot be built", color: "hsl(var(--sev-high))", icon: CircleSlash },
  INVALID: { label: "Signature verification failed", color: "hsl(var(--sev-critical))", icon: ShieldAlert },
  UNKNOWN: { label: "Not evaluated", color: "hsl(var(--sev-info))", icon: ShieldQuestion },
};

function Flags({ cert, index }: { cert: CertificateDetail; index: number }) {
  if (index !== 0) return null;
  const flags: [boolean | null | undefined, string][] = [
    [cert.expired, "expired at capture time"],
    [cert.not_yet_valid, "not yet valid"],
    [cert.expiring_soon, `expires in ${cert.days_to_expiry} d`],
    [cert.hostname_match === false, `does not cover ${cert.checked_hostname}`],
    [cert.weak_key, "weak key"],
    [cert.broken_signature, "broken signature hash"],
    [cert.self_signed, "self-signed"],
    [cert.chain_incomplete, "no issuer chain presented"],
  ];
  const active = flags.filter(([f]) => f);
  if (!active.length)
    return <div className="text-xs text-sev-ok">No validity, key, signature or hostname problem at capture time</div>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {active.map(([, l]) => (
        <span key={l} className="rounded border border-sev-critical/40 bg-sev-critical/10 px-1.5 py-0.5 text-[11px] font-medium text-sev-critical">
          {l}
        </span>
      ))}
    </div>
  );
}

function CertCard({ leaf, cert, index }: { leaf: CertLeaf; cert: CertificateDetail; index: number }) {
  const role = index === 0 ? "Leaf (server)" : leaf.is_ca && leaf.subject === leaf.issuer ? "Root CA" : "Intermediate CA";
  const Icon = index === 0 ? FileKey2 : Landmark;
  return (
    <div className="rounded-lg border bg-card p-3">
      <div className="flex items-start gap-3">
        <div className="grid size-8 shrink-0 place-items-center rounded-md bg-muted text-muted-foreground">
          <Icon className="size-4" />
        </div>
        <div className="min-w-0 flex-1 space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">{role}</span>
            <span className="truncate font-mono text-sm font-medium">{leaf.subject_cn ?? leaf.subject}</span>
          </div>
          <div className="grid gap-x-6 gap-y-1 text-xs text-muted-foreground sm:grid-cols-2">
            <div>
              Issuer <span className="font-mono text-foreground/85">{leaf.issuer_cn ?? leaf.issuer}</span>
            </div>
            <div>
              Key{" "}
              <span className={cn("font-mono text-foreground/85", index === 0 && cert.weak_key && "text-sev-critical")}>
                {leaf.public_key_algorithm} {leaf.public_key_bits}
              </span>
            </div>
            <div>
              Signature{" "}
              <span className={cn("font-mono text-foreground/85", index === 0 && cert.broken_signature && "text-sev-critical")}>{leaf.signature_algorithm}</span>
            </div>
            <div>
              Valid <span className="font-mono text-foreground/85">{leaf.not_before.slice(0, 10)} → {leaf.not_after.slice(0, 10)}</span>
            </div>
            {leaf.san.length > 0 && (
              <div className="sm:col-span-2">
                SAN{" "}
                {leaf.san.map((s) => (
                  <Tag key={s} className="mr-1">
                    {s}
                  </Tag>
                ))}
              </div>
            )}
            <div className="truncate sm:col-span-2">
              SHA-256 <span className="font-mono text-[10.5px]">{leaf.fingerprint_sha256}</span>
            </div>
          </div>
          <Flags cert={cert} index={index} />
        </div>
      </div>
    </div>
  );
}

/** Presented chain, top-down from leaf, with each link's signature verdict and the trust anchor. */
export function CertChain({ cert }: { cert: CertificateDetail }) {
  const trust = TRUST[cert.chain_trust] ?? TRUST.UNKNOWN;
  const links = cert.chain_links ?? [];
  return (
    <div className="space-y-2">
      <div className="flex items-start gap-2 rounded-lg border p-3" style={{ borderColor: `color-mix(in srgb, ${trust.color} 45%, transparent)`, background: `color-mix(in srgb, ${trust.color} 7%, transparent)` }}>
        <trust.icon className="mt-0.5 size-4 shrink-0" style={{ color: trust.color }} />
        <div className="text-sm">
          <div className="font-medium" style={{ color: trust.color }}>
            {trust.label}
          </div>
          <div className="text-xs text-muted-foreground">{cert.chain_trust_reason}</div>
        </div>
      </div>
      {cert.chain.map((leaf, i) => {
        const link = links.find((l) => l.child === i && l.issuer === i + 1);
        return (
          <div key={leaf.fingerprint_sha256 + i}>
            <CertCard leaf={leaf} cert={cert} index={i} />
            {i < cert.chain.length - 1 && (
              <div className="flex items-center gap-2 py-1 pl-6 text-[11px]">
                <ArrowDown className="size-3.5 text-muted-foreground" />
                <span
                  className="font-medium"
                  style={{ color: link?.status === "valid" ? "hsl(var(--sev-ok))" : link ? "hsl(var(--sev-critical))" : "hsl(var(--muted-foreground))" }}
                >
                  {link ? (link.status === "valid" ? "signed by next certificate — signature verifies" : `link broken — ${link.problems.join("; ")}`) : "not evaluated"}
                </span>
              </div>
            )}
          </div>
        );
      })}
      {cert.chain_anchor && (
        <div className="flex items-center gap-2 pl-6 text-[11px] text-sev-ok">
          <ArrowDown className="size-3.5" />
          anchored in {cert.chain_anchor.source} trust store: <span className="font-mono">{cert.chain_anchor.subject}</span>
        </div>
      )}
    </div>
  );
}
