"""Cryptographic dependency graph and blast radius.

A finding says "this session negotiated TLS 1.0". An operator needs the next
question answered too: *what else leans on that?* Every client that sends mail
through that server inherits the weakness, whether or not its own session
happened to be the one that tripped the rule.

The graph makes those dependencies explicit:

    client --connects--> server --negotiates--> crypto primitive
                           ^
    weakness --affects-----+          domain --mx--> server

Blast radius is then computed per weakness in two rings:

  * **direct**   sessions that are themselves evidence for the weakness
  * **dependent** every session and client that relies on an affected server,
                  i.e. everything that would be exposed if the weakness is
                  exploited against the server rather than one connection

Both rings are expressed as a share of the *observed* environment. The capture
is a partial view, so "40% of observed clients" is a claim we can back;
"40% of your organisation" is not, and the output says so.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from app.models.finding import Finding
from app.models.session import EmailSession
from app.protocols import CLEARTEXT_STATES

_CLEARTEXT = {s.value for s in CLEARTEXT_STATES}
_DEPRECATED_VERSIONS = {"SSL 3.0", "TLS 1.0", "TLS 1.1"}
_SEVERITY_WEIGHT = {"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.5, "LOW": 0.25, "INFO": 0.1}
_RISK_OF_SEVERITY = {
    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info",
}
_MAX_CLIENT_NODES = 150


def _server_key(session: EmailSession) -> str:
    return f"{session.server_ip}:{session.server_port}"


@dataclass
class _Node:
    id: str
    type: str
    label: str
    risk: str = "ok"
    sub: str | None = None
    metrics: dict = field(default_factory=dict)

    def serialise(self) -> dict:
        return {
            "id": self.id, "type": self.type, "label": self.label,
            "risk": self.risk, "sub": self.sub, "metrics": self.metrics,
        }


def _crypto_nodes_for(session: EmailSession) -> list[tuple[str, str, str, str]]:
    """(id, label, sub, risk) for every primitive a session depended on."""
    if session.encryption_state in _CLEARTEXT or not session.tls_version:
        if session.encryption_state in _CLEARTEXT:
            return [("crypto:none", "No encryption", "cleartext transport", "critical")]
        return []

    nodes = []
    version = session.tls_version
    nodes.append((
        f"crypto:version:{version}", version, "protocol version",
        "high" if version in _DEPRECATED_VERSIONS else "ok",
    ))
    if session.tls_cipher_suite:
        weak = bool(((session.tls_detail or {}).get("cipher_suite") or {}).get("weaknesses"))
        nodes.append((
            f"crypto:suite:{session.tls_cipher_suite}", session.tls_cipher_suite, "cipher suite",
            "medium" if weak else ("low" if session.tls_aead is False else "ok"),
        ))
    if session.tls_selected_group:
        nodes.append((
            f"crypto:group:{session.tls_selected_group}", session.tls_selected_group,
            "key exchange group", "ok" if session.tls_pqc_selected else "quantum",
        ))
    elif session.tls_forward_secrecy is False and session.tls_key_exchange:
        nodes.append((
            f"crypto:kex:{session.tls_key_exchange}", f"{session.tls_key_exchange} key transport",
            "key exchange", "high",
        ))
    return nodes


def _finding_scope(
    finding: Finding, by_ref: dict[str, EmailSession]
) -> tuple[set[str], set[str], str | None]:
    """Sessions and servers a finding is evidence about, plus its domain if any."""
    evidence = finding.evidence or {}
    sessions: set[str] = set()
    servers: set[str] = set()

    for ref in [finding.session_ref, evidence.get("affected_session"),
                *(evidence.get("cleartext_sessions") or [])]:
        if ref and ref in by_ref:
            sessions.add(ref)

    for server in evidence.get("servers") or []:
        if isinstance(server, str):
            servers.add(server)
    profile = evidence.get("server_profile") or {}
    if isinstance(profile, dict) and profile.get("server"):
        servers.add(profile["server"])

    servers |= {_server_key(by_ref[r]) for r in sessions}
    return sessions, servers, evidence.get("domain")


def build(sessions: list[EmailSession], findings: list[Finding]) -> dict:
    email = [s for s in sessions if s.protocol]
    by_ref = {s.ref: s for s in email}
    nodes: dict[str, _Node] = {}
    edges: dict[tuple[str, str, str], dict] = {}

    def edge(source: str, target: str, kind: str, **extra) -> None:
        key = (source, target, kind)
        entry = edges.setdefault(
            key, {"source": source, "target": target, "type": kind, "weight": 0}
        )
        entry["weight"] += 1
        for k, v in extra.items():
            entry[k] = entry.get(k, 0) + v

    # --- Clients (capped, remainder aggregated) --------------------------------
    client_sessions = Counter(s.client_ip for s in email)
    kept = {ip for ip, _ in client_sessions.most_common(_MAX_CLIENT_NODES)}

    def client_id(ip: str) -> str:
        return f"client:{ip}" if ip in kept else "client:other"

    server_clients: dict[str, set[str]] = defaultdict(set)
    server_sessions: dict[str, list[EmailSession]] = defaultdict(list)
    crypto_sessions: dict[str, list[EmailSession]] = defaultdict(list)

    for s in email:
        cid = client_id(s.client_ip)
        sid = f"server:{_server_key(s)}"
        cleartext = s.encryption_state in _CLEARTEXT

        client = nodes.setdefault(cid, _Node(
            cid, "client",
            s.client_ip if cid != "client:other" else "Other clients",
            metrics={"sessions": 0, "cleartext": 0, "credentials_exposed": 0},
        ))
        client.metrics["sessions"] += 1
        client.metrics["cleartext"] += int(cleartext)
        client.metrics["credentials_exposed"] += int(bool(s.cleartext_auth_observed))

        server = nodes.setdefault(sid, _Node(
            sid, "server", _server_key(s), sub=s.protocol,
            metrics={"sessions": 0, "cleartext": 0, "clients": 0, "protocols": {}},
        ))
        server.metrics["sessions"] += 1
        server.metrics["cleartext"] += int(cleartext)
        server.metrics["protocols"][s.protocol] = server.metrics["protocols"].get(s.protocol, 0) + 1

        edge(cid, sid, "connects", cleartext=int(cleartext))
        server_clients[sid].add(s.client_ip)
        server_sessions[sid].append(s)

        for crypto_id, label, sub, risk in _crypto_nodes_for(s):
            node = nodes.setdefault(crypto_id, _Node(
                crypto_id, "crypto", label, risk=risk, sub=sub, metrics={"sessions": 0},
            ))
            node.metrics["sessions"] += 1
            edge(sid, crypto_id, "negotiates")
            crypto_sessions[crypto_id].append(s)

    for sid, clients in server_clients.items():
        nodes[sid].metrics["clients"] = len(clients)

    # --- Weaknesses from findings ---------------------------------------------
    by_category: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.verdict == "FAIL":
            by_category[f.category].append(f)

    weakness_scope: dict[str, dict] = {}
    for category, items in by_category.items():
        worst = min(items, key=lambda f: f.severity_rank)
        wid = f"weakness:{category}"
        direct: set[str] = set()
        servers: set[str] = set()
        domains: set[str] = set()
        for f in items:
            s_refs, s_keys, domain = _finding_scope(f, by_ref)
            direct |= s_refs
            servers |= s_keys
            if domain:
                domains.add(domain)

        nodes[wid] = _Node(
            wid, "weakness", worst.title, risk=_RISK_OF_SEVERITY.get(worst.severity, "info"),
            sub=category, metrics={"findings": len(items), "severity": worst.severity},
        )
        for key in servers:
            sid = f"server:{key}"
            if sid in nodes:
                edge(wid, sid, "affects")
                if _RISK_ORDER[nodes[wid].risk] < _RISK_ORDER[nodes[sid].risk]:
                    nodes[sid].risk = nodes[wid].risk
        for domain in domains:
            did = f"domain:{domain}"
            nodes.setdefault(did, _Node(did, "domain", domain, sub="mail domain"))
            edge(wid, did, "affects")
            for key in servers:
                if f"server:{key}" in nodes:
                    edge(did, f"server:{key}", "mx")

        weakness_scope[category] = {
            "node": wid, "title": worst.title, "severity": worst.severity,
            "findings": items, "direct": direct, "servers": servers, "domains": domains,
        }

    # --- Blast radius -----------------------------------------------------------
    total_sessions = len(email) or 1
    total_clients = len({s.client_ip for s in email}) or 1
    total_servers = len(server_sessions) or 1

    radius = []
    for category, scope in weakness_scope.items():
        radius.append(_radius_entry(
            kind="finding", key=category, node=scope["node"], title=scope["title"],
            severity=scope["severity"], direct_refs=scope["direct"],
            servers=scope["servers"], by_ref=by_ref, server_sessions=server_sessions,
            totals=(total_sessions, total_clients, total_servers),
            finding_refs=[f.ref for f in scope["findings"]], domains=sorted(scope["domains"]),
        ))

    for crypto_id, rows in crypto_sessions.items():
        node = nodes[crypto_id]
        if node.risk in ("ok",):
            continue
        severity = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
                    "low": "LOW", "quantum": "INFO"}[node.risk]
        radius.append(_radius_entry(
            kind="crypto", key=crypto_id, node=crypto_id,
            title=f"{node.label} ({node.sub})", severity=severity,
            direct_refs={s.ref for s in rows}, servers={_server_key(s) for s in rows},
            by_ref=by_ref, server_sessions=server_sessions,
            totals=(total_sessions, total_clients, total_servers),
            finding_refs=[], domains=[],
        ))

    radius.sort(key=lambda r: -r["blast_score"])

    for entry in radius:
        if entry["node"] in nodes:
            nodes[entry["node"]].metrics["blast_score"] = entry["blast_score"]

    # Servers ranked by how much depends on them and how exposed they are.
    critical_servers = sorted(
        (
            {
                "server": n.label,
                "node": n.id,
                "clients": n.metrics["clients"],
                "sessions": n.metrics["sessions"],
                "cleartext": n.metrics["cleartext"],
                "risk": n.risk,
                "weaknesses": sorted(
                    c for c, sc in weakness_scope.items() if n.label in sc["servers"]
                ),
            }
            for n in nodes.values() if n.type == "server"
        ),
        key=lambda r: (_RISK_ORDER[r["risk"]], -r["clients"], -r["sessions"]),
    )

    return {
        "nodes": [n.serialise() for n in nodes.values()],
        "edges": list(edges.values()),
        "blast_radius": radius,
        "servers": critical_servers,
        "totals": {
            "sessions": len(email),
            "clients": len({s.client_ip for s in email}),
            "servers": len(server_sessions),
            "weaknesses": len(weakness_scope),
            "client_nodes_aggregated": max(0, len(client_sessions) - len(kept)),
        },
        "method": (
            "Direct = sessions that are themselves evidence for the weakness. "
            "Dependent = every observed session and client relying on an affected "
            "server. Blast score = severity weight x (0.6 x direct session share + "
            "0.4 x dependent client share) x 100. Shares are of the observed "
            "environment only — a capture is a partial view."
        ),
    }


_RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "quantum": 4, "info": 5, "ok": 6}


def _radius_entry(
    *, kind: str, key: str, node: str, title: str, severity: str,
    direct_refs: set[str], servers: set[str], by_ref: dict[str, EmailSession],
    server_sessions: dict[str, list[EmailSession]], totals: tuple[int, int, int],
    finding_refs: list[str], domains: list[str],
) -> dict:
    total_sessions, total_clients, total_servers = totals
    direct = [by_ref[r] for r in direct_refs if r in by_ref]
    dependent = [s for key_ in servers for s in server_sessions.get(f"server:{key_}", [])]
    dependent_clients = {s.client_ip for s in dependent}
    direct_share = len(direct) / total_sessions
    client_share = len(dependent_clients) / total_clients
    weight = _SEVERITY_WEIGHT.get(severity, 0.1)

    return {
        "kind": kind,
        "key": key,
        "node": node,
        "title": title,
        "severity": severity,
        "finding_refs": finding_refs,
        "domains": domains,
        "direct_sessions": len(direct),
        "direct_session_refs": sorted(r.ref for r in direct)[:25],
        "direct_pct": round(100 * direct_share, 1),
        "dependent_sessions": len(dependent),
        "dependent_pct": round(100 * len(dependent) / total_sessions, 1),
        "servers": sorted(servers),
        "servers_pct": round(100 * len(servers) / total_servers, 1),
        "dependent_clients": len(dependent_clients),
        "clients_pct": round(100 * client_share, 1),
        "credentials_exposed": sum(1 for s in direct if s.cleartext_auth_observed),
        "protocols": dict(Counter(s.protocol for s in dependent)),
        "blast_score": round(weight * (0.6 * direct_share + 0.4 * client_share) * 100, 1),
    }
