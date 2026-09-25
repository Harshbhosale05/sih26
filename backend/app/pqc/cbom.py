"""Cryptographic Bill of Materials (CycloneDX 1.6) and PQC readiness.

CycloneDX 1.6 added `cryptographic-asset` components specifically so that
organisations can inventory where classical public-key cryptography lives ahead
of the migration deadlines in CNSA 2.0. Producing a standards-compliant CBOM
*from a packet capture* is genuinely novel — normally a CBOM is assembled from
source code and configuration, which tells you what is deployed but not what is
actually negotiated on the wire.

What this module claims: here is the cryptography observed in this capture, and
here is where classical public-key algorithms remain.

What it never claims: that any attack is occurring, or that a cryptographically
relevant quantum computer exists. The honest risk framing is
harvest-now-decrypt-later — traffic recorded today without forward secrecy stays
readable if the key is later recovered.
"""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import datetime, timezone

from app.models.capture import Capture
from app.models.session import EmailSession

# NIST-standardised PQC primitives, for labelling what a hybrid group contains.
_PQC_COMPONENTS = {
    "X25519MLKEM768": ("ML-KEM-768", "FIPS 203"),
    "SecP256r1MLKEM768": ("ML-KEM-768", "FIPS 203"),
    "SecP384r1MLKEM1024": ("ML-KEM-1024", "FIPS 203"),
    "X25519Kyber768Draft00": ("Kyber-768 (draft)", "pre-standard"),
    "P256Kyber768Draft00": ("Kyber-768 (draft)", "pre-standard"),
}

# Classical primitives broken by Shor's algorithm on a CRQC.
_QUANTUM_VULNERABLE = {
    "x25519": "Elliptic-curve Diffie-Hellman (Curve25519)",
    "secp256r1": "Elliptic-curve Diffie-Hellman (NIST P-256)",
    "secp384r1": "Elliptic-curve Diffie-Hellman (NIST P-384)",
    "ECDHE": "Ephemeral elliptic-curve Diffie-Hellman",
    "DHE": "Ephemeral finite-field Diffie-Hellman",
    "RSA": "RSA key transport / signature",
    "ECDSA": "Elliptic-curve digital signature",
}


def _ref(*parts: str) -> str:
    return "crypto/" + "/".join(p.replace(" ", "-").lower() for p in parts if p)


def _asset(
    name: str,
    primitive: str,
    *,
    ref: str,
    execution_env: str = "software-plain-ram",
    nist_level: int | None = None,
    notes: str = "",
) -> dict:
    component = {
        "type": "cryptographic-asset",
        "bom-ref": ref,
        "name": name,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": primitive,
                "executionEnvironment": execution_env,
                "cryptoFunctions": ["keygen"] if primitive == "kem" else ["encrypt"],
            },
        },
    }
    if nist_level is not None:
        component["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] = (
            nist_level
        )
    if notes:
        component["description"] = notes
    return component


def build(capture: Capture, sessions: list[EmailSession]) -> dict:
    """Emit a CycloneDX 1.6 CBOM describing the observed cryptography."""
    tls = [s for s in sessions if s.tls_version]

    versions = Counter(s.tls_version for s in tls if s.tls_version)
    ciphers = Counter(s.tls_cipher_suite for s in tls if s.tls_cipher_suite)
    groups = Counter(s.tls_selected_group for s in tls if s.tls_selected_group)
    kex = Counter(s.tls_key_exchange for s in tls if s.tls_key_exchange)
    auth = Counter(s.tls_authentication for s in tls if s.tls_authentication)

    pqc_offered = [s for s in tls if s.tls_pqc_offered]
    pqc_selected = [s for s in tls if s.tls_pqc_selected]
    no_pfs = [s for s in tls if s.tls_forward_secrecy is False]

    components: list[dict] = []

    for name, count in ciphers.items():
        components.append(
            _asset(
                name, "ae", ref=_ref("suite", name),
                notes=f"Negotiated in {count} session(s) in this capture.",
            )
        )

    for name, count in groups.items():
        pqc = _PQC_COMPONENTS.get(name)
        if pqc:
            components.append(
                _asset(
                    name, "kem", ref=_ref("group", name), nist_level=3,
                    notes=(
                        f"Hybrid key exchange containing {pqc[0]} ({pqc[1]}). "
                        f"Selected in {count} session(s). Not vulnerable to Shor's "
                        "algorithm."
                    ),
                )
            )
        else:
            components.append(
                _asset(
                    name, "key-agree", ref=_ref("group", name),
                    notes=(
                        f"{_QUANTUM_VULNERABLE.get(name, 'Classical key agreement')}. "
                        f"Selected in {count} session(s). Classical public-key "
                        "dependency — migration candidate."
                    ),
                )
            )

    for name, count in kex.items():
        components.append(
            _asset(
                name, "key-agree", ref=_ref("kex", name),
                notes=(
                    f"{_QUANTUM_VULNERABLE.get(name, name)} used in {count} session(s)."
                ),
            )
        )

    for name, count in auth.items():
        components.append(
            _asset(
                name, "signature", ref=_ref("auth", name),
                notes=(
                    f"{_QUANTUM_VULNERABLE.get(name, name)} used for server "
                    f"authentication in {count} session(s). Migration candidate."
                ),
            )
        )

    total = len(tls) or 1

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {"type": "application", "name": "SecureMailScope", "version": "0.1.0"}
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": f"capture/{capture.id}",
                "name": capture.original_filename,
                "version": capture.ref,
                "hashes": [{"alg": "SHA-256", "content": capture.sha256}],
                "description": (
                    "Cryptography observed passively in an email traffic capture. "
                    "Reflects what was negotiated on the wire, not what is configured."
                ),
            },
        },
        "components": components,
        # Not part of the CycloneDX schema, but carried alongside so the
        # inventory arrives with the analysis that makes it actionable.
        "properties": [
            {"name": "securemailscope:tls_sessions", "value": str(len(tls))},
            {"name": "securemailscope:pqc_offered", "value": str(len(pqc_offered))},
            {"name": "securemailscope:pqc_selected", "value": str(len(pqc_selected))},
            {"name": "securemailscope:no_forward_secrecy", "value": str(len(no_pfs))},
        ],
        "securemailscope": {
            "readiness": {
                "tls_sessions": len(tls),
                "clients_offering_pqc": len(pqc_offered),
                "clients_offering_pqc_pct": round(100 * len(pqc_offered) / total, 1),
                "servers_selecting_pqc": len(pqc_selected),
                "servers_selecting_pqc_pct": round(100 * len(pqc_selected) / total, 1),
                "sessions_without_forward_secrecy": len(no_pfs),
                "tls_versions": dict(versions),
                "classical_key_agreement": dict(groups),
                "classical_authentication": dict(auth),
            },
            "framing": (
                "This is a migration inventory, not a threat assessment. It records "
                "where classical public-key cryptography remains in observed email "
                "traffic. Sessions without forward secrecy are the clearest "
                "harvest-now-decrypt-later exposure: recorded today, readable later "
                "if the server key is ever recovered."
            ),
            "standards": ["CycloneDX 1.6", "FIPS 203 (ML-KEM)", "CNSA 2.0", "RFC 8446"],
        },
    }


def readiness_finding(sessions: list[EmailSession]):
    """A LOW finding where clients have migrated to PQC and servers have not."""
    from app.detection.engine import DraftFinding

    tls = [s for s in sessions if s.tls_version]
    if not tls:
        return []

    offered = [s for s in tls if s.tls_pqc_offered]
    selected = [s for s in tls if s.tls_pqc_selected]
    if not offered or selected:
        return []

    servers = sorted({f"{s.server_ip}:{s.server_port}" for s in offered})
    return [
        DraftFinding(
            category="pqc_server_not_ready",
            session_ref=offered[0].ref,
            session_id=offered[0].id,
            description=(
                f"{len(offered)} of {len(tls)} clients offered hybrid post-quantum key "
                "exchange, and no server selected it."
            ),
            rationale=(
                "Some observed clients are PQC-capable; no observed server selected "
                "the hybrid group they offered, so every session fell back to classical "
                "key agreement. This describes only the clients and servers present in "
                "this capture — it is not a statement about the wider estate. A "
                "migration-readiness gap, not an active vulnerability."
            ),
            evidence={
                "clients_offering_pqc": len(offered),
                "tls_sessions": len(tls),
                "servers": servers,
                "groups_offered": sorted(
                    {
                        g
                        for s in offered
                        for g in ((s.tls_detail or {}).get("pqc_groups_offered") or [])
                    }
                ),
            },
            evidence_frames=[offered[0].first_frame],
            wireshark_filter=offered[0].wireshark_filter,
            affected_sessions=len(offered),
        )
    ]
