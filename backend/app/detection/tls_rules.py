"""Cryptographic rules over the negotiated TLS parameters.

All deterministic. A TLS version number either is or is not deprecated; a
cipher suite either does or does not provide forward secrecy. These are table
lookups, not predictions, and using a model for any of them would be a bug.

Every rule cites the standard that makes it a rule, so a finding can be argued
with on the merits rather than accepted on authority.
"""

from __future__ import annotations

from app.detection.engine import VERDICT_UNKNOWN, DraftFinding
from app.models.session import EmailSession

# RFC 8996 deprecates TLS 1.0 and 1.1; NIST SP 800-52r2 requires 1.2 minimum.
DEPRECATED_VERSIONS = {
    "SSL 3.0": "SSL 3.0 is prohibited by RFC 7568 and is broken by POODLE.",
    "TLS 1.0": "TLS 1.0 is deprecated by RFC 8996 and prohibited by NIST SP 800-52r2.",
    "TLS 1.1": "TLS 1.1 is deprecated by RFC 8996 and prohibited by NIST SP 800-52r2.",
}


def _frames(session: EmailSession) -> list[int]:
    frames = [
        e["frame"]
        for e in (session.events or [])
        if e.get("kind") in {"tls_server_hello", "tls_client_hello"}
    ]
    return frames or [session.first_frame]


def session_tls_findings(session: EmailSession) -> list[DraftFinding]:
    drafts: list[DraftFinding] = []

    # No handshake observed: say nothing. Silence here is correct -- a session
    # with no TLS is already covered by the transport-security rules.
    if not session.tls_version:
        return drafts

    server = f"{session.server_ip}:{session.server_port}"
    frames = _frames(session)

    # --- Deprecated protocol version --------------------------------------
    if session.tls_version in DEPRECATED_VERSIONS:
        drafts.append(
            DraftFinding(
                category="deprecated_tls_version",
                session_ref=session.ref,
                session_id=session.id,
                description=(
                    f"{server} negotiated {session.tls_version} with {session.ref}."
                ),
                rationale=DEPRECATED_VERSIONS[session.tls_version],
                evidence={
                    "server": server,
                    "negotiated_version": session.tls_version,
                    "versions_offered": (session.tls_detail or {}).get("versions_offered"),
                    "cipher_suite": session.tls_cipher_suite,
                },
                evidence_frames=frames,
                wireshark_filter=session.wireshark_filter,
            )
        )

    # --- Cipher suite weaknesses -------------------------------------------
    suite = (session.tls_detail or {}).get("cipher_suite") or {}
    weaknesses = suite.get("weaknesses") or []

    # Static RSA is reported as its own finding, so exclude it here to avoid
    # saying the same thing twice at two severities.
    cipher_weaknesses = [w for w in weaknesses if "forward secrecy" not in w]
    if cipher_weaknesses:
        drafts.append(
            DraftFinding(
                category="weak_cipher_suite",
                session_ref=session.ref,
                session_id=session.id,
                description=(
                    f"{server} negotiated {session.tls_cipher_suite} with {session.ref}."
                ),
                rationale=" ".join(cipher_weaknesses),
                evidence={
                    "server": server,
                    "cipher_suite": session.tls_cipher_suite,
                    "cipher_code": session.tls_cipher_code,
                    "encryption": suite.get("encryption"),
                    "mode": suite.get("mode"),
                    "aead": suite.get("aead"),
                    "weaknesses": cipher_weaknesses,
                },
                evidence_frames=frames,
                wireshark_filter=session.wireshark_filter,
            )
        )

    # --- Forward secrecy ----------------------------------------------------
    if session.tls_forward_secrecy is False:
        drafts.append(
            DraftFinding(
                category="no_forward_secrecy",
                session_ref=session.ref,
                session_id=session.id,
                description=(
                    f"{server} negotiated {session.tls_cipher_suite}, which uses "
                    f"{session.tls_key_exchange} key exchange and provides no forward "
                    "secrecy."
                ),
                rationale=(
                    "Without an ephemeral key exchange, every session recorded on this "
                    "path stays decryptable forever if the server's private key is ever "
                    "disclosed. This is also the clearest harvest-now-decrypt-later "
                    "exposure in the capture."
                ),
                evidence={
                    "server": server,
                    "cipher_suite": session.tls_cipher_suite,
                    "key_exchange": session.tls_key_exchange,
                },
                evidence_frames=frames,
                wireshark_filter=session.wireshark_filter,
            )
        )

    # --- Certificate observability ------------------------------------------
    # Not a fault, and deliberately INFO with an UNKNOWN verdict. It exists so
    # the posture report can state its own evidence coverage rather than
    # implying a clean certificate result it never had the data to reach.
    if not session.cert_observable and session.tls_established:
        drafts.append(
            DraftFinding(
                category="certificate_not_observable",
                session_ref=session.ref,
                session_id=session.id,
                description=(
                    f"No certificate could be examined for {session.ref}; certificate "
                    "posture for this session is undetermined."
                ),
                rationale=session.cert_unobservable_reason
                or "Certificate message not present in the capture.",
                verdict=VERDICT_UNKNOWN,
                evidence={
                    "server": server,
                    "negotiated_version": session.tls_version,
                    "remedy": (
                        "Capture with SSLKEYLOGFILE, or analyse a TLS 1.2 session, to "
                        "make the certificate chain visible."
                    ),
                },
                evidence_frames=frames,
                wireshark_filter=session.wireshark_filter,
            )
        )

    return drafts
