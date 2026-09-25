"""Feature extraction for the anomaly model.

Everything here is numeric and derived from facts already established by the
deterministic pipeline. Nothing is inferred, and no feature encodes a verdict --
feeding the model our own conclusions would just make it agree with us.
"""

from __future__ import annotations

from app.models.session import EmailSession

FEATURE_NAMES = [
    "is_smtp",
    "is_imap",
    "is_pop3",
    "server_port",
    "tls_established",
    "implicit_tls",
    "tls_version_rank",
    "forward_secrecy",
    "aead",
    "cipher_is_known",
    "pqc_offered",
    "cert_observable",
    "upgrade_advertised",
    "upgrade_requested",
    "upgrade_mangled",
    "cleartext_auth",
    "cleartext_mail",
    "handshake_ms",
    "frame_span",
    "event_count",
    "session_complete",
]

_VERSION_RANK = {"SSL 3.0": 1, "TLS 1.0": 2, "TLS 1.1": 3, "TLS 1.2": 4, "TLS 1.3": 5}


def extract_features(session: EmailSession) -> list[float]:
    detail = session.tls_detail or {}
    suite = detail.get("cipher_suite") or {}

    return [
        1.0 if session.protocol == "SMTP" else 0.0,
        1.0 if session.protocol == "IMAP" else 0.0,
        1.0 if session.protocol == "POP3" else 0.0,
        float(session.server_port),
        1.0 if session.tls_established else 0.0,
        1.0 if session.encryption_state == "IMPLICIT_TLS" else 0.0,
        float(_VERSION_RANK.get(session.tls_version or "", 0)),
        1.0 if session.tls_forward_secrecy else 0.0,
        1.0 if session.tls_aead else 0.0,
        1.0 if suite.get("name") and suite["name"] != "UNKNOWN" else 0.0,
        1.0 if session.tls_pqc_offered else 0.0,
        1.0 if session.cert_observable else 0.0,
        1.0 if session.upgrade_advertised else 0.0,
        1.0 if session.upgrade_requested else 0.0,
        1.0 if session.upgrade_advertised_mangled else 0.0,
        1.0 if session.cleartext_auth_observed else 0.0,
        1.0 if session.cleartext_mail_observed else 0.0,
        float(session.tls_handshake_ms or 0.0),
        float(max(session.last_frame - session.first_frame, 0)),
        float(len(session.events or [])),
        1.0 if session.session_complete else 0.0,
    ]
