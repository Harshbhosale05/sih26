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


# --- Risk-classifier features ---------------------------------------------
# A wider vector than the anomaly model's: the classifier is supervised, so it
# can use certificate and cipher facts that would only add noise to an
# unsupervised outlier search. Still facts only -- never a finding or verdict.

RISK_FEATURE_NAMES = [
    "is_smtp", "is_imap", "is_pop3",
    "implicit_tls_port", "tls_established", "implicit_tls",
    "tls_version_rank", "forward_secrecy", "aead", "cipher_key_bits",
    "cipher_weakness_count", "pqc_offered", "pqc_selected",
    "upgrade_advertised", "upgrade_requested", "upgrade_mangled", "upgrade_rejected",
    "cleartext_auth", "cleartext_mail",
    "cert_observable", "cert_expired", "cert_not_yet_valid", "cert_days_to_expiry",
    "cert_key_bits", "cert_weak_key", "cert_broken_signature", "cert_hostname_mismatch",
    "cert_self_signed", "cert_chain_incomplete", "cert_chain_invalid",
]

# What each feature means to an analyst, for attribution displays.
RISK_FEATURE_LABELS = {
    "is_smtp": "Protocol is SMTP", "is_imap": "Protocol is IMAP", "is_pop3": "Protocol is POP3",
    "implicit_tls_port": "Implicit-TLS port (465/993/995)",
    "tls_established": "TLS established", "implicit_tls": "Implicit TLS used",
    "tls_version_rank": "Negotiated TLS version", "forward_secrecy": "Forward secrecy",
    "aead": "AEAD cipher", "cipher_key_bits": "Cipher key size",
    "cipher_weakness_count": "Known cipher weaknesses", "pqc_offered": "Client offered PQC",
    "pqc_selected": "Server selected PQC", "upgrade_advertised": "STARTTLS advertised",
    "upgrade_requested": "STARTTLS requested", "upgrade_mangled": "STARTTLS capability mangled",
    "upgrade_rejected": "STARTTLS refused", "cleartext_auth": "Credentials sent in cleartext",
    "cleartext_mail": "Mail data sent in cleartext", "cert_observable": "Certificate observable",
    "cert_expired": "Certificate expired", "cert_not_yet_valid": "Certificate not yet valid",
    "cert_days_to_expiry": "Days until certificate expiry", "cert_key_bits": "Certificate key size",
    "cert_weak_key": "Weak certificate key", "cert_broken_signature": "Broken signature hash",
    "cert_hostname_mismatch": "Hostname mismatch", "cert_self_signed": "Self-signed certificate",
    "cert_chain_incomplete": "Incomplete chain", "cert_chain_invalid": "Chain signature invalid",
}

_IMPLICIT_PORTS = {465, 993, 995}


def risk_features(session: EmailSession) -> list[float]:
    detail = session.tls_detail or {}
    suite = detail.get("cipher_suite") or {}
    cert = detail.get("certificate") or {}
    leaf = (cert.get("chain") or [{}])[0] if cert.get("observed") else {}
    weaknesses = [w for w in (suite.get("weaknesses") or []) if "forward secrecy" not in w]
    rejected = session.encryption_state == "PLAINTEXT_AFTER_FAILURE" or any(
        e.get("kind") == "upgrade_rejected" for e in (session.events or [])
    )
    days = cert.get("days_to_expiry")
    observed = bool(cert.get("observed"))

    def flag(value) -> float:
        return 1.0 if value else 0.0

    return [
        flag(session.protocol == "SMTP"), flag(session.protocol == "IMAP"),
        flag(session.protocol == "POP3"),
        flag(session.server_port in _IMPLICIT_PORTS), flag(session.tls_established),
        flag(session.encryption_state == "IMPLICIT_TLS"),
        float(_VERSION_RANK.get(session.tls_version or "", 0)),
        flag(session.tls_forward_secrecy), flag(session.tls_aead),
        float(suite.get("key_size") or 0), float(len(weaknesses)),
        flag(session.tls_pqc_offered), flag(session.tls_pqc_selected),
        flag(session.upgrade_advertised), flag(session.upgrade_requested),
        flag(session.upgrade_advertised_mangled), flag(rejected),
        flag(session.cleartext_auth_observed), flag(session.cleartext_mail_observed),
        flag(observed), flag(cert.get("expired")), flag(cert.get("not_yet_valid")),
        float(min(max(days, 0), 400)) if observed and days is not None else (0.0 if observed else 400.0),
        float(leaf.get("public_key_bits") or 0) if observed else 0.0,
        flag(cert.get("weak_key")), flag(cert.get("broken_signature")),
        flag(cert.get("hostname_match") is False), flag(cert.get("self_signed")),
        flag(cert.get("chain_incomplete")), flag(cert.get("chain_invalid")),
    ]
