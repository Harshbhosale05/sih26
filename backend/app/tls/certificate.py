"""X.509 certificate extraction and analysis.

Two things this module is careful about.

**Expiry is measured against capture time, not now.** A certificate that expired
last week but was valid when the traffic was recorded was *not* a problem at the
time, and reporting it as one would be a false positive on any archived capture.
Conversely a certificate valid today may have been expired during the capture.
Forensics compares against the evidence's own clock.

**Chain trust is not validated.** A capture rarely contains the enterprise trust
store, so any claim about whether a chain is trusted would be unfounded. We
report what the presented chain contains and mark trust UNKNOWN. That is the
honest answer, and it is better than a confident wrong one.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from app.tls.records import CONTENT_HANDSHAKE, find_tls_start, parse_records

logger = logging.getLogger(__name__)

HANDSHAKE_CERTIFICATE = 0x0B

# Signature algorithms that must not appear in a current certificate.
BROKEN_SIGNATURE_ALGORITHMS = {
    "md5": "MD5 is collision-broken; certificates signed with it are forgeable.",
    "sha1": (
        "SHA-1 is collision-broken (SHAttered, 2017) and has been prohibited for "
        "certificate signatures since 2017."
    ),
    "md2": "MD2 is obsolete and broken.",
}

# Minimum public key sizes, per NIST SP 800-57 Part 1 Rev 5 (112-bit security).
MIN_KEY_BITS = {"RSA": 2048, "DSA": 2048, "EC": 224}

# Warn this far ahead of expiry: long enough to renew without an outage.
EXPIRY_WARNING_DAYS = 30


@dataclass
class CertificateInfo:
    index: int
    subject: str
    subject_cn: str | None
    issuer: str
    issuer_cn: str | None
    serial: str
    not_before: datetime
    not_after: datetime
    public_key_algorithm: str
    public_key_bits: int | None
    signature_algorithm: str
    san: list[str] = field(default_factory=list)
    is_ca: bool = False
    fingerprint_sha256: str = ""

    def serialise(self) -> dict:
        return {
            "index": self.index,
            "subject": self.subject,
            "subject_cn": self.subject_cn,
            "issuer": self.issuer,
            "issuer_cn": self.issuer_cn,
            "serial": self.serial,
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "public_key_algorithm": self.public_key_algorithm,
            "public_key_bits": self.public_key_bits,
            "signature_algorithm": self.signature_algorithm,
            "san": self.san,
            "is_ca": self.is_ca,
            "fingerprint_sha256": self.fingerprint_sha256,
        }


@dataclass
class CertificateAnalysis:
    observed: bool = False
    chain: list[CertificateInfo] = field(default_factory=list)
    chain_length: int = 0

    # Verdicts, all evaluated at capture time.
    expired: bool = False
    not_yet_valid: bool = False
    days_to_expiry: int | None = None
    expiring_soon: bool = False
    hostname_match: bool | None = None
    weak_key: bool = False
    broken_signature: bool = False
    self_signed: bool = False
    chain_incomplete: bool = False

    reasons: list[str] = field(default_factory=list)
    checked_hostname: str | None = None
    evaluated_at: str | None = None

    @property
    def leaf(self) -> CertificateInfo | None:
        return self.chain[0] if self.chain else None

    def serialise(self) -> dict:
        return {
            "observed": self.observed,
            "chain_length": self.chain_length,
            "chain": [c.serialise() for c in self.chain],
            "expired": self.expired,
            "not_yet_valid": self.not_yet_valid,
            "days_to_expiry": self.days_to_expiry,
            "expiring_soon": self.expiring_soon,
            "hostname_match": self.hostname_match,
            "checked_hostname": self.checked_hostname,
            "weak_key": self.weak_key,
            "broken_signature": self.broken_signature,
            "self_signed": self.self_signed,
            "chain_incomplete": self.chain_incomplete,
            "chain_trust": "UNKNOWN",
            "chain_trust_reason": (
                "Chain trust cannot be validated from a capture: the enterprise trust "
                "store is not present in the evidence."
            ),
            "evaluated_at": self.evaluated_at,
            "reasons": self.reasons,
        }


def extract_chain(stream_data: bytes) -> list[bytes]:
    """Pull DER certificates out of a TLS Certificate handshake message.

    Returns [] for TLS 1.3, where the message is encrypted — the caller reports
    that as unobservable rather than as an absent certificate.
    """
    start = find_tls_start(stream_data)
    if start is None:
        return []

    for record in parse_records(stream_data, start):
        if record.content_type != CONTENT_HANDSHAKE:
            continue
        if record.handshake_type != HANDSHAKE_CERTIFICATE:
            continue

        body = stream_data[record.offset + 5 : record.offset + 5 + record.length]
        # handshake header (1 type + 3 length), then certificate_list length (3)
        if len(body) < 7:
            return []
        cursor = 4
        list_length = int.from_bytes(body[cursor : cursor + 3], "big")
        cursor += 3
        end = min(cursor + list_length, len(body))

        chain: list[bytes] = []
        while cursor + 3 <= end:
            size = int.from_bytes(body[cursor : cursor + 3], "big")
            cursor += 3
            if size <= 0 or cursor + size > len(body):
                break
            chain.append(body[cursor : cursor + size])
            cursor += size
        return chain
    return []


def _key_info(cert: x509.Certificate) -> tuple[str, int | None]:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "EC", key.curve.key_size
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    return type(key).__name__, None


def _cn(name: x509.Name) -> str | None:
    values = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return values[0].value if values else None


def _san(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return list(ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        return []


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value.ca
    except x509.ExtensionNotFound:
        return False


def _matches(hostname: str, pattern: str) -> bool:
    """RFC 6125 name matching, including a single leftmost wildcard label."""
    hostname = hostname.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern == hostname:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]
        # A wildcard matches exactly one label, so *.a.com does not match b.c.a.com.
        return hostname.endswith(suffix) and hostname.count(".") == pattern.count(".")
    return False


def analyse(
    der_chain: list[bytes],
    *,
    capture_time: datetime,
    hostname: str | None = None,
) -> CertificateAnalysis:
    result = CertificateAnalysis(evaluated_at=capture_time.isoformat())
    if not der_chain:
        return result

    parsed: list[x509.Certificate] = []
    for der in der_chain:
        try:
            parsed.append(x509.load_der_x509_certificate(der))
        except Exception as exc:  # noqa: BLE001 - a malformed cert is data, not a crash
            logger.warning("could not parse certificate: %s", exc)

    if not parsed:
        return result

    result.observed = True
    result.chain_length = len(parsed)

    for index, cert in enumerate(parsed):
        algorithm, bits = _key_info(cert)
        try:
            sig = cert.signature_algorithm_oid._name
        except AttributeError:
            sig = str(cert.signature_algorithm_oid)

        result.chain.append(
            CertificateInfo(
                index=index,
                subject=cert.subject.rfc4514_string(),
                subject_cn=_cn(cert.subject),
                issuer=cert.issuer.rfc4514_string(),
                issuer_cn=_cn(cert.issuer),
                serial=format(cert.serial_number, "x"),
                not_before=cert.not_valid_before_utc,
                not_after=cert.not_valid_after_utc,
                public_key_algorithm=algorithm,
                public_key_bits=bits,
                signature_algorithm=sig,
                san=_san(cert),
                is_ca=_is_ca(cert),
                fingerprint_sha256=hashlib.sha256(
                    cert.public_bytes(__import__("cryptography").hazmat.primitives
                                      .serialization.Encoding.DER)
                ).hexdigest(),
            )
        )

    leaf = parsed[0]
    info = result.chain[0]

    # --- Validity, against the capture's own clock -------------------------
    if capture_time > info.not_after:
        result.expired = True
        days = (capture_time - info.not_after).days
        result.reasons.append(
            f"Certificate expired {days} day(s) before this traffic was captured "
            f"(notAfter {info.not_after.date()}, capture {capture_time.date()})."
        )
    elif capture_time < info.not_before:
        result.not_yet_valid = True
        days = (info.not_before - capture_time).days
        result.reasons.append(
            f"Certificate was not valid until {days} day(s) after this traffic was "
            f"captured (notBefore {info.not_before.date()})."
        )
    else:
        remaining = (info.not_after - capture_time).days
        result.days_to_expiry = remaining
        if remaining <= EXPIRY_WARNING_DAYS:
            result.expiring_soon = True
            result.reasons.append(
                f"Certificate had {remaining} day(s) of validity remaining at capture time."
            )

    # --- Identity ------------------------------------------------------------
    if hostname:
        result.checked_hostname = hostname
        names = list(info.san) or ([info.subject_cn] if info.subject_cn else [])
        result.hostname_match = any(_matches(hostname, n) for n in names if n)
        if result.hostname_match is False:
            result.reasons.append(
                f"Certificate identifies {', '.join(names) or 'no host'}, which does not "
                f"cover {hostname}."
            )

    # --- Key strength ---------------------------------------------------------
    minimum = MIN_KEY_BITS.get(info.public_key_algorithm)
    if minimum and info.public_key_bits and info.public_key_bits < minimum:
        result.weak_key = True
        result.reasons.append(
            f"{info.public_key_algorithm} public key is {info.public_key_bits} bits, "
            f"below the {minimum}-bit minimum in NIST SP 800-57 Part 1 Rev 5."
        )

    # --- Signature algorithm ---------------------------------------------------
    sig_lower = info.signature_algorithm.lower()
    for token, reason in BROKEN_SIGNATURE_ALGORITHMS.items():
        if token in sig_lower:
            result.broken_signature = True
            result.reasons.append(reason)
            break

    # --- Chain shape ------------------------------------------------------------
    result.self_signed = leaf.subject == leaf.issuer
    if result.self_signed:
        result.reasons.append(
            "Certificate is self-signed: no certificate authority attests to this identity."
        )
    elif len(parsed) == 1:
        result.chain_incomplete = True
        result.reasons.append(
            "Only the leaf certificate was presented; no issuer chain accompanied it, "
            "which causes validation failures on clients lacking the intermediate."
        )

    return result
