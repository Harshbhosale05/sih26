#!/usr/bin/env python3
"""Generate the X.509 fixtures the certificate scenarios are built from.

These are **real certificates** — same library, same encoding, same structures a
CA produces. Only the TLS handshake we later wrap them in is synthetic, and
that does not matter: passive analysis parses the Certificate message, it never
verifies a signature against a live key exchange.

Run once; the DER files are committed as fixtures so scenarios stay
reproducible. Validity windows are anchored to the scenario epoch
(2026-03-02 09:15 UTC), so "expired" stays expired forever.

    docker compose exec api python /app/testbed_certs.py /data/certs
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# The epoch every scenario capture uses. Certificate validity is expressed
# relative to this so "expired" means expired *at capture time*, which is the
# only comparison that is meaningful in forensic analysis.
CAPTURE_TIME = datetime(2026, 3, 2, 9, 15, 0, tzinfo=timezone.utc)

HOST = "mail01.corp.local"


def _name(cn: str, org: str = "Corp Internal") -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def _key(bits: int = 3072) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


# Modern `cryptography` refuses to *sign* with SHA-1, which is correct of it and
# unhelpful here: we need a SHA-1-signed certificate to prove the detector
# catches one. Both OIDs are DER-encoded to identical length, so swapping them
# in the finished certificate is a clean byte substitution that needs no
# re-encoding.
#
# The resulting signature does not verify. That is irrelevant: passive analysis
# parses the signature *algorithm* field and can never verify a signature
# anyway, having no access to the issuer's key.
_OID_SHA256_RSA = bytes.fromhex("06092A864886F70D01010B")
_OID_SHA1_RSA = bytes.fromhex("06092A864886F70D010105")


def _downgrade_signature_oid(der: bytes) -> bytes:
    if _OID_SHA256_RSA not in der:
        raise ValueError("expected a sha256WithRSAEncryption certificate")
    return der.replace(_OID_SHA256_RSA, _OID_SHA1_RSA)


def _build(
    *,
    subject_cn: str,
    issuer_cn: str,
    issuer_key,
    subject_key,
    not_before: datetime,
    not_after: datetime,
    san: list[str] | None = None,
    algorithm=None,
    is_ca: bool = False,
    serial: int = 0x1000,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject_cn))
        .issuer_name(_name(issuer_cn))
        .public_key(subject_key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None if is_ca else None),
            critical=True,
        )
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in san]),
            critical=False,
        )
    return builder.sign(issuer_key, algorithm or hashes.SHA256())


def main(outdir: Path) -> int:
    outdir.mkdir(parents=True, exist_ok=True)

    ca_key = _key(4096)
    ca = _build(
        subject_cn="Corp Internal Root CA",
        issuer_cn="Corp Internal Root CA",
        issuer_key=ca_key,
        subject_key=ca_key,
        not_before=CAPTURE_TIME - timedelta(days=730),
        not_after=CAPTURE_TIME + timedelta(days=2555),
        is_ca=True,
        serial=0x0001,
    )

    fixtures: dict[str, dict] = {}

    def emit(name: str, certs: list[x509.Certificate], note: str, transform=None) -> None:
        chain = [c.public_bytes(serialization.Encoding.DER) for c in certs]
        if transform is not None:
            chain[0] = transform(chain[0])
        for index, der in enumerate(chain):
            (outdir / f"{name}-{index}.der").write_bytes(der)
        leaf = x509.load_der_x509_certificate(chain[0])
        fixtures[name] = {
            "files": [f"{name}-{i}.der" for i in range(len(chain))],
            "chain_length": len(chain),
            "subject_cn": leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            "issuer_cn": leaf.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            "not_before": leaf.not_valid_before_utc.isoformat(),
            "not_after": leaf.not_valid_after_utc.isoformat(),
            "key_bits": leaf.public_key().key_size,
            "signature_algorithm": (
                leaf.signature_algorithm_oid._name
                if hasattr(leaf.signature_algorithm_oid, "_name")
                else str(leaf.signature_algorithm_oid)
            ),
            "note": note,
        }

    # 1. Healthy: valid window, strong key, SHA-256, correct SAN, chains to CA.
    key = _key(3072)
    emit("valid", [
        _build(subject_cn=HOST, issuer_cn="Corp Internal Root CA", issuer_key=ca_key,
               subject_key=key,
               not_before=CAPTURE_TIME - timedelta(days=60),
               not_after=CAPTURE_TIME + timedelta(days=305),
               san=[HOST, "smtp.corp.local"], serial=0x1001),
        ca,
    ], "Healthy baseline. No certificate finding should fire on this.")

    # 2. Expired before the capture was taken.
    key = _key(3072)
    emit("expired", [
        _build(subject_cn=HOST, issuer_cn="Corp Internal Root CA", issuer_key=ca_key,
               subject_key=key,
               not_before=CAPTURE_TIME - timedelta(days=400),
               not_after=CAPTURE_TIME - timedelta(days=29),
               san=[HOST], serial=0x1002),
        ca,
    ], "notAfter precedes capture time by 29 days.")

    # 3. Expiring imminently: valid, but about to become an outage.
    key = _key(3072)
    emit("expiring_soon", [
        _build(subject_cn=HOST, issuer_cn="Corp Internal Root CA", issuer_key=ca_key,
               subject_key=key,
               not_before=CAPTURE_TIME - timedelta(days=360),
               not_after=CAPTURE_TIME + timedelta(days=3),
               san=[HOST], serial=0x1003),
        ca,
    ], "Valid at capture time, expires in 3 days.")

    # 4. Not yet valid — a clock-skew or misissuance signature.
    key = _key(3072)
    emit("not_yet_valid", [
        _build(subject_cn=HOST, issuer_cn="Corp Internal Root CA", issuer_key=ca_key,
               subject_key=key,
               not_before=CAPTURE_TIME + timedelta(days=30),
               not_after=CAPTURE_TIME + timedelta(days=395),
               san=[HOST], serial=0x1004),
        ca,
    ], "notBefore is 30 days after capture time.")

    # 5. Identity mismatch: the certificate is for a different host entirely.
    key = _key(3072)
    emit("wrong_host", [
        _build(subject_cn="webmail.othercorp.example", issuer_cn="Corp Internal Root CA",
               issuer_key=ca_key, subject_key=key,
               not_before=CAPTURE_TIME - timedelta(days=60),
               not_after=CAPTURE_TIME + timedelta(days=305),
               san=["webmail.othercorp.example"], serial=0x1005),
        ca,
    ], "Subject and SAN do not cover mail01.corp.local.")

    # 6. Weak key: 1024-bit RSA, below every current guideline.
    key = _key(1024)
    emit("weak_key", [
        _build(subject_cn=HOST, issuer_cn="Corp Internal Root CA", issuer_key=ca_key,
               subject_key=key,
               not_before=CAPTURE_TIME - timedelta(days=60),
               not_after=CAPTURE_TIME + timedelta(days=305),
               san=[HOST], serial=0x1006),
        ca,
    ], "1024-bit RSA public key.")

    # 7. SHA-1 signature: collision-broken signing algorithm.
    key = _key(3072)
    emit("sha1_signed", [
        _build(subject_cn=HOST, issuer_cn="Corp Internal Root CA", issuer_key=ca_key,
               subject_key=key,
               not_before=CAPTURE_TIME - timedelta(days=60),
               not_after=CAPTURE_TIME + timedelta(days=305),
               san=[HOST], serial=0x1007),
        ca,
    ], "Certificate declares a SHA-1 signature algorithm.",
       transform=_downgrade_signature_oid)

    # 8. Self-signed leaf, presented alone with no issuer chain.
    key = _key(2048)
    emit("self_signed", [
        _build(subject_cn=HOST, issuer_cn=HOST, issuer_key=key, subject_key=key,
               not_before=CAPTURE_TIME - timedelta(days=60),
               not_after=CAPTURE_TIME + timedelta(days=305),
               san=[HOST], serial=0x1008),
    ], "Self-signed, no issuer chain presented.")

    (outdir / "manifest.json").write_text(json.dumps(fixtures, indent=2) + "\n")

    print(f"{'fixture':<16} {'key':>6} {'sig':>8}  {'not_after':<26} note")
    print("-" * 96)
    for name, meta in fixtures.items():
        print(
            f"{name:<16} {meta['key_bits']:>6} {meta['signature_algorithm']:>8}  "
            f"{meta['not_after']:<26} {meta['note']}"
        )
    print(f"\nwrote {len(fixtures)} fixtures to {outdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(Path(sys.argv[1] if len(sys.argv) > 1 else "certs")))
