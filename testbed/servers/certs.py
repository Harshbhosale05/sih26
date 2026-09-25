"""Certificate + key pairs for the live servers.

The tier-1 fixtures are DER certificates with no private keys — fine for parsing,
useless for serving. These are generated fresh at run time so the servers have
keys, with validity anchored to real "now" so the live handshakes are ordinary.

The one exception is `expired`, which is deliberately issued in the past. That
is the whole point of the scenario: we need a genuine TLS handshake carrying a
genuinely expired certificate.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

HOST = "mail.testbed.local"  # must match runner.HOST: SNI is what gets verified


def _name(cn: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMailScope Testbed"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def _write(path: Path, key, cert, chain: list = None) -> Path:
    pem = cert.public_bytes(serialization.Encoding.PEM)
    for extra in chain or []:
        pem += extra.public_bytes(serialization.Encoding.PEM)
    pem += key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    return path


def generate(outdir: Path) -> dict[str, Path]:
    """Build the key/certificate pairs the scenarios need."""
    outdir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca = (
        x509.CertificateBuilder()
        .subject_name(_name("Testbed Root CA"))
        .issuer_name(_name("Testbed Root CA"))
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=365))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    def leaf(cn: str, san: str, bits: int, not_before, not_after, serial: int):
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name(cn))
            .issuer_name(_name("Testbed Root CA"))
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False
            )
            .sign(ca_key, hashes.SHA256())
        )
        return key, cert

    paths: dict[str, Path] = {}

    key, cert = leaf(HOST, HOST, 2048, now - timedelta(days=30), now + timedelta(days=335), 0x2001)
    paths["valid"] = _write(outdir / "valid.pem", key, cert, [ca])

    # Genuinely expired: issued and expired in the past, served for real.
    key, cert = leaf(HOST, HOST, 2048, now - timedelta(days=400), now - timedelta(days=35), 0x2002)
    paths["expired"] = _write(outdir / "expired.pem", key, cert, [ca])

    key, cert = leaf(HOST, HOST, 1024, now - timedelta(days=30), now + timedelta(days=335), 0x2003)
    paths["weak_key"] = _write(outdir / "weak_key.pem", key, cert, [ca])

    key, cert = leaf(
        "elsewhere.invalid", "elsewhere.invalid", 2048,
        now - timedelta(days=30), now + timedelta(days=335), 0x2004,
    )
    paths["wrong_host"] = _write(outdir / "wrong_host.pem", key, cert, [ca])

    # Leaf only, no CA appended: an incomplete chain as actually served.
    key, cert = leaf(HOST, HOST, 2048, now - timedelta(days=30), now + timedelta(days=335), 0x2005)
    paths["chain_incomplete"] = _write(outdir / "chain_incomplete.pem", key, cert)

    return paths
