"""TLS fingerprints: JA3/JA3S and JA4/JA4S.

We compute the industry-standard fingerprints rather than inventing our own.
They are what SOC tooling, Zeek and Suricata already speak, and they give the
behavioural-baseline work a primitive with published semantics.

GREASE values are excluded everywhere. Clients randomise them per connection,
so including them yields a fingerprint that changes every session -- the exact
opposite of what a fingerprint is for.

Licensing: JA3/JA3S are open (Salesforce, BSD-3). JA4 is BSD-3-Clause; other
JA4+ variants carry FoxIO licence terms and are deliberately not implemented
here. See NOTICE.
"""

from __future__ import annotations

import hashlib

from app.tls.groups import is_grease
from app.tls.handshake import ClientHello, ServerHello

# TLS 1.3 exists only as a supported_versions entry; JA4 labels it "13".
_JA4_VERSION = {
    0x0304: "13",
    0x0303: "12",
    0x0302: "11",
    0x0301: "10",
    0x0300: "s3",
}


def ja3(hello: ClientHello) -> tuple[str, str]:
    """JA3 client fingerprint. Returns (raw_string, md5).

    Format: SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
    """
    parts = [
        str(hello.legacy_version),
        "-".join(str(c) for c in hello.cipher_suites),
        "-".join(str(e) for e in hello.extensions),
        "-".join(str(g) for g in hello.supported_groups),
        "-".join(str(p) for p in hello.ec_point_formats),
    ]
    raw = ",".join(parts)
    return raw, hashlib.md5(raw.encode()).hexdigest()  # noqa: S324 - spec mandates MD5


def ja3s(hello: ServerHello) -> tuple[str, str]:
    """JA3S server fingerprint: SSLVersion,Cipher,Extensions."""
    raw = ",".join([
        str(hello.legacy_version),
        str(hello.cipher_suite),
        "-".join(str(e) for e in hello.extensions),
    ])
    return raw, hashlib.md5(raw.encode()).hexdigest()  # noqa: S324


def _truncated_sha256(values: list[str]) -> str:
    """First 12 hex chars of sha256 over a comma-joined list, per JA4."""
    if not values:
        return "000000000000"
    joined = ",".join(values)
    return hashlib.sha256(joined.encode()).hexdigest()[:12]


def ja4(hello: ClientHello, *, transport: str = "t") -> str:
    """JA4 client fingerprint.

    Layout: <transport><version><sni><ciphercount><extcount><alpn>_<ciphers>_<exts>

    Unlike JA3, the cipher and extension lists are *sorted* before hashing, so
    the fingerprint survives clients that shuffle their ordering.
    """
    version = _JA4_VERSION.get(hello.max_version_offered, "00")
    sni_flag = "d" if hello.sni else "i"

    ciphers = [f"{c:04x}" for c in hello.cipher_suites if not is_grease(c)]
    extensions = [f"{e:04x}" for e in hello.extensions if not is_grease(e)]

    cipher_count = f"{min(len(ciphers), 99):02d}"
    ext_count = f"{min(len(extensions), 99):02d}"

    if hello.alpn:
        first = hello.alpn[0]
        alpn = f"{first[0]}{first[-1]}" if len(first) >= 2 else f"{first}{first}"
    else:
        alpn = "00"

    # SNI and ALPN are excluded from the extension hash: they are already
    # represented in the prefix, and including them would make the hash vary
    # with the destination rather than with the client.
    hashable_exts = sorted(e for e in extensions if e not in ("0000", "0010"))

    prefix = f"{transport}{version}{sni_flag}{cipher_count}{ext_count}{alpn}"
    cipher_hash = _truncated_sha256(sorted(ciphers))

    sig_algs = [f"{s:04x}" for s in hello.signature_algorithms if not is_grease(s)]
    ext_hash = _truncated_sha256(hashable_exts + sig_algs if sig_algs else hashable_exts)

    return f"{prefix}_{cipher_hash}_{ext_hash}"


def ja4s(hello: ServerHello, *, transport: str = "t") -> str:
    """JA4S server fingerprint: <transport><version><extcount><alpn>_<cipher>_<exts>"""
    version = _JA4_VERSION.get(hello.negotiated_version, "00")
    extensions = [f"{e:04x}" for e in hello.extensions if not is_grease(e)]
    ext_count = f"{min(len(extensions), 99):02d}"
    alpn = "00"
    if hello.alpn:
        alpn = (
            f"{hello.alpn[0]}{hello.alpn[-1]}" if len(hello.alpn) >= 2
            else f"{hello.alpn}{hello.alpn}"
        )
    cipher = f"{hello.cipher_suite:04x}"
    return f"{transport}{version}{ext_count}{alpn}_{cipher}_{_truncated_sha256(sorted(extensions))}"
