"""Minimal but structurally real TLS handshake message builder.

These are genuine wire-format ClientHello / ServerHello messages -- Wireshark
dissects them, and our own parser can extract version, cipher suite, groups,
SNI and compute JA3/JA4 from them. They are not cryptographically functional
(no real key exchange, no Finished), which does not matter: passive analysis
reads the handshake, it never completes one.

What this covers: negotiated version, cipher suite, supported groups, PQC group
offers, SNI, extension ordering.
What it cannot cover: real certificates and real key exchange -- those come
from the Docker testbed (tier 2).
"""

from __future__ import annotations

import struct

# --- Protocol versions ---------------------------------------------------
TLS1_0 = 0x0301
TLS1_1 = 0x0302
TLS1_2 = 0x0303
TLS1_3 = 0x0304

VERSION_NAMES = {
    TLS1_0: "TLS 1.0",
    TLS1_1: "TLS 1.1",
    TLS1_2: "TLS 1.2",
    TLS1_3: "TLS 1.3",
}

# --- Cipher suites -------------------------------------------------------
# TLS 1.3 suites: AEAD + hash only; key exchange is negotiated separately.
TLS_AES_128_GCM_SHA256 = 0x1301
TLS_AES_256_GCM_SHA384 = 0x1302
TLS_CHACHA20_POLY1305_SHA256 = 0x1303

# TLS 1.2 suites with forward secrecy.
TLS_ECDHE_RSA_AES_128_GCM_SHA256 = 0xC02F
TLS_ECDHE_RSA_AES_256_GCM_SHA384 = 0xC030
TLS_ECDHE_RSA_AES_128_CBC_SHA256 = 0xC027

# TLS 1.2 suites WITHOUT forward secrecy (static RSA key exchange).
TLS_RSA_AES_128_CBC_SHA = 0x002F
TLS_RSA_AES_256_CBC_SHA = 0x0035

# Legacy / weak.
TLS_RSA_3DES_EDE_CBC_SHA = 0x000A
TLS_RSA_RC4_128_SHA = 0x0005

# --- Supported groups ----------------------------------------------------
GROUP_SECP256R1 = 0x0017
GROUP_SECP384R1 = 0x0018
GROUP_X25519 = 0x001D
# Hybrid post-quantum key exchange, standardised codepoint. Seeing this offered
# in a ClientHello is exactly what the PQC readiness module reports on.
GROUP_X25519MLKEM768 = 0x11EC
# Earlier draft hybrid, still present in older deployed clients.
GROUP_X25519KYBER768_DRAFT00 = 0x6399

PQC_HYBRID_GROUPS = {GROUP_X25519MLKEM768, GROUP_X25519KYBER768_DRAFT00}

GROUP_NAMES = {
    GROUP_SECP256R1: "secp256r1",
    GROUP_SECP384R1: "secp384r1",
    GROUP_X25519: "x25519",
    GROUP_X25519MLKEM768: "X25519MLKEM768",
    GROUP_X25519KYBER768_DRAFT00: "X25519Kyber768Draft00",
}

# --- Extension types -----------------------------------------------------
EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_KEY_SHARE = 0x0033

CONTENT_TYPE_HANDSHAKE = 0x16
CONTENT_TYPE_APPLICATION_DATA = 0x17

HANDSHAKE_CLIENT_HELLO = 0x01
HANDSHAKE_SERVER_HELLO = 0x02
HANDSHAKE_CERTIFICATE = 0x0B


def _deterministic_random(seed: int) -> bytes:
    """32 bytes of filler for the Hello random field.

    Deterministic so a regenerated scenario is byte-identical; a changed sha256
    then means the generator changed, not the capture.
    """
    return bytes(((seed * 37 + i * 61) % 256) for i in range(32))


def _u16_list(values: list[int]) -> bytes:
    return b"".join(struct.pack("!H", v) for v in values)


def _extension(ext_type: int, body: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(body)) + body


def _ext_server_name(hostname: str) -> bytes:
    host = hostname.encode("idna") if hostname.isascii() else hostname.encode()
    entry = struct.pack("!BH", 0x00, len(host)) + host  # name_type=host_name
    return _extension(EXT_SERVER_NAME, struct.pack("!H", len(entry)) + entry)


def _ext_supported_groups(groups: list[int]) -> bytes:
    body = _u16_list(groups)
    return _extension(EXT_SUPPORTED_GROUPS, struct.pack("!H", len(body)) + body)


def _ext_supported_versions_client(versions: list[int]) -> bytes:
    body = _u16_list(versions)
    return _extension(EXT_SUPPORTED_VERSIONS, struct.pack("!B", len(body)) + body)


def _ext_supported_versions_server(version: int) -> bytes:
    return _extension(EXT_SUPPORTED_VERSIONS, struct.pack("!H", version))


def _ext_signature_algorithms(algs: list[int]) -> bytes:
    body = _u16_list(algs)
    return _extension(EXT_SIGNATURE_ALGORITHMS, struct.pack("!H", len(body)) + body)


def _ext_key_share_client(groups: list[int]) -> bytes:
    """A key_share entry per group, with filler key material.

    Lengths are realistic per group so the extension size looks right on the
    wire; the bytes themselves are not valid public keys.
    """
    sizes = {
        GROUP_X25519: 32,
        GROUP_SECP256R1: 65,
        GROUP_SECP384R1: 97,
        GROUP_X25519MLKEM768: 1216,
        GROUP_X25519KYBER768_DRAFT00: 1216,
    }
    entries = b""
    for group in groups:
        size = sizes.get(group, 32)
        entries += struct.pack("!HH", group, size) + bytes(size)
    return _extension(EXT_KEY_SHARE, struct.pack("!H", len(entries)) + entries)


def _ext_key_share_server(group: int) -> bytes:
    sizes = {GROUP_X25519: 32, GROUP_SECP256R1: 65, GROUP_X25519MLKEM768: 1120}
    size = sizes.get(group, 32)
    return _extension(EXT_KEY_SHARE, struct.pack("!HH", group, size) + bytes(size))


def _ext_alpn(protocols: list[str]) -> bytes:
    body = b""
    for proto in protocols:
        raw = proto.encode()
        body += struct.pack("!B", len(raw)) + raw
    return _extension(EXT_ALPN, struct.pack("!H", len(body)) + body)


def _wrap_handshake(msg_type: int, body: bytes, record_version: int) -> bytes:
    handshake = struct.pack("!B", msg_type) + len(body).to_bytes(3, "big") + body
    return (
        struct.pack("!BHH", CONTENT_TYPE_HANDSHAKE, record_version, len(handshake))
        + handshake
    )


def build_client_hello(
    *,
    sni: str | None = None,
    max_version: int = TLS1_2,
    cipher_suites: list[int] | None = None,
    groups: list[int] | None = None,
    seed: int = 1,
) -> bytes:
    """Build a ClientHello record.

    For max_version >= TLS 1.3 the legacy_version field stays TLS 1.2 and the
    real version list goes in supported_versions, exactly as RFC 8446 requires.
    A parser that reads the legacy field and reports "TLS 1.2" is wrong, and
    this fixture is what catches that.
    """
    if cipher_suites is None:
        cipher_suites = [
            TLS_AES_256_GCM_SHA384,
            TLS_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_AES_128_GCM_SHA256,
        ]
    if groups is None:
        groups = [GROUP_X25519, GROUP_SECP256R1]

    legacy_version = TLS1_2 if max_version >= TLS1_2 else max_version

    body = struct.pack("!H", legacy_version)
    body += _deterministic_random(seed)
    body += struct.pack("!B", 32) + _deterministic_random(seed + 7)  # session id
    suites = _u16_list(cipher_suites)
    body += struct.pack("!H", len(suites)) + suites
    body += struct.pack("!BB", 1, 0)  # compression: null only

    extensions = b""
    if sni:
        extensions += _ext_server_name(sni)
    extensions += _ext_supported_groups(groups)
    extensions += _extension(EXT_EC_POINT_FORMATS, bytes([1, 0]))
    extensions += _ext_signature_algorithms([0x0403, 0x0804, 0x0401, 0x0503, 0x0805])
    if max_version >= TLS1_3:
        offered = [v for v in (TLS1_3, TLS1_2) if v <= max_version]
        extensions += _ext_supported_versions_client(offered)
        extensions += _ext_key_share_client(groups[:1])
    extensions += _ext_alpn(["smtp"])

    body += struct.pack("!H", len(extensions)) + extensions

    # Record-layer version is always TLS 1.0 for the first flight (middlebox
    # compatibility), regardless of what is actually being negotiated.
    return _wrap_handshake(HANDSHAKE_CLIENT_HELLO, body, TLS1_0)


def build_server_hello(
    *,
    version: int = TLS1_2,
    cipher_suite: int = TLS_ECDHE_RSA_AES_256_GCM_SHA384,
    group: int = GROUP_X25519,
    seed: int = 2,
) -> bytes:
    """Build a ServerHello record announcing the negotiated parameters."""
    legacy_version = TLS1_2 if version >= TLS1_3 else version

    body = struct.pack("!H", legacy_version)
    body += _deterministic_random(seed)
    body += struct.pack("!B", 32) + _deterministic_random(seed + 7)
    body += struct.pack("!H", cipher_suite)
    body += struct.pack("!B", 0)  # compression: null

    extensions = b""
    if version >= TLS1_3:
        extensions += _ext_supported_versions_server(version)
        extensions += _ext_key_share_server(group)
    body += struct.pack("!H", len(extensions)) + extensions

    return _wrap_handshake(HANDSHAKE_SERVER_HELLO, body, TLS1_2)


def build_application_data(size: int, version: int = TLS1_2, seed: int = 3) -> bytes:
    """An opaque application-data record.

    This is what the bulk of a real session looks like to a passive observer:
    encrypted bytes we can measure but never read. Included so our pipeline is
    forced to handle "encrypted, therefore UNKNOWN" as the normal case.
    """
    payload = bytes(((seed + i) % 256) for i in range(size))
    return struct.pack("!BHH", CONTENT_TYPE_APPLICATION_DATA, version, size) + payload


def build_certificate(chain: list[bytes], version: int = TLS1_2) -> bytes:
    """Build a Certificate handshake record carrying a real DER chain.

    Only emitted for TLS <= 1.2. In TLS 1.3 this message travels under handshake
    traffic keys and is invisible to a passive observer, which is exactly why
    certificate coverage is normally zero on modern infrastructure.

    The certificates inside are genuine X.509 -- the synthetic part is only the
    handshake framing around them.
    """
    entries = b""
    for der in chain:
        entries += len(der).to_bytes(3, "big") + der
    body = len(entries).to_bytes(3, "big") + entries
    return _wrap_handshake(HANDSHAKE_CERTIFICATE, body, version)


def load_chain(name: str) -> list[bytes]:
    """Load a committed certificate fixture chain by name."""
    from pathlib import Path

    certs_dir = Path(__file__).resolve().parents[1] / "certs"
    chain: list[bytes] = []
    index = 0
    while True:
        path = certs_dir / f"{name}-{index}.der"
        if not path.exists():
            break
        chain.append(path.read_bytes())
        index += 1
    if not chain:
        raise FileNotFoundError(
            f"No certificate fixture {name!r} in {certs_dir}. "
            "Generate them first: see testbed/certs/generate.py"
        )
    return chain
