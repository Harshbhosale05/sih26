"""ClientHello / ServerHello parsing.

The single most important correctness rule in this file:

    In TLS 1.3 the negotiated version is NOT the legacy_version field.

RFC 8446 pins legacy_version to 0x0303 (TLS 1.2) for middlebox compatibility
and carries the real version in the `supported_versions` extension. A parser
that reads the legacy field reports every TLS 1.3 session as TLS 1.2 -- which
would silently understate the posture of the most modern infrastructure we
analyse. `17-segmented-starttls` and the TLS 1.3 scenarios exist to catch that.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from app.tls.groups import GROUP_NAMES, PQC_HYBRID_GROUPS, is_grease

EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_KEY_SHARE = 0x0033
EXT_ENCRYPTED_CLIENT_HELLO = 0xFE0D

VERSION_NAMES = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

SNI_PRESENT = "present"
SNI_ABSENT = "absent"
SNI_ENCRYPTED = "encrypted_ech"


@dataclass
class ClientHello:
    legacy_version: int = 0
    versions_offered: list[int] = field(default_factory=list)
    cipher_suites: list[int] = field(default_factory=list)
    extensions: list[int] = field(default_factory=list)
    supported_groups: list[int] = field(default_factory=list)
    signature_algorithms: list[int] = field(default_factory=list)
    ec_point_formats: list[int] = field(default_factory=list)
    key_share_groups: list[int] = field(default_factory=list)
    alpn: list[str] = field(default_factory=list)
    sni: str | None = None
    sni_status: str = SNI_ABSENT

    @property
    def max_version_offered(self) -> int:
        candidates = self.versions_offered or [self.legacy_version]
        return max(candidates) if candidates else 0

    @property
    def pqc_groups_offered(self) -> list[int]:
        return [g for g in self.supported_groups if g in PQC_HYBRID_GROUPS]


@dataclass
class ServerHello:
    legacy_version: int = 0
    negotiated_version: int = 0
    cipher_suite: int = 0
    extensions: list[int] = field(default_factory=list)
    selected_group: int | None = None
    alpn: str | None = None


class _Reader:
    """Bounds-checked sequential reader.

    Every read is length-checked. Handshake bytes here come from a capture and
    may be truncated, malformed, or hostile; an IndexError in a dissector is a
    crash in the analysis pipeline.
    """

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.pos

    def take(self, n: int) -> bytes:
        if n < 0 or self.remaining < n:
            raise ValueError("truncated handshake message")
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("!H", self.take(2))[0]

    def u24(self) -> int:
        return int.from_bytes(self.take(3), "big")

    def vector(self, length_bytes: int) -> bytes:
        if length_bytes == 1:
            return self.take(self.u8())
        if length_bytes == 2:
            return self.take(self.u16())
        return self.take(self.u24())


def _u16_list(data: bytes, *, drop_grease: bool = True) -> list[int]:
    values = [
        struct.unpack("!H", data[i : i + 2])[0] for i in range(0, len(data) - 1, 2)
    ]
    return [v for v in values if not (drop_grease and is_grease(v))]


def _parse_extensions(reader: _Reader) -> dict[int, bytes]:
    """Return extensions in wire order. Order matters for fingerprinting."""
    out: dict[int, bytes] = {}
    if reader.remaining < 2:
        return out
    try:
        block = _Reader(reader.vector(2))
    except ValueError:
        return out

    while block.remaining >= 4:
        try:
            ext_type = block.u16()
            body = block.vector(2)
        except ValueError:
            break
        out[ext_type] = body
    return out


def parse_client_hello(record_body: bytes) -> ClientHello | None:
    """Parse a ClientHello handshake message body (after the record header)."""
    try:
        reader = _Reader(record_body)
        if reader.u8() != 0x01:  # handshake type
            return None
        reader.u24()  # message length
        hello = ClientHello()
        hello.legacy_version = reader.u16()
        reader.take(32)  # random
        reader.vector(1)  # legacy_session_id

        hello.cipher_suites = _u16_list(reader.vector(2))
        reader.vector(1)  # compression methods

        extensions = _parse_extensions(reader)
    except (ValueError, struct.error, IndexError):
        return None

    hello.extensions = [e for e in extensions if not is_grease(e)]

    if EXT_SUPPORTED_GROUPS in extensions:
        body = extensions[EXT_SUPPORTED_GROUPS]
        hello.supported_groups = _u16_list(body[2:]) if len(body) >= 2 else []

    if EXT_SIGNATURE_ALGORITHMS in extensions:
        body = extensions[EXT_SIGNATURE_ALGORITHMS]
        hello.signature_algorithms = _u16_list(body[2:]) if len(body) >= 2 else []

    if EXT_EC_POINT_FORMATS in extensions:
        body = extensions[EXT_EC_POINT_FORMATS]
        hello.ec_point_formats = list(body[1:]) if body else []

    if EXT_SUPPORTED_VERSIONS in extensions:
        body = extensions[EXT_SUPPORTED_VERSIONS]
        # Client form: 1-byte length prefix, then a version list.
        hello.versions_offered = _u16_list(body[1:]) if body else []

    if EXT_KEY_SHARE in extensions:
        hello.key_share_groups = _parse_key_share_client(extensions[EXT_KEY_SHARE])

    if EXT_ALPN in extensions:
        hello.alpn = _parse_alpn(extensions[EXT_ALPN])

    if EXT_ENCRYPTED_CLIENT_HELLO in extensions:
        # ECH conceals the true SNI. Reporting "no SNI" here would be wrong and
        # would misattribute sessions to the wrong server.
        hello.sni_status = SNI_ENCRYPTED
    elif EXT_SERVER_NAME in extensions:
        hello.sni = _parse_sni(extensions[EXT_SERVER_NAME])
        hello.sni_status = SNI_PRESENT if hello.sni else SNI_ABSENT

    return hello


def parse_server_hello(record_body: bytes) -> ServerHello | None:
    try:
        reader = _Reader(record_body)
        if reader.u8() != 0x02:
            return None
        reader.u24()
        hello = ServerHello()
        hello.legacy_version = reader.u16()
        reader.take(32)
        reader.vector(1)
        hello.cipher_suite = reader.u16()
        reader.u8()  # compression method
        extensions = _parse_extensions(reader)
    except (ValueError, struct.error, IndexError):
        return None

    hello.extensions = [e for e in extensions if not is_grease(e)]

    # THE rule: prefer supported_versions over legacy_version.
    negotiated = hello.legacy_version
    if EXT_SUPPORTED_VERSIONS in extensions:
        body = extensions[EXT_SUPPORTED_VERSIONS]
        if len(body) >= 2:
            negotiated = struct.unpack("!H", body[:2])[0]
    hello.negotiated_version = negotiated

    if EXT_KEY_SHARE in extensions:
        body = extensions[EXT_KEY_SHARE]
        if len(body) >= 2:
            group = struct.unpack("!H", body[:2])[0]
            hello.selected_group = None if is_grease(group) else group

    if EXT_ALPN in extensions:
        protocols = _parse_alpn(extensions[EXT_ALPN])
        hello.alpn = protocols[0] if protocols else None

    return hello


def _parse_sni(body: bytes) -> str | None:
    """Extract the host_name entry from a server_name extension.

    SNI is always ASCII on the wire -- internationalised names travel as
    punycode. Decoding with the `idna` codec directly is a trap: Python's idna
    codec raises on any `errors` value other than "strict", so a permissive
    decode silently throws and the SNI is lost.
    """
    try:
        reader = _Reader(body)
        entries = _Reader(reader.vector(2))
        while entries.remaining >= 3:
            name_type = entries.u8()
            name = entries.vector(2)
            if name_type != 0x00 or not name:
                continue

            host = name.decode("ascii", errors="replace")
            if "xn--" in host:
                # Present the unicode form for display, keeping punycode if it
                # fails to decode rather than dropping the name entirely.
                try:
                    return name.decode("idna")
                except (UnicodeError, ValueError):
                    return host
            return host
    except ValueError:
        return None
    return None


def _parse_alpn(body: bytes) -> list[str]:
    protocols: list[str] = []
    try:
        reader = _Reader(body)
        entries = _Reader(reader.vector(2))
        while entries.remaining >= 1:
            protocols.append(entries.vector(1).decode("ascii", errors="replace"))
    except ValueError:
        pass
    return protocols


def _parse_key_share_client(body: bytes) -> list[int]:
    groups: list[int] = []
    try:
        reader = _Reader(body)
        entries = _Reader(reader.vector(2))
        while entries.remaining >= 4:
            group = entries.u16()
            entries.vector(2)  # key exchange bytes
            if not is_grease(group):
                groups.append(group)
    except ValueError:
        pass
    return groups


def version_name(version: int) -> str:
    return VERSION_NAMES.get(version, f"unknown (0x{version:04X})")


def group_name(group: int | None) -> str | None:
    if group is None:
        return None
    return GROUP_NAMES.get(group, f"unknown (0x{group:04X})")
