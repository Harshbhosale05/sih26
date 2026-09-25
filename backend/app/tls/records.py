"""TLS record-layer detection.

Phase 1 scope: answer "did a TLS handshake start here, and did it get far
enough to look established?" Version, cipher suite, groups and certificates are
Phase 2 -- this module deliberately stops at the record header.

Note on "established": passively, we can never see a TLS 1.3 Finished message
(it is encrypted). The strongest honest signal is ServerHello followed by
application data flowing in both directions. We report that as
TLS_ESTABLISHED, and anything weaker stays UNKNOWN rather than being upgraded
to a pass.
"""

from __future__ import annotations

from dataclasses import dataclass

CONTENT_CHANGE_CIPHER_SPEC = 0x14
CONTENT_ALERT = 0x15
CONTENT_HANDSHAKE = 0x16
CONTENT_APPLICATION_DATA = 0x17

HANDSHAKE_CLIENT_HELLO = 0x01
HANDSHAKE_SERVER_HELLO = 0x02
HANDSHAKE_CERTIFICATE = 0x0B

_VALID_CONTENT_TYPES = {
    CONTENT_CHANGE_CIPHER_SPEC,
    CONTENT_ALERT,
    CONTENT_HANDSHAKE,
    CONTENT_APPLICATION_DATA,
}

# Legal record-layer versions. Anything else means this is not TLS.
_VALID_VERSIONS = {0x0300, 0x0301, 0x0302, 0x0303, 0x0304}


@dataclass(frozen=True)
class TLSRecord:
    content_type: int
    version: int
    length: int
    offset: int
    handshake_type: int | None = None

    @property
    def is_client_hello(self) -> bool:
        return (
            self.content_type == CONTENT_HANDSHAKE
            and self.handshake_type == HANDSHAKE_CLIENT_HELLO
        )

    @property
    def is_server_hello(self) -> bool:
        return (
            self.content_type == CONTENT_HANDSHAKE
            and self.handshake_type == HANDSHAKE_SERVER_HELLO
        )

    @property
    def is_application_data(self) -> bool:
        return self.content_type == CONTENT_APPLICATION_DATA

    @property
    def is_alert(self) -> bool:
        return self.content_type == CONTENT_ALERT


def looks_like_tls(data: bytes, offset: int = 0) -> bool:
    """Cheap check that `data` at `offset` starts a plausible TLS record."""
    if len(data) - offset < 5:
        return False
    content_type = data[offset]
    version = int.from_bytes(data[offset + 1 : offset + 3], "big")
    length = int.from_bytes(data[offset + 3 : offset + 5], "big")
    return (
        content_type in _VALID_CONTENT_TYPES
        and version in _VALID_VERSIONS
        # RFC 8446: records are at most 2^14 + 256 bytes.
        and 0 < length <= 0x4200
    )


def parse_records(data: bytes, start: int = 0, limit: int = 64) -> list[TLSRecord]:
    """Walk the record layer from `start`.

    Stops at the first thing that is not a valid record header -- in a
    passively captured session that usually means we have reached encrypted
    data whose framing we can still see but whose content we cannot. Bounded by
    `limit` because after the handshake every remaining record is opaque and
    enumerating thousands of them tells us nothing.
    """
    records: list[TLSRecord] = []
    offset = start

    while offset + 5 <= len(data) and len(records) < limit:
        if not looks_like_tls(data, offset):
            break

        content_type = data[offset]
        version = int.from_bytes(data[offset + 1 : offset + 3], "big")
        length = int.from_bytes(data[offset + 3 : offset + 5], "big")
        body_start = offset + 5

        handshake_type = None
        if content_type == CONTENT_HANDSHAKE and body_start < len(data):
            handshake_type = data[body_start]

        records.append(
            TLSRecord(
                content_type=content_type,
                version=version,
                length=length,
                offset=offset,
                handshake_type=handshake_type,
            )
        )
        offset = body_start + length

    return records


def find_tls_start(data: bytes) -> int | None:
    """Offset where TLS begins, or None.

    For implicit TLS this is 0. After STARTTLS it is wherever the plaintext
    dialogue ended, which the caller does not have to compute -- we scan for the
    first valid ClientHello-shaped record.
    """
    if looks_like_tls(data, 0):
        return 0

    # Scan for a handshake record header. Bounded: the upgrade happens early or
    # not at all, and scanning megabytes of mail body for a false positive is
    # both slow and wrong.
    horizon = min(len(data), 65536)
    for offset in range(horizon - 5):
        if data[offset] != CONTENT_HANDSHAKE:
            continue
        if looks_like_tls(data, offset) and offset + 5 < len(data):
            if data[offset + 5] in (HANDSHAKE_CLIENT_HELLO, HANDSHAKE_SERVER_HELLO):
                return offset
    return None
