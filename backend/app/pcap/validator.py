"""Container-format validation by magic bytes.

We never trust the uploaded filename or the client-supplied Content-Type to
decide what a file is. The first bytes on disk decide, and anything we do not
recognise is rejected before it ever reaches a dissector.
"""

from __future__ import annotations

import gzip
from dataclasses import dataclass
from pathlib import Path


class InvalidCaptureFile(ValueError):
    """The uploaded file is not a capture container we accept."""


# libpcap: the four byte orders / timestamp precisions in the wild.
_PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4": "pcap (big-endian, microsecond)",
    b"\xd4\xc3\xb2\xa1": "pcap (little-endian, microsecond)",
    b"\xa1\xb2\x3c\x4d": "pcap (big-endian, nanosecond)",
    b"\x4d\x3c\xb2\xa1": "pcap (little-endian, nanosecond)",
}

# pcapng always opens with a Section Header Block whose type is 0x0A0D0D0A.
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

_GZIP_MAGIC = b"\x1f\x8b"


@dataclass(frozen=True)
class ContainerInfo:
    container_format: str
    is_compressed: bool


def _classify(header: bytes) -> str | None:
    if header[:4] in _PCAP_MAGICS:
        return "pcap"
    if header[:4] == _PCAPNG_MAGIC:
        return "pcapng"
    return None


def detect_container(path: Path) -> ContainerInfo:
    """Identify the capture container, transparently seeing through gzip.

    Wireshark reads gzipped captures natively, so we keep the file compressed
    on disk -- the sha256 in the evidence manifest is of the bytes the user
    actually uploaded, and decompressing would break that correspondence.
    """
    with path.open("rb") as fh:
        header = fh.read(8)

    if len(header) < 4:
        raise InvalidCaptureFile("File is too small to be a packet capture.")

    if header[:2] == _GZIP_MAGIC:
        try:
            with gzip.open(path, "rb") as gz:
                inner = gz.read(8)
        except OSError as exc:
            raise InvalidCaptureFile(f"File is gzip-framed but unreadable: {exc}") from exc

        fmt = _classify(inner)
        if fmt is None:
            raise InvalidCaptureFile(
                "Gzip archive does not contain a pcap or pcapng capture."
            )
        return ContainerInfo(container_format=fmt, is_compressed=True)

    fmt = _classify(header)
    if fmt is None:
        raise InvalidCaptureFile(
            "Not a packet capture: expected pcap or pcapng magic bytes. "
            f"Got {header[:4].hex()}."
        )
    return ContainerInfo(container_format=fmt, is_compressed=False)


def safe_extension(filename: str, container: ContainerInfo) -> str:
    """Return the on-disk extension, derived from content rather than input.

    The uploaded filename never touches the filesystem -- it is stored in the
    database as metadata only. This removes path traversal and shell
    metacharacter concerns entirely rather than trying to sanitise them.
    """
    base = ".pcapng" if container.container_format == "pcapng" else ".pcap"
    return f"{base}.gz" if container.is_compressed else base
