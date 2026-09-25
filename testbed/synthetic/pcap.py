"""Minimal pcap writer and Ethernet/IPv4/TCP packet builder.

Why hand-build packets instead of capturing real traffic?

For the plaintext phase of email protocols -- the part that actually carries our
highest-value findings (STARTTLS stripping, cleartext AUTH, capability
mangling) -- synthesising the bytes is strictly better than capturing them:

  * Ground truth is exact. We know which frame carries the mangled capability
    line, so tests assert on frame numbers, not on "something around here".
  * No root, no Docker, no network namespace. Runs in CI.
  * Deterministic. The same scenario produces a byte-identical file every run,
    so a changed sha256 means a changed generator, not a changed capture.

Real TLS handshakes and real certificates cannot be faked this way -- those come
from the Docker testbed (tier 2).

Format: classic libpcap, little-endian, microsecond precision, LINKTYPE_ETHERNET.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

PCAP_MAGIC_LE_USEC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1
DEFAULT_SNAPLEN = 262144

ETHERTYPE_IPV4 = 0x0800
IPPROTO_TCP = 6
IPPROTO_UDP = 17

# TCP flags
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10


def _checksum(data: bytes) -> int:
    """Standard internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def mac_for_ip(ip: str) -> bytes:
    """Derive a stable, locally-administered MAC from an IP.

    Deterministic so regenerating a scenario yields identical bytes.
    """
    octets = [int(o) for o in ip.split(".")]
    return bytes([0x02, 0x00, *octets])


def _ip_to_bytes(ip: str) -> bytes:
    return bytes(int(o) for o in ip.split("."))


def build_ethernet(src_ip: str, dst_ip: str, payload: bytes) -> bytes:
    return (
        mac_for_ip(dst_ip)
        + mac_for_ip(src_ip)
        + struct.pack("!H", ETHERTYPE_IPV4)
        + payload
    )


def build_ipv4(
    src_ip: str, dst_ip: str, payload: bytes, ident: int, proto: int = IPPROTO_TCP
) -> bytes:
    total_length = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,             # version 4, IHL 5
        0x00,             # DSCP/ECN
        total_length,
        ident & 0xFFFF,
        0x4000,           # Don't Fragment
        64,               # TTL
        proto,
        0,                # checksum placeholder
        _ip_to_bytes(src_ip),
        _ip_to_bytes(dst_ip),
    )
    checksum = _checksum(header)
    header = header[:10] + struct.pack("!H", checksum) + header[12:]
    return header + payload


def build_tcp(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes,
    window: int = 64240,
) -> bytes:
    header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        0x50,             # data offset 5 words, no options
        flags,
        window,
        0,                # checksum placeholder
        0,                # urgent pointer
    )
    segment = header + payload

    pseudo = (
        _ip_to_bytes(src_ip)
        + _ip_to_bytes(dst_ip)
        + struct.pack("!BBH", 0, IPPROTO_TCP, len(segment))
    )
    checksum = _checksum(pseudo + segment)
    header = header[:16] + struct.pack("!H", checksum) + header[18:]
    return header + payload


@dataclass
class Packet:
    timestamp: float
    data: bytes
    # Populated by PcapWriter so scenario metadata can cite frame numbers --
    # this is what makes evidence links testable end to end.
    frame_number: int = 0


@dataclass
class PcapWriter:
    """Accumulates frames and writes a libpcap file.

    Frames are sorted by timestamp on write so multiple interleaved
    conversations produce a realistic capture.
    """

    snaplen: int = DEFAULT_SNAPLEN
    packets: list[Packet] = field(default_factory=list)

    def add(self, timestamp: float, data: bytes) -> Packet:
        pkt = Packet(timestamp=timestamp, data=data)
        self.packets.append(pkt)
        return pkt

    def write(self, path: Path, *, truncate_after: int | None = None) -> int:
        """Write the pcap file. Returns the number of frames written.

        `truncate_after` stops writing mid-file, which is how we build the
        "incomplete evidence" scenario: a capture that ends in the middle of a
        session, exactly as a real one would if the analyst stopped tcpdump.
        """
        ordered = sorted(self.packets, key=lambda p: p.timestamp)
        for index, pkt in enumerate(ordered, start=1):
            pkt.frame_number = index

        if truncate_after is not None:
            ordered = ordered[:truncate_after]

        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as fh:
            fh.write(
                struct.pack(
                    "<IHHiIII",
                    PCAP_MAGIC_LE_USEC,
                    2,                 # version major
                    4,                 # version minor
                    0,                 # thiszone (UTC)
                    0,                 # sigfigs
                    self.snaplen,
                    LINKTYPE_ETHERNET,
                )
            )
            for pkt in ordered:
                seconds = int(pkt.timestamp)
                micros = int(round((pkt.timestamp - seconds) * 1_000_000))
                if micros >= 1_000_000:  # rounding can carry
                    seconds += 1
                    micros -= 1_000_000
                captured = pkt.data[: self.snaplen]
                fh.write(
                    struct.pack(
                        "<IIII", seconds, micros, len(captured), len(pkt.data)
                    )
                )
                fh.write(captured)

        return len(ordered)


def build_udp(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes
) -> bytes:
    """UDP datagram with a correct checksum.

    Needed for DNS: the queries that preceded an SMTP connection are in the same
    capture, and correlating them with what the session then did is where the
    MTA-STS and DANE policy findings come from.
    """
    length = 8 + len(payload)
    header = struct.pack("!HHHH", src_port, dst_port, length, 0)
    pseudo = (
        _ip_to_bytes(src_ip)
        + _ip_to_bytes(dst_ip)
        + struct.pack("!BBH", 0, IPPROTO_UDP, length)
    )
    checksum = _checksum(pseudo + header + payload)
    # A zero checksum means "not computed" in UDP, so 0 is sent as 0xFFFF.
    header = struct.pack("!HHHH", src_port, dst_port, length, checksum or 0xFFFF)
    return header + payload
