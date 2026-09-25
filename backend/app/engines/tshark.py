"""TShark invocations for the two-pass pipeline.

Pass 1 indexes every TCP flow cheaply (no payload). Pass 2 pulls per-frame
payload bytes for candidate email flows only.

A deliberate choice in pass 2: TCP desegmentation is turned **off** and each
frame reports its own payload. We reassemble ourselves in
`app.flows.reassembler`, not because tshark's reassembly is wrong, but because
letting tshark hand us one pre-joined blob destroys the byte -> frame mapping.
Without that mapping we cannot say "the mangled capability line is in frame
182", and evidence-linked findings are the product.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.engines.base import run_tool

# Fields are positional; changing this tuple means changing the parsers below.
# ip.* and ipv6.* are both requested and coalesced: a packet populates one or
# the other. Filtering on `ip` alone silently drops every IPv6 session, which
# on a real network means dropping a large share of modern mail traffic.
_INDEX_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "tcp.stream",
    "ip.src",
    "ipv6.src",
    "tcp.srcport",
    "ip.dst",
    "ipv6.dst",
    "tcp.dstport",
    "tcp.len",
    "tcp.flags.syn",
    "tcp.flags.fin",
    "tcp.flags.reset",
)

_PAYLOAD_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "tcp.stream",
    "ip.src",
    "ipv6.src",
    "tcp.srcport",
    "ip.dst",
    "ipv6.dst",
    "tcp.dstport",
    "tcp.seq",
    "tcp.len",
    "tcp.payload",
)


@dataclass(frozen=True)
class IndexedPacket:
    frame_number: int
    timestamp: float
    stream: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    tcp_len: int
    syn: bool
    fin: bool
    rst: bool


@dataclass(frozen=True)
class PayloadSegment:
    frame_number: int
    timestamp: float
    stream: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    seq: int
    payload: bytes


def _base_argv(pcap: Path) -> list[str]:
    return [
        "tshark",
        "-r",
        str(pcap),
        "-n",                      # no DNS/port name resolution: slow and irrelevant
        "-o", "tcp.calculate_timestamps:FALSE",
    ]


def _fields_argv(fields: tuple[str, ...]) -> list[str]:
    argv = ["-T", "fields", "-E", "separator=/t", "-E", "occurrence=f"]
    for field in fields:
        argv += ["-e", field]
    return argv


def _int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _float(value: str, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _flag(value: str) -> bool:
    return value.strip() in {"1", "True", "true"}


def index_tcp_packets(pcap: Path) -> list[IndexedPacket]:
    """Pass 1: every TCP packet's envelope, no payload. IPv4 and IPv6."""
    argv = _base_argv(pcap) + ["-Y", "tcp"] + _fields_argv(_INDEX_FIELDS)
    result = run_tool(argv, check=False)

    packets: list[IndexedPacket] = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < len(_INDEX_FIELDS) or not parts[2]:
            continue

        src_ip = parts[3] or parts[4]   # ip.src, else ipv6.src
        dst_ip = parts[6] or parts[7]
        if not src_ip or not dst_ip:
            continue  # neither IPv4 nor IPv6: not something we can attribute

        packets.append(
            IndexedPacket(
                frame_number=_int(parts[0]),
                timestamp=_float(parts[1]),
                stream=_int(parts[2]),
                src_ip=src_ip,
                src_port=_int(parts[5]),
                dst_ip=dst_ip,
                dst_port=_int(parts[8]),
                tcp_len=_int(parts[9]),
                syn=_flag(parts[10]),
                fin=_flag(parts[11]),
                rst=_flag(parts[12]),
            )
        )
    return packets


def probe_stream_openings(pcap: Path, streams: list[int]) -> dict[int, bytes]:
    """Cheaply fetch the first data segment of each given stream.

    This is how mail on a non-standard port gets found. Selecting candidates by
    port alone misses exactly the misconfiguration a posture assessment should
    be reporting -- an SMTP server listening somewhere unexpected.

    `tcp.seq == 1` selects the first data byte of each direction under
    tshark's relative sequence numbering, so this reads a handful of frames
    rather than every payload in the capture.
    """
    if not streams:
        return {}

    stream_filter = "tcp.stream in {" + ", ".join(str(s) for s in sorted(streams)) + "}"
    argv = (
        _base_argv(pcap)
        + [
            "-o", "tcp.desegment_tcp_streams:FALSE",
            "-Y", f"({stream_filter}) && tcp.len > 0 && tcp.seq == 1",
        ]
        + _fields_argv(("tcp.stream", "tcp.srcport", "tcp.payload"))
    )
    result = run_tool(argv, check=False)

    openings: dict[int, bytes] = {}
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 3 or not parts[0]:
            continue
        raw_hex = parts[2].replace(":", "").strip()
        if not raw_hex:
            continue
        try:
            payload = bytes.fromhex(raw_hex)
        except ValueError:
            continue
        stream = _int(parts[0])
        # Keep the first opening seen per stream; the server greeting in these
        # protocols always precedes the client's first command.
        openings.setdefault(stream, payload)
    return openings


def extract_payloads(pcap: Path, streams: list[int]) -> dict[int, list[PayloadSegment]]:
    """Pass 2: per-frame payload bytes for the given TCP streams.

    Returns segments grouped by stream, in capture order. Ordering by sequence
    number and dropping retransmissions happens in the reassembler.
    """
    if not streams:
        return {}

    # tshark's membership operator keeps the filter short even for many streams.
    # Wireshark 4.x requires comma-separated set elements; space-separated was
    # accepted by 3.x and is a silent filter-parse error on 4.x.
    stream_filter = "tcp.stream in {" + ", ".join(str(s) for s in sorted(streams)) + "}"
    argv = (
        _base_argv(pcap)
        + [
            # Off so each frame reports its own bytes and the byte -> frame
            # mapping survives. See module docstring.
            "-o", "tcp.desegment_tcp_streams:FALSE",
            "-Y", f"({stream_filter}) && tcp.len > 0",
        ]
        + _fields_argv(_PAYLOAD_FIELDS)
    )
    result = run_tool(argv, check=False)

    grouped: dict[int, list[PayloadSegment]] = {}
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < len(_PAYLOAD_FIELDS) or not parts[2]:
            continue

        # tshark renders byte fields as hex, sometimes colon-separated.
        raw_hex = parts[11].replace(":", "").strip()
        if not raw_hex:
            continue
        try:
            payload = bytes.fromhex(raw_hex)
        except ValueError:
            continue

        src_ip = parts[3] or parts[4]
        dst_ip = parts[6] or parts[7]
        if not src_ip or not dst_ip:
            continue

        segment = PayloadSegment(
            frame_number=_int(parts[0]),
            timestamp=_float(parts[1]),
            stream=_int(parts[2]),
            src_ip=src_ip,
            src_port=_int(parts[5]),
            dst_ip=dst_ip,
            dst_port=_int(parts[8]),
            seq=_int(parts[9]),
            payload=payload,
        )
        grouped.setdefault(segment.stream, []).append(segment)

    return grouped


@dataclass(frozen=True)
class DNSRecord:
    frame_number: int
    timestamp: float
    is_response: bool
    qname: str
    qtype: int
    rcode: int
    txt: list[str]
    mx: list[str]
    addresses: list[str]
    answer_count: int


def extract_dns(pcap: Path) -> list[DNSRecord]:
    """Pull every DNS message from the capture.

    A capture of real mail traffic contains the lookups that preceded the SMTP
    connections. Correlating those against what the sessions then did is what
    turns "TLS was not used" into "the sender fetched an MTA-STS policy in
    enforce mode and sent in cleartext anyway" -- a policy violation proven
    from a single capture.
    """
    fields = (
        "frame.number",
        "frame.time_epoch",
        "dns.flags.response",
        "dns.qry.name",
        "dns.qry.type",
        "dns.flags.rcode",
        "dns.txt",
        "dns.mx.mail_exchange",
        "dns.a",
        "dns.count.answers",
    )
    argv = (
        _base_argv(pcap)
        + ["-Y", "dns"]
        + ["-T", "fields", "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,"]
    )
    for field in fields:
        argv += ["-e", field]

    result = run_tool(argv, check=False)

    def split(value: str) -> list[str]:
        return [v for v in value.split(",") if v] if value else []

    records: list[DNSRecord] = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < len(fields) or not parts[3]:
            continue
        records.append(
            DNSRecord(
                frame_number=_int(parts[0].split(",")[0]),
                timestamp=_float(parts[1].split(",")[0]),
                is_response=_flag(parts[2].split(",")[0]),
                qname=parts[3].split(",")[0].lower().rstrip("."),
                qtype=_int(parts[4].split(",")[0]),
                rcode=_int(parts[5].split(",")[0]),
                txt=split(parts[6]),
                mx=split(parts[7]),
                addresses=split(parts[8]),
                answer_count=_int(parts[9].split(",")[0]),
            )
        )
    return records
