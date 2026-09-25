"""TCP conversation builder: turns a scripted dialogue into real frames.

Maintains sequence/acknowledgement state for both directions so the resulting
capture reassembles correctly in Wireshark, tshark and our own pipeline. If
these numbers are wrong the capture still *opens*, but stream reassembly
silently produces garbage -- which would make our own test fixtures lie to us.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from testbed.synthetic.pcap import (
    ACK,
    FIN,
    PSH,
    SYN,
    Packet,
    PcapWriter,
    build_ethernet,
    build_ipv4,
    build_tcp,
)

CRLF = b"\r\n"


@dataclass
class Endpoint:
    ip: str
    port: int
    seq: int
    ip_id: int = 1

    def next_ip_id(self) -> int:
        self.ip_id += 1
        return self.ip_id


@dataclass
class TCPConversation:
    """One client<->server TCP connection, scripted line by line.

    `emit_*` helpers append frames to the shared PcapWriter. Frame objects are
    returned so scenario code can record which frames carry the evidence for a
    given finding.
    """

    writer: PcapWriter
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    start_time: float
    rtt: float = 0.0008
    client_seq: int = 1000
    server_seq: int = 5000

    clock: float = field(init=False)
    client: Endpoint = field(init=False)
    server: Endpoint = field(init=False)
    frames: list[Packet] = field(init=False, default_factory=list)

    def __post_init__(self) -> None:
        self.clock = self.start_time
        self.client = Endpoint(self.client_ip, self.client_port, self.client_seq)
        self.server = Endpoint(self.server_ip, self.server_port, self.server_seq)

    # -- internals --------------------------------------------------------

    def _tick(self, delta: float | None = None) -> float:
        self.clock += self.rtt if delta is None else delta
        return self.clock

    def _emit(
        self,
        src: Endpoint,
        dst: Endpoint,
        flags: int,
        payload: bytes = b"",
        delta: float | None = None,
    ) -> Packet:
        timestamp = self._tick(delta)
        tcp = build_tcp(
            src.ip,
            dst.ip,
            src.port,
            dst.port,
            seq=src.seq,
            ack=dst.seq,
            flags=flags,
            payload=payload,
        )
        ip = build_ipv4(src.ip, dst.ip, tcp, src.next_ip_id())
        frame = build_ethernet(src.ip, dst.ip, ip)

        # SYN and FIN each consume one sequence number.
        consumed = len(payload) + (1 if flags & (SYN | FIN) else 0)
        src.seq = (src.seq + consumed) & 0xFFFFFFFF

        pkt = self.writer.add(timestamp, frame)
        self.frames.append(pkt)
        return pkt

    # -- handshake / teardown ---------------------------------------------

    def open(self) -> list[Packet]:
        """Three-way handshake."""
        syn = self._emit(self.client, self.server, SYN, delta=0.0)
        synack = self._emit(self.server, self.client, SYN | ACK)
        ack = self._emit(self.client, self.server, ACK)
        return [syn, synack, ack]

    def close(self) -> list[Packet]:
        """Graceful four-way teardown."""
        fin1 = self._emit(self.client, self.server, FIN | ACK)
        ack1 = self._emit(self.server, self.client, ACK)
        fin2 = self._emit(self.server, self.client, FIN | ACK)
        ack2 = self._emit(self.client, self.server, ACK)
        return [fin1, ack1, fin2, ack2]

    # -- application data --------------------------------------------------

    def client_says(self, text: str | bytes, delta: float | None = None) -> Packet:
        """One client line, plus the server's bare ACK."""
        payload = _as_line(text)
        pkt = self._emit(self.client, self.server, PSH | ACK, payload, delta=delta)
        self._emit(self.server, self.client, ACK)
        return pkt

    def server_says(self, text: str | bytes, delta: float | None = None) -> Packet:
        payload = _as_line(text)
        pkt = self._emit(self.server, self.client, PSH | ACK, payload, delta=delta)
        self._emit(self.client, self.server, ACK)
        return pkt

    def server_says_multi(self, lines: list[str], delta: float | None = None) -> Packet:
        """Multi-line reply sent as a single segment.

        Real multi-line SMTP replies (the EHLO capability list) arrive in one
        TCP segment. Keeping that true matters: our capability-stripping
        detector inspects the segment as a unit.
        """
        payload = b"".join(_as_line(line) for line in lines)
        pkt = self._emit(self.server, self.client, PSH | ACK, payload, delta=delta)
        self._emit(self.client, self.server, ACK)
        return pkt

    def client_raw(self, data: bytes, delta: float | None = None) -> Packet:
        """Opaque client bytes -- used for TLS records."""
        pkt = self._emit(self.client, self.server, PSH | ACK, data, delta=delta)
        self._emit(self.server, self.client, ACK)
        return pkt

    def server_raw(self, data: bytes, delta: float | None = None) -> Packet:
        pkt = self._emit(self.server, self.client, PSH | ACK, data, delta=delta)
        self._emit(self.client, self.server, ACK)
        return pkt

    def split_client_says(self, text: str, at: int, delta: float | None = None) -> list[Packet]:
        """Send one command split across two segments.

        Exercises the reassembly requirement directly: a pipeline that reads
        packets instead of streams will see "STAR" and "TTLS" and miss the
        command entirely.
        """
        payload = _as_line(text)
        first = self._emit(self.client, self.server, ACK, payload[:at], delta=delta)
        self._emit(self.server, self.client, ACK)
        second = self._emit(self.client, self.server, PSH | ACK, payload[at:])
        self._emit(self.server, self.client, ACK)
        return [first, second]


def _as_line(text: str | bytes) -> bytes:
    if isinstance(text, bytes):
        return text
    return text.encode("utf-8") + CRLF
