"""Directional stream reassembly that preserves frame provenance.

We are not writing a TCP stack -- tshark already dissected and sequenced these
segments. What we add is the one thing tshark's own reassembly throws away:
a mapping from every byte in the reassembled stream back to the frame that
carried it.

That mapping is the product. "STARTTLS was mangled" is an observation;
"STARTTLS was mangled, frame 182, here is the display filter" is evidence.

Handled here: retransmissions, duplicates, out-of-order delivery, overlapping
segments, and gaps from missing packets. Gaps are recorded rather than papered
over -- a session with a hole in it must be able to say UNKNOWN.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.engines.tshark import PayloadSegment

C2S = "c2s"
S2C = "s2c"


@dataclass(frozen=True)
class Line:
    """One protocol line, with the evidence needed to point at it."""

    text: str
    raw: bytes
    offset: int
    frame_number: int
    timestamp: float
    direction: str


@dataclass
class ReassembledStream:
    """One direction of one TCP connection."""

    direction: str
    data: bytes = b""
    # (start_offset, end_offset, frame_number, timestamp), ascending by offset.
    _map: list[tuple[int, int, int, float]] = field(default_factory=list)
    gaps: list[tuple[int, int]] = field(default_factory=list)

    def frame_for_offset(self, offset: int) -> tuple[int, float]:
        """Frame number and timestamp for the byte at `offset`."""
        lo, hi = 0, len(self._map) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            start, end, frame, ts = self._map[mid]
            if offset < start:
                hi = mid - 1
            elif offset >= end:
                lo = mid + 1
            else:
                return frame, ts
        if self._map:
            _, _, frame, ts = self._map[-1]
            return frame, ts
        return 0, 0.0

    @property
    def has_gaps(self) -> bool:
        return bool(self.gaps)

    def lines(self) -> list[Line]:
        """Split into CRLF/LF-delimited lines, each carrying its frame.

        A trailing fragment with no terminator is still returned: a capture
        that stops mid-line is exactly the truncated case we must detect.
        """
        out: list[Line] = []
        offset = 0
        for raw in self.data.splitlines(keepends=True):
            stripped = raw.rstrip(b"\r\n")
            frame, ts = self.frame_for_offset(offset)
            out.append(
                Line(
                    text=stripped.decode("utf-8", errors="replace"),
                    raw=stripped,
                    offset=offset,
                    frame_number=frame,
                    timestamp=ts,
                    direction=self.direction,
                )
            )
            offset += len(raw)
        return out


def reassemble(segments: list[PayloadSegment], direction: str) -> ReassembledStream:
    """Order segments by sequence number, dropping duplicates and retransmissions."""
    stream = ReassembledStream(direction=direction)
    if not segments:
        return stream

    # Sort by sequence, then by frame so the earliest transmission of a
    # retransmitted segment wins -- that is the frame an analyst should be
    # pointed at.
    ordered = sorted(segments, key=lambda s: (s.seq, s.frame_number))

    base_seq = ordered[0].seq
    buffer = bytearray()
    mapping: list[tuple[int, int, int, float]] = []
    gaps: list[tuple[int, int]] = []
    next_seq = base_seq

    for seg in ordered:
        seg_end = seg.seq + len(seg.payload)

        if seg_end <= next_seq:
            continue  # pure retransmission of data we already have

        if seg.seq > next_seq:
            # Missing bytes. Record the hole and zero-fill so downstream offsets
            # stay aligned with sequence space; the gap list is what makes the
            # session report UNKNOWN rather than inventing continuity.
            hole = seg.seq - next_seq
            gaps.append((len(buffer), len(buffer) + hole))
            buffer.extend(b"\x00" * hole)
            next_seq = seg.seq

        # Overlapping retransmission: keep only the genuinely new tail.
        overlap = next_seq - seg.seq
        payload = seg.payload[overlap:] if overlap > 0 else seg.payload
        if not payload:
            continue

        start = len(buffer)
        buffer.extend(payload)
        mapping.append((start, len(buffer), seg.frame_number, seg.timestamp))
        next_seq = seg_end

    stream.data = bytes(buffer)
    stream._map = mapping
    stream.gaps = gaps
    return stream


@dataclass
class StreamPair:
    """Both directions of one TCP connection, plus a merged view."""

    stream_index: int
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    client_to_server: ReassembledStream
    server_to_client: ReassembledStream
    first_frame: int
    last_frame: int
    start_time: float
    end_time: float

    @property
    def has_gaps(self) -> bool:
        return self.client_to_server.has_gaps or self.server_to_client.has_gaps

    def merged_lines(self) -> list[Line]:
        """Both directions interleaved in frame order.

        Protocol state is a property of the dialogue, not of one side, so the
        state machine consumes this rather than either direction alone.
        """
        lines = self.client_to_server.lines() + self.server_to_client.lines()
        return sorted(lines, key=lambda line: line.frame_number)


def build_stream_pair(
    stream_index: int,
    segments: list[PayloadSegment],
    client_ip: str,
    client_port: int,
) -> StreamPair:
    """Split a stream's segments by direction and reassemble each side.

    The client side is identified by the caller from the SYN, not guessed from
    port numbers -- on a capture that starts mid-session there may be no SYN,
    and a wrong guess inverts the entire dialogue.
    """
    c2s = [s for s in segments if s.src_ip == client_ip and s.src_port == client_port]
    s2c = [s for s in segments if not (s.src_ip == client_ip and s.src_port == client_port)]

    server_ip, server_port = "", 0
    if c2s:
        server_ip, server_port = c2s[0].dst_ip, c2s[0].dst_port
    elif s2c:
        server_ip, server_port = s2c[0].src_ip, s2c[0].src_port

    frames = [s.frame_number for s in segments] or [0]
    times = [s.timestamp for s in segments] or [0.0]

    return StreamPair(
        stream_index=stream_index,
        client_ip=client_ip,
        client_port=client_port,
        server_ip=server_ip,
        server_port=server_port,
        client_to_server=reassemble(c2s, C2S),
        server_to_client=reassemble(s2c, S2C),
        first_frame=min(frames),
        last_frame=max(frames),
        start_time=min(times),
        end_time=max(times),
    )
