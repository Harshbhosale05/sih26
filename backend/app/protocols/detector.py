"""Protocol identification and per-session assembly.

Detection uses the dialogue first and the port second. A mail server on a
non-standard port is exactly the kind of misconfiguration this product should
be finding, so port-only detection would miss the interesting cases.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.flows import (
    C2S,
    EMAIL_PORTS,
    IMPLICIT_TLS_PORTS,
    S2C,
    Flow,
    Line,
    StreamPair,
    signature_hint,
)
from app.protocols import imap, pop3, smtp
from app.protocols.events import EventKind, ProtocolEvent
from app.protocols.state_machine import EncryptionAnalysis, analyse
from app.tls import find_tls_start, parse_records
from app.tls.analyzer import TLSAnalysis
from app.tls.analyzer import analyse as analyse_tls

PARSERS = {"SMTP": smtp.parse, "IMAP": imap.parse, "POP3": pop3.parse}


@dataclass
class EmailSessionAnalysis:
    stream_index: int
    protocol: str | None
    detection_method: str
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    first_frame: int
    last_frame: int
    start_time: float
    end_time: float
    events: list[ProtocolEvent] = field(default_factory=list)
    encryption: EncryptionAnalysis | None = None
    tls: TLSAnalysis | None = None
    server_banner: str | None = None
    tls_offset: int | None = None
    has_gaps: bool = False
    session_complete: bool = True


def detect_protocol(pair: StreamPair, flow: Flow) -> tuple[str | None, str]:
    """Identify the application protocol. Returns (protocol, method)."""
    server_data = pair.server_to_client.data
    client_data = pair.client_to_server.data

    # Implicit TLS: the very first bytes are a TLS record, so there is no
    # dialogue to read. Port is the only signal available, and that is fine --
    # 465/993/995 exist for exactly this.
    if client_data[:1] == b"\x16" or server_data[:1] == b"\x16":
        if flow.server_port in IMPLICIT_TLS_PORTS:
            return IMPLICIT_TLS_PORTS[flow.server_port], "implicit_tls_port"
        return None, "tls_on_unknown_port"

    hint = signature_hint(server_data)
    if hint:
        # Two distinct situations, and they are not the same finding:
        #   - the port is not a registered mail port at all (shadow service)
        #   - the port is registered, but for a different mail protocol
        # Both mean "believe the bytes, not the port", and both are worth
        # reporting, but only the first was being detected before.
        if flow.server_port not in EMAIL_PORTS:
            return hint, "payload_signature_nonstandard_port"
        if EMAIL_PORTS.get(flow.server_port) != hint:
            return hint, "payload_signature_port_mismatch"
        return hint, "payload_signature"

    if flow.port_hint:
        # Port says email but the greeting is unreadable -- likely a mid-session
        # or truncated capture. Proceed, but say where the guess came from.
        return flow.port_hint, "port_only"

    return None, "undetected"


def _tls_events(pair: StreamPair) -> tuple[list[ProtocolEvent], int | None]:
    """Locate the TLS handshake in either direction and emit events for it."""
    events: list[ProtocolEvent] = []

    c2s_start = find_tls_start(pair.client_to_server.data)
    s2c_start = find_tls_start(pair.server_to_client.data)
    if c2s_start is None and s2c_start is None:
        return events, None

    for stream, start in (
        (pair.client_to_server, c2s_start),
        (pair.server_to_client, s2c_start),
    ):
        if start is None:
            continue
        for record in parse_records(stream.data, start):
            frame, ts = stream.frame_for_offset(record.offset)
            if record.is_client_hello:
                kind = EventKind.TLS_CLIENT_HELLO
            elif record.is_server_hello:
                kind = EventKind.TLS_SERVER_HELLO
            elif record.is_application_data:
                kind = EventKind.TLS_APPLICATION_DATA
            elif record.is_alert:
                kind = EventKind.TLS_ALERT
            else:
                continue
            events.append(
                ProtocolEvent(
                    kind, frame, ts, stream.direction,
                    detail=kind.value, offset=record.offset,
                    metadata={"record_version": hex(record.version)},
                )
            )

    return events, c2s_start if c2s_start is not None else s2c_start


def _plaintext_lines(pair: StreamPair, tls_offset: int | None) -> list[Line]:
    """Lines from before the TLS upgrade only.

    Feeding encrypted bytes to a line parser produces garbage events, so the
    dialogue is cut at the handshake boundary in each direction.
    """
    def cut(stream, boundary: int | None) -> list[Line]:
        lines = stream.lines()
        if boundary is None:
            return lines
        return [line for line in lines if line.offset < boundary]

    c2s_boundary = find_tls_start(pair.client_to_server.data)
    s2c_boundary = find_tls_start(pair.server_to_client.data)

    lines = cut(pair.client_to_server, c2s_boundary) + cut(pair.server_to_client, s2c_boundary)
    return sorted(lines, key=lambda line: line.frame_number)


def analyse_stream(pair: StreamPair, flow: Flow, *, capture_time=None) -> EmailSessionAnalysis:
    protocol, method = detect_protocol(pair, flow)

    session = EmailSessionAnalysis(
        stream_index=pair.stream_index,
        protocol=protocol,
        detection_method=method,
        client_ip=pair.client_ip,
        client_port=pair.client_port,
        server_ip=pair.server_ip,
        server_port=pair.server_port,
        first_frame=flow.first_frame,
        last_frame=flow.last_frame,
        start_time=flow.start_time,
        end_time=flow.end_time,
        has_gaps=pair.has_gaps,
        # A session whose close we never saw cannot be judged complete. RST
        # counts: it is an observed termination.
        session_complete=(flow.saw_fin or flow.saw_rst) and not flow.mid_session,
    )

    if protocol is None:
        return session

    tls_events, tls_offset = _tls_events(pair)
    session.tls_offset = tls_offset

    implicit_tls = tls_offset == 0

    protocol_events: list[ProtocolEvent] = []
    if not implicit_tls:
        protocol_events = PARSERS[protocol](_plaintext_lines(pair, tls_offset))

    session.events = sorted(
        protocol_events + tls_events, key=lambda e: (e.frame_number, e.offset)
    )

    greeting = next((e for e in session.events if e.kind == EventKind.GREETING), None)
    if greeting:
        session.server_banner = greeting.metadata.get("banner")

    session.encryption = analyse(
        session.events,
        implicit_tls=implicit_tls,
        session_complete=session.session_complete,
        has_gaps=session.has_gaps,
    )

    if tls_offset is not None:
        session.tls = analyse_tls(pair, capture_time=capture_time)

    return session
