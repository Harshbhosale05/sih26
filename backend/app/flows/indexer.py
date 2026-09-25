"""Flow indexing and email-candidate selection (pass 1).

Port numbers are a hint, never the decision. Mail servers run on non-standard
ports constantly, and anything listening on 25 may not be SMTP at all. A flow
becomes a candidate on ports OR payload signature, and the protocol is only
*confirmed* later from the dialogue itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.engines.tshark import IndexedPacket

# Standard email ports. Presence here promotes a flow to candidate; it never
# by itself determines the protocol.
STARTTLS_PORTS = {25: "SMTP", 587: "SMTP", 2525: "SMTP", 110: "POP3", 143: "IMAP"}
IMPLICIT_TLS_PORTS = {465: "SMTP", 993: "IMAP", 995: "POP3"}
EMAIL_PORTS = {**STARTTLS_PORTS, **IMPLICIT_TLS_PORTS}


@dataclass
class Flow:
    stream_index: int
    client_ip: str = ""
    client_port: int = 0
    server_ip: str = ""
    server_port: int = 0
    first_frame: int = 0
    last_frame: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    packets: int = 0
    bytes_c2s: int = 0
    bytes_s2c: int = 0
    saw_syn: bool = False
    saw_fin: bool = False
    saw_rst: bool = False
    port_hint: str | None = None
    is_candidate: bool = False
    _frames: list[int] = field(default_factory=list, repr=False)

    @property
    def is_implicit_tls_port(self) -> bool:
        return self.server_port in IMPLICIT_TLS_PORTS

    @property
    def mid_session(self) -> bool:
        """True if the capture never saw this connection open.

        Analysis can still proceed, but any verdict about what happened before
        the capture started must be UNKNOWN.
        """
        return not self.saw_syn


def index_flows(packets: list[IndexedPacket]) -> dict[int, Flow]:
    """Group indexed packets into flows and orient each one client->server.

    Orientation comes from the SYN when present. Without a SYN we fall back to
    the lower-numbered... no: we fall back to *port role*, because a mid-session
    capture of SMTP still has an obvious server side (port 25) even though the
    handshake is long gone.
    """
    flows: dict[int, Flow] = {}

    for pkt in packets:
        flow = flows.get(pkt.stream)
        if flow is None:
            flow = Flow(stream_index=pkt.stream, first_frame=pkt.frame_number,
                        start_time=pkt.timestamp)
            flows[pkt.stream] = flow

        flow.packets += 1
        flow.last_frame = max(flow.last_frame, pkt.frame_number)
        flow.end_time = max(flow.end_time, pkt.timestamp)
        flow.saw_fin |= pkt.fin
        flow.saw_rst |= pkt.rst

        # A bare SYN (no ACK) identifies the client unambiguously.
        if pkt.syn and not flow.saw_syn:
            flow.saw_syn = True
            flow.client_ip, flow.client_port = pkt.src_ip, pkt.src_port
            flow.server_ip, flow.server_port = pkt.dst_ip, pkt.dst_port

    # Orient flows that never showed a SYN, and tally directional bytes.
    for flow in flows.values():
        if not flow.client_ip:
            _orient_without_syn(flow, packets)

    for pkt in packets:
        flow = flows[pkt.stream]
        if pkt.src_ip == flow.client_ip and pkt.src_port == flow.client_port:
            flow.bytes_c2s += pkt.tcp_len
        else:
            flow.bytes_s2c += pkt.tcp_len

    for flow in flows.values():
        flow.port_hint = EMAIL_PORTS.get(flow.server_port)
        flow.is_candidate = flow.port_hint is not None

    return flows


def _orient_without_syn(flow: Flow, packets: list[IndexedPacket]) -> None:
    """Pick the server side of a mid-session flow using port role."""
    sample = next((p for p in packets if p.stream == flow.stream_index), None)
    if sample is None:
        return

    src_is_email = sample.src_port in EMAIL_PORTS
    dst_is_email = sample.dst_port in EMAIL_PORTS

    if dst_is_email and not src_is_email:
        flow.client_ip, flow.client_port = sample.src_ip, sample.src_port
        flow.server_ip, flow.server_port = sample.dst_ip, sample.dst_port
    elif src_is_email and not dst_is_email:
        flow.client_ip, flow.client_port = sample.dst_ip, sample.dst_port
        flow.server_ip, flow.server_port = sample.src_ip, sample.src_port
    else:
        # Neither side is a known email port: the higher port is conventionally
        # the ephemeral client side.
        if sample.src_port >= sample.dst_port:
            flow.client_ip, flow.client_port = sample.src_ip, sample.src_port
            flow.server_ip, flow.server_port = sample.dst_ip, sample.dst_port
        else:
            flow.client_ip, flow.client_port = sample.dst_ip, sample.dst_port
            flow.server_ip, flow.server_port = sample.src_ip, sample.src_port


# Payload signatures for email protocols on non-standard ports. Checked against
# the first bytes the server sends.
_SERVER_SIGNATURES = (
    (b"220 ", "SMTP"),
    (b"220-", "SMTP"),
    (b"* OK", "IMAP"),
    (b"* PREAUTH", "IMAP"),
    (b"+OK", "POP3"),
)


def signature_hint(server_first_bytes: bytes) -> str | None:
    """Identify an email protocol from a server greeting.

    Lets us catch mail on non-standard ports, which is exactly the
    misconfiguration a posture assessment should be finding.
    """
    head = server_first_bytes[:16]
    for prefix, protocol in _SERVER_SIGNATURES:
        if head.startswith(prefix):
            return protocol
    return None
