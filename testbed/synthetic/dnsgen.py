"""DNS query/response generation for the testbed.

A real capture of mail traffic contains the DNS that preceded the SMTP
connections. That is what makes the policy correlation possible: we can see
whether the sender looked up an MTA-STS policy, whether one was published, and
then whether the session that followed actually honoured it.

Building those lookups here lets us test that correlation without a resolver.
"""

from __future__ import annotations

import struct

from testbed.synthetic.pcap import IPPROTO_UDP, build_ethernet, build_ipv4, build_udp

TYPE_A = 1
TYPE_CNAME = 5
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_TLSA = 52

CLASS_IN = 1


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _encode_txt(text: str) -> bytes:
    """TXT rdata is a sequence of length-prefixed strings, each ≤255 bytes."""
    raw = text.encode("ascii")
    chunks = [raw[i : i + 255] for i in range(0, len(raw), 255)] or [b""]
    return b"".join(bytes([len(c)]) + c for c in chunks)


def _encode_mx(preference: int, exchange: str) -> bytes:
    return struct.pack("!H", preference) + _encode_name(exchange)


def build_query(qname: str, qtype: int, txid: int) -> bytes:
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)  # RD set
    return header + _encode_name(qname) + struct.pack("!HH", qtype, CLASS_IN)


def build_response(
    qname: str, qtype: int, txid: int, answers: list[bytes], *, nxdomain: bool = False
) -> bytes:
    """Build a response. `answers` are pre-encoded rdata blobs.

    NXDOMAIN with zero answers is how "no policy published" is represented --
    a distinct and meaningful observation, not an absence of data.
    """
    flags = 0x8183 if nxdomain else 0x8180  # QR+RD+RA, rcode 3 or 0
    header = struct.pack("!HHHHHH", txid, flags, 1, len(answers), 0, 0)
    body = _encode_name(qname) + struct.pack("!HH", qtype, CLASS_IN)

    for rdata in answers:
        body += (
            b"\xc0\x0c"  # pointer to the question name at offset 12
            + struct.pack("!HHIH", qtype, CLASS_IN, 300, len(rdata))
            + rdata
        )
    return header + body


def txt_answer(text: str) -> bytes:
    return _encode_txt(text)


def mx_answer(preference: int, exchange: str) -> bytes:
    return _encode_mx(preference, exchange)


def a_answer(ip: str) -> bytes:
    return bytes(int(o) for o in ip.split("."))


def tlsa_answer(usage: int, selector: int, matching: int, digest: bytes) -> bytes:
    return bytes([usage, selector, matching]) + digest


def emit_lookup(
    writer,
    lab,
    *,
    client_ip: str,
    resolver_ip: str,
    qname: str,
    qtype: int,
    answers: list[bytes] | None = None,
    nxdomain: bool = False,
    txid: int = 0x1234,
):
    """Emit a query/response pair and return both packets."""
    src_port = lab.next_port()

    q = build_query(qname, qtype, txid)
    frame_q = build_ethernet(
        client_ip, resolver_ip,
        build_ipv4(
            client_ip, resolver_ip,
            build_udp(client_ip, resolver_ip, src_port, 53, q),
            ident=txid, proto=IPPROTO_UDP,
        ),
    )
    pkt_q = writer.add(lab.advance(0.004), frame_q)

    r = build_response(qname, qtype, txid, answers or [], nxdomain=nxdomain)
    frame_r = build_ethernet(
        resolver_ip, client_ip,
        build_ipv4(
            resolver_ip, client_ip,
            build_udp(resolver_ip, client_ip, 53, src_port, r),
            ident=txid + 1, proto=IPPROTO_UDP,
        ),
    )
    pkt_r = writer.add(lab.advance(0.006), frame_r)

    return pkt_q, pkt_r
