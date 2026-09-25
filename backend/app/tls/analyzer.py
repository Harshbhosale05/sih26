"""Pull the full cryptographic picture out of a handshake."""

from __future__ import annotations

from dataclasses import dataclass, field

from app.flows import StreamPair
from app.tls import certificate as cert_mod
from app.tls import fingerprint, suites
from app.tls.groups import PQC_HYBRID_GROUPS, name as group_name
from app.tls.handshake import (
    SNI_ENCRYPTED,
    ClientHello,
    ServerHello,
    parse_client_hello,
    parse_server_hello,
    version_name,
)
from app.tls.records import (
    CONTENT_HANDSHAKE,
    HANDSHAKE_CERTIFICATE,
    find_tls_start,
    parse_records,
)


@dataclass
class TLSAnalysis:
    observed: bool = False
    negotiated_version: int | None = None
    negotiated_version_name: str | None = None
    versions_offered: list[str] = field(default_factory=list)
    cipher_suite: suites.SuiteInfo | None = None
    selected_group: int | None = None
    selected_group_name: str | None = None
    groups_offered: list[str] = field(default_factory=list)
    pqc_groups_offered: list[str] = field(default_factory=list)
    pqc_group_selected: str | None = None
    sni: str | None = None
    sni_status: str | None = None
    alpn: str | None = None
    ja3: str | None = None
    ja3s: str | None = None
    ja4: str | None = None
    ja4s: str | None = None
    handshake_duration_ms: float | None = None

    # Certificate observability. TLS 1.3 encrypts the Certificate message, so
    # on modern infrastructure this is normally False -- which is a fact about
    # the evidence, not a failure of the server.
    cert_observable: bool = False
    cert_unobservable_reason: str | None = None
    certificate: object | None = None

    def serialise(self) -> dict:
        return {
            "observed": self.observed,
            "negotiated_version": self.negotiated_version_name,
            "versions_offered": self.versions_offered,
            "cipher_suite": self.cipher_suite.serialise() if self.cipher_suite else None,
            "selected_group": self.selected_group_name,
            "groups_offered": self.groups_offered,
            "pqc_groups_offered": self.pqc_groups_offered,
            "pqc_group_selected": self.pqc_group_selected,
            "sni": self.sni,
            "sni_status": self.sni_status,
            "alpn": self.alpn,
            "ja3": self.ja3,
            "ja3s": self.ja3s,
            "ja4": self.ja4,
            "ja4s": self.ja4s,
            "handshake_duration_ms": self.handshake_duration_ms,
            "cert_observable": self.cert_observable,
            "cert_unobservable_reason": self.cert_unobservable_reason,
            "certificate": self.certificate.serialise() if self.certificate else None,
        }


def _first_handshake(stream_data: bytes, handshake_type: int) -> bytes | None:
    start = find_tls_start(stream_data)
    if start is None:
        return None
    for record in parse_records(stream_data, start):
        if record.content_type != CONTENT_HANDSHAKE:
            continue
        if record.handshake_type != handshake_type:
            continue
        body_start = record.offset + 5
        return stream_data[body_start : body_start + record.length]
    return None


def _certificate_visible(stream_data: bytes) -> bool:
    start = find_tls_start(stream_data)
    if start is None:
        return False
    return any(
        r.content_type == CONTENT_HANDSHAKE and r.handshake_type == HANDSHAKE_CERTIFICATE
        for r in parse_records(stream_data, start)
    )


def analyse(pair: StreamPair, *, capture_time=None) -> TLSAnalysis:
    result = TLSAnalysis()

    ch_body = _first_handshake(pair.client_to_server.data, 0x01)
    sh_body = _first_handshake(pair.server_to_client.data, 0x02)

    client: ClientHello | None = parse_client_hello(ch_body) if ch_body else None
    server: ServerHello | None = parse_server_hello(sh_body) if sh_body else None

    if client is None and server is None:
        return result

    result.observed = True

    if client is not None:
        result.versions_offered = [
            version_name(v) for v in sorted(client.versions_offered, reverse=True)
        ] or [version_name(client.legacy_version)]
        result.groups_offered = [group_name(g) for g in client.supported_groups]
        result.pqc_groups_offered = [
            group_name(g) for g in client.supported_groups if g in PQC_HYBRID_GROUPS
        ]
        result.sni = client.sni
        result.sni_status = client.sni_status
        if client.sni_status == SNI_ENCRYPTED:
            result.sni = None
        result.alpn = client.alpn[0] if client.alpn else None
        _, result.ja3 = fingerprint.ja3(client)
        result.ja4 = fingerprint.ja4(client)

    if server is not None:
        result.negotiated_version = server.negotiated_version
        result.negotiated_version_name = version_name(server.negotiated_version)
        result.cipher_suite = suites.lookup(server.cipher_suite)
        result.selected_group = server.selected_group
        result.selected_group_name = (
            group_name(server.selected_group) if server.selected_group else None
        )
        if server.selected_group in PQC_HYBRID_GROUPS:
            result.pqc_group_selected = group_name(server.selected_group)
        if server.alpn:
            result.alpn = server.alpn
        _, result.ja3s = fingerprint.ja3s(server)
        result.ja4s = fingerprint.ja4s(server)

    # --- Certificate ------------------------------------------------------
    chain = cert_mod.extract_chain(pair.server_to_client.data)
    if chain and capture_time is not None:
        result.certificate = cert_mod.analyse(
            chain, capture_time=capture_time, hostname=result.sni
        )
    result.cert_observable = _certificate_visible(pair.server_to_client.data)
    if not result.cert_observable:
        if result.negotiated_version == 0x0304:
            result.cert_unobservable_reason = (
                "TLS 1.3 encrypts the Certificate message under handshake traffic "
                "keys (RFC 8446 §4.4.2). Certificate analysis requires session keys."
            )
        elif server is None:
            result.cert_unobservable_reason = "No ServerHello observed in this capture."
        else:
            result.cert_unobservable_reason = (
                "No Certificate message present in the captured bytes."
            )

    # Handshake timing: ClientHello to ServerHello, a feature for the
    # behavioural baseline later.
    if ch_body and sh_body:
        ch_start = find_tls_start(pair.client_to_server.data)
        sh_start = find_tls_start(pair.server_to_client.data)
        if ch_start is not None and sh_start is not None:
            _, ch_time = pair.client_to_server.frame_for_offset(ch_start)
            _, sh_time = pair.server_to_client.frame_for_offset(sh_start)
            if ch_time and sh_time and sh_time >= ch_time:
                result.handshake_duration_ms = round((sh_time - ch_time) * 1000, 3)

    return result
