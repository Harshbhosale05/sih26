"""Scenario catalogue: scripted email sessions with known ground truth.

Every scenario emits (a) a pcap and (b) a ground-truth JSON stating exactly
which findings the platform is expected to produce and which frames prove them.
The ground truth is the test oracle -- detectors are graded against it, so a
detector that fires on the right session for the wrong reason still fails.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Callable

from testbed.synthetic import dnsgen, tls
from testbed.synthetic.conversation import TCPConversation
from testbed.synthetic.pcap import Packet, PcapWriter

# Base epoch for all scenarios: 2026-03-02 09:15:00 UTC. Fixed so captures are
# reproducible; certificate-expiry logic in tier 2 is calibrated against it.
BASE_TIME = 1772442900.0


@dataclass
class ExpectedFinding:
    category: str
    severity: str
    session: str
    rationale: str
    evidence: list[Packet] = field(default_factory=list)

    def serialise(self) -> dict:
        return {
            "category": self.category,
            "severity": self.severity,
            "session": self.session,
            "rationale": self.rationale,
            "evidence_frames": [p.frame_number for p in self.evidence],
        }


@dataclass
class SessionTruth:
    session: str
    protocol: str
    client: str
    server: str
    server_port: int
    encryption_state: str
    tls_version: str | None = None
    cipher_suite: str | None = None
    forward_secrecy: bool | None = None
    notes: str = ""

    def serialise(self) -> dict:
        return {
            "session": self.session,
            "protocol": self.protocol,
            "client": self.client,
            "server": self.server,
            "server_port": self.server_port,
            "encryption_state": self.encryption_state,
            "tls_version": self.tls_version,
            "cipher_suite": self.cipher_suite,
            "forward_secrecy": self.forward_secrecy,
            "notes": self.notes,
        }


@dataclass
class GroundTruth:
    scenario: str
    label: str
    description: str
    sessions: list[SessionTruth] = field(default_factory=list)
    expected_findings: list[ExpectedFinding] = field(default_factory=list)
    truncate_after: int | None = None
    notes: str = ""

    def serialise(self) -> dict:
        return {
            "scenario": self.scenario,
            "label": self.label,
            "description": self.description,
            "tier": "synthetic",
            "sessions": [s.serialise() for s in self.sessions],
            "expected_findings": [f.serialise() for f in self.expected_findings],
            "notes": self.notes,
        }


@dataclass
class Lab:
    """Allocates client ports and session names so scenarios stay readable."""

    clock: float = BASE_TIME
    _port: int = 40000
    _counter: dict = field(default_factory=dict)

    def next_port(self) -> int:
        self._port += 1
        return self._port

    def next_name(self, protocol: str) -> str:
        n = self._counter.get(protocol, 0) + 1
        self._counter[protocol] = n
        return f"{protocol}-{n:04d}"

    def advance(self, seconds: float) -> float:
        self.clock += seconds
        return self.clock


CLIENT_IP = "10.10.2.15"
MAIL01 = ("10.10.2.50", "mail01.corp.local")
MAIL02 = ("10.10.2.51", "mail02.corp.local")


# --------------------------------------------------------------------------
# Building blocks
# --------------------------------------------------------------------------

def _tls_handshake(
    convo: TCPConversation,
    *,
    version: int,
    cipher: int,
    group: int = tls.GROUP_X25519,
    sni: str,
    offer_pqc: bool = False,
    certificate: str | None = None,
    seed: int = 1,
) -> tuple[Packet, Packet]:
    groups = [tls.GROUP_X25519, tls.GROUP_SECP256R1]
    if offer_pqc:
        groups = [tls.GROUP_X25519MLKEM768, *groups]

    ch = convo.client_raw(
        tls.build_client_hello(
            sni=sni, max_version=version, cipher_suites=[cipher], groups=groups, seed=seed
        )
    )
    sh = convo.server_raw(
        tls.build_server_hello(version=version, cipher_suite=cipher, group=group, seed=seed + 1)
    )
    if certificate and version < tls.TLS1_3:
        # TLS <= 1.2 sends the certificate in the clear. Under TLS 1.3 this
        # message is encrypted, so emitting one there would be a fiction.
        convo.server_raw(tls.build_certificate(tls.load_chain(certificate), version))
    # Bulk encrypted traffic: measurable, unreadable. This is the normal case.
    convo.client_raw(tls.build_application_data(512, seed=seed))
    convo.server_raw(tls.build_application_data(256, seed=seed + 3))
    return ch, sh


def smtp_session(
    writer: PcapWriter,
    lab: Lab,
    *,
    server: tuple[str, str] = MAIL01,
    port: int = 25,
    advertise_starttls: bool = True,
    mangle_starttls: bool = False,
    use_starttls: bool = True,
    starttls_succeeds: bool = True,
    tls_version: int = tls.TLS1_3,
    cipher: int = tls.TLS_AES_256_GCM_SHA384,
    offer_pqc: bool = False,
    certificate: str | None = None,
    cleartext_auth: bool = False,
    split_starttls: bool = False,
    implicit_tls: bool = False,
    client_ip: str = CLIENT_IP,
    seed: int = 1,
) -> tuple[SessionTruth, dict[str, Packet]]:
    """One scripted SMTP session. Returns its ground truth and key frames."""
    server_ip, server_host = server
    name = lab.next_name("SMTP")
    marks: dict[str, Packet] = {}

    convo = TCPConversation(
        writer=writer,
        client_ip=client_ip,
        server_ip=server_ip,
        client_port=lab.next_port(),
        server_port=port,
        start_time=lab.advance(0.35),
    )
    convo.open()

    if implicit_tls:
        # RFC 8314 implicit TLS: no plaintext phase at all.
        ch, sh = _tls_handshake(
            convo, version=tls_version, cipher=cipher, sni=server_host,
            offer_pqc=offer_pqc, seed=seed,
        )
        marks["client_hello"] = ch
        marks["server_hello"] = sh
        convo.close()
        return (
            SessionTruth(
                session=name, protocol="SMTP", client=client_ip, server=server_host,
                server_port=port, encryption_state="IMPLICIT_TLS",
                tls_version=tls.VERSION_NAMES[tls_version],
                cipher_suite=hex(cipher),
                forward_secrecy=_has_pfs(cipher, tls_version),
                notes="Implicit TLS on submission port, no plaintext phase.",
            ),
            marks,
        )

    convo.server_says(f"220 {server_host} ESMTP Postfix (Debian/GNU)")
    convo.client_says("EHLO client.corp.local")

    capabilities = [
        f"250-{server_host}",
        "250-PIPELINING",
        "250-SIZE 10240000",
    ]
    if advertise_starttls:
        # A middlebox stripping STARTTLS typically overwrites the token in
        # place, preserving the line length so TCP sequence numbers stay valid.
        capabilities.append("250-XXXXXXXA" if mangle_starttls else "250-STARTTLS")
    capabilities += ["250-AUTH LOGIN PLAIN", "250 8BITMIME"]

    marks["ehlo_response"] = convo.server_says_multi(capabilities)

    tls_established = False
    if use_starttls:
        if split_starttls:
            # Command split across segments: only a stream-reassembling
            # pipeline sees "STARTTLS" here.
            parts = convo.split_client_says("STARTTLS", at=4)
            marks["starttls_request"] = parts[0]
        else:
            marks["starttls_request"] = convo.client_says("STARTTLS")

        if starttls_succeeds:
            convo.server_says("220 2.0.0 Ready to start TLS")
            ch, sh = _tls_handshake(
                convo, version=tls_version, cipher=cipher, sni=server_host,
                offer_pqc=offer_pqc, certificate=certificate, seed=seed,
            )
            marks["client_hello"] = ch
            marks["server_hello"] = sh
            tls_established = True
        else:
            # Server refuses the upgrade; the question is what the client does
            # next. Continuing in cleartext is the severe outcome.
            marks["starttls_rejected"] = convo.server_says(
                "454 4.7.0 TLS not available due to temporary reason"
            )

    if not tls_established:
        if cleartext_auth:
            marks["auth_command"] = convo.client_says("AUTH LOGIN")
            convo.server_says("334 VXNlcm5hbWU6")
            marks["auth_username"] = convo.client_says(
                base64.b64encode(b"jdoe@corp.local").decode()
            )
            convo.server_says("334 UGFzc3dvcmQ6")
            marks["auth_password"] = convo.client_says(
                base64.b64encode(b"Wint3r@2026!").decode()
            )
            convo.server_says("235 2.7.0 Authentication successful")

        convo.client_says("MAIL FROM:<jdoe@corp.local>")
        convo.server_says("250 2.1.0 Ok")
        convo.client_says("RCPT TO:<ops@partner.example>")
        convo.server_says("250 2.1.5 Ok")
        convo.client_says("DATA")
        convo.server_says("354 End data with <CR><LF>.<CR><LF>")
        convo.client_says("Subject: Q1 infrastructure review\r\n\r\nSee attached.\r\n.")
        convo.server_says("250 2.0.0 Ok: queued as 4A2F1C")

    convo.client_says("QUIT")
    convo.server_says("221 2.0.0 Bye")
    convo.close()

    if tls_established:
        state = "TLS_ESTABLISHED"
    elif mangle_starttls:
        # A mangled capability is NOT an advertisement. From the client's point
        # of view STARTTLS was never offered -- which is precisely what the
        # stripping attack achieves. Labelling this ADVERTISED_NOT_USED would
        # blame the client for a choice it never had.
        state = "STARTTLS_NOT_ADVERTISED"
    elif not use_starttls and advertise_starttls:
        state = "STARTTLS_ADVERTISED_NOT_USED"
    elif not advertise_starttls:
        state = "STARTTLS_NOT_ADVERTISED"
    elif not starttls_succeeds:
        state = "PLAINTEXT_AFTER_FAILURE"
    else:
        state = "PLAINTEXT_THROUGHOUT"

    return (
        SessionTruth(
            session=name, protocol="SMTP", client=client_ip, server=server_host,
            server_port=port, encryption_state=state,
            tls_version=tls.VERSION_NAMES[tls_version] if tls_established else None,
            cipher_suite=hex(cipher) if tls_established else None,
            forward_secrecy=_has_pfs(cipher, tls_version) if tls_established else None,
            notes="mangled STARTTLS capability" if mangle_starttls else "",
        ),
        marks,
    )


def _has_pfs(cipher: int, version: int) -> bool:
    if version >= tls.TLS1_3:
        return True  # TLS 1.3 mandates ephemeral key exchange
    return cipher in {
        tls.TLS_ECDHE_RSA_AES_128_GCM_SHA256,
        tls.TLS_ECDHE_RSA_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_RSA_AES_128_CBC_SHA256,
    }


def imap_session(
    writer: PcapWriter,
    lab: Lab,
    *,
    server: tuple[str, str] = MAIL01,
    port: int = 143,
    advertise_starttls: bool = True,
    use_starttls: bool = True,
    cleartext_login: bool = False,
    tls_version: int = tls.TLS1_3,
    cipher: int = tls.TLS_AES_256_GCM_SHA384,
    client_ip: str = CLIENT_IP,
    seed: int = 20,
) -> tuple[SessionTruth, dict[str, Packet]]:
    server_ip, server_host = server
    name = lab.next_name("IMAP")
    marks: dict[str, Packet] = {}

    convo = TCPConversation(
        writer=writer, client_ip=client_ip, server_ip=server_ip,
        client_port=lab.next_port(), server_port=port,
        start_time=lab.advance(0.4),
    )
    convo.open()

    caps = "* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE"
    caps += " STARTTLS AUTH=PLAIN] Dovecot ready." if advertise_starttls else " AUTH=PLAIN] Dovecot ready."
    convo.server_says(caps)

    convo.client_says("a001 CAPABILITY")
    cap_line = "* CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE"
    if advertise_starttls:
        cap_line += " STARTTLS"
    cap_line += " AUTH=PLAIN"
    marks["capability_response"] = convo.server_says_multi(
        [cap_line, "a001 OK Pre-login capabilities listed, post-login capabilities have more."]
    )

    established = False
    if use_starttls and advertise_starttls:
        marks["starttls_request"] = convo.client_says("a002 STARTTLS")
        convo.server_says("a002 OK Begin TLS negotiation now.")
        ch, sh = _tls_handshake(
            convo, version=tls_version, cipher=cipher, sni=server_host, seed=seed
        )
        marks["client_hello"] = ch
        marks["server_hello"] = sh
        established = True

    if not established:
        if cleartext_login:
            # IMAP LOGIN sends credentials as literal arguments -- no encoding
            # at all, not even base64.
            marks["login_command"] = convo.client_says(
                'a003 LOGIN "jdoe@corp.local" "Wint3r@2026!"'
            )
            convo.server_says("a003 OK [CAPABILITY IMAP4rev1] Logged in")
        convo.client_says("a004 SELECT INBOX")
        convo.server_says_multi(["* 42 EXISTS", "a004 OK [READ-WRITE] Select completed."])

    convo.client_says("a005 LOGOUT")
    convo.server_says_multi(["* BYE Logging out", "a005 OK Logout completed."])
    convo.close()

    if established:
        state = "TLS_ESTABLISHED"
    elif not advertise_starttls:
        state = "STARTTLS_NOT_ADVERTISED"
    else:
        state = "STARTTLS_ADVERTISED_NOT_USED"

    return (
        SessionTruth(
            session=name, protocol="IMAP", client=client_ip, server=server_host,
            server_port=port, encryption_state=state,
            tls_version=tls.VERSION_NAMES[tls_version] if established else None,
            cipher_suite=hex(cipher) if established else None,
            forward_secrecy=_has_pfs(cipher, tls_version) if established else None,
        ),
        marks,
    )


def pop3_session(
    writer: PcapWriter,
    lab: Lab,
    *,
    server: tuple[str, str] = MAIL01,
    port: int = 110,
    advertise_stls: bool = True,
    use_stls: bool = True,
    cleartext_auth: bool = False,
    tls_version: int = tls.TLS1_2,
    cipher: int = tls.TLS_ECDHE_RSA_AES_256_GCM_SHA384,
    client_ip: str = CLIENT_IP,
    seed: int = 40,
) -> tuple[SessionTruth, dict[str, Packet]]:
    """POP3 upgrades with STLS, not STARTTLS -- a distinction the upgrade-command
    mapping must carry as data rather than a hardcoded string."""
    server_ip, server_host = server
    name = lab.next_name("POP3")
    marks: dict[str, Packet] = {}

    convo = TCPConversation(
        writer=writer, client_ip=client_ip, server_ip=server_ip,
        client_port=lab.next_port(), server_port=port,
        start_time=lab.advance(0.3),
    )
    convo.open()
    convo.server_says(f"+OK {server_host} POP3 server ready")

    convo.client_says("CAPA")
    caps = ["+OK Capability list follows", "TOP", "USER", "UIDL"]
    if advertise_stls:
        caps.append("STLS")
    caps.append(".")
    marks["capa_response"] = convo.server_says_multi(caps)

    established = False
    if use_stls and advertise_stls:
        marks["stls_request"] = convo.client_says("STLS")
        convo.server_says("+OK Begin TLS negotiation")
        ch, sh = _tls_handshake(
            convo, version=tls_version, cipher=cipher, sni=server_host, seed=seed
        )
        marks["client_hello"] = ch
        marks["server_hello"] = sh
        established = True

    if not established:
        if cleartext_auth:
            marks["user_command"] = convo.client_says("USER jdoe@corp.local")
            convo.server_says("+OK")
            marks["pass_command"] = convo.client_says("PASS Wint3r@2026!")
            convo.server_says("+OK Logged in.")
        convo.client_says("STAT")
        convo.server_says("+OK 3 4820")

    convo.client_says("QUIT")
    convo.server_says("+OK Logging out.")
    convo.close()

    if established:
        state = "TLS_ESTABLISHED"
    elif not advertise_stls:
        state = "STARTTLS_NOT_ADVERTISED"
    else:
        state = "STARTTLS_ADVERTISED_NOT_USED"

    return (
        SessionTruth(
            session=name, protocol="POP3", client=client_ip, server=server_host,
            server_port=port, encryption_state=state,
            tls_version=tls.VERSION_NAMES[tls_version] if established else None,
            cipher_suite=hex(cipher) if established else None,
            forward_secrecy=_has_pfs(cipher, tls_version) if established else None,
        ),
        marks,
    )


# --------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------

def scenario_secure_tls13(writer: PcapWriter, lab: Lab) -> GroundTruth:
    gt = GroundTruth(
        scenario="01-secure-tls13",
        label="secure",
        description="SMTP, IMAP and POP3 all upgrading cleanly to TLS 1.3 with AES-256-GCM.",
        notes=(
            "The negative control. Any finding above INFO on this capture is a "
            "false positive and a test failure."
        ),
    )
    for seed in range(3):
        s, _ = smtp_session(writer, lab, port=587, seed=seed)
        gt.sessions.append(s)
    s, _ = imap_session(writer, lab)
    gt.sessions.append(s)
    s, _ = pop3_session(writer, lab, tls_version=tls.TLS1_3,
                        cipher=tls.TLS_AES_256_GCM_SHA384)
    gt.sessions.append(s)
    return gt


def scenario_deprecated_tls(writer: PcapWriter, lab: Lab) -> GroundTruth:
    gt = GroundTruth(
        scenario="03-deprecated-tls",
        label="deprecated_tls",
        description="STARTTLS succeeds but negotiates TLS 1.0 with a CBC cipher.",
        notes="RFC 8996 deprecates TLS 1.0/1.1; NIST SP 800-52r2 forbids them.",
    )
    s, marks = smtp_session(
        writer, lab, port=587, tls_version=tls.TLS1_0,
        cipher=tls.TLS_ECDHE_RSA_AES_128_CBC_SHA256,
    )
    gt.sessions.append(s)
    gt.expected_findings.append(
        ExpectedFinding(
            category="deprecated_tls_version", severity="HIGH", session=s.session,
            rationale="ServerHello negotiates TLS 1.0, deprecated by RFC 8996.",
            evidence=[marks["server_hello"]],
        )
    )
    return gt


def scenario_no_forward_secrecy(writer: PcapWriter, lab: Lab) -> GroundTruth:
    gt = GroundTruth(
        scenario="07-no-forward-secrecy",
        label="no_pfs",
        description="TLS 1.2 negotiated with static RSA key exchange.",
        notes=(
            "Recorded traffic stays decryptable forever if the server key leaks. "
            "This is also the clearest harvest-now-decrypt-later exposure."
        ),
    )
    s, marks = smtp_session(
        writer, lab, port=587, tls_version=tls.TLS1_2,
        cipher=tls.TLS_RSA_AES_256_CBC_SHA,
    )
    gt.sessions.append(s)
    gt.expected_findings.append(
        ExpectedFinding(
            category="no_forward_secrecy", severity="HIGH", session=s.session,
            rationale="TLS_RSA_WITH_AES_256_CBC_SHA uses static RSA key exchange.",
            evidence=[marks["server_hello"]],
        )
    )
    return gt


def scenario_starttls_not_enforced(writer: PcapWriter, lab: Lab) -> GroundTruth:
    gt = GroundTruth(
        scenario="08-starttls-not-enforced",
        label="starttls_not_enforced",
        description="Server advertises STARTTLS; client never requests it and sends mail in the clear.",
    )
    s, marks = smtp_session(writer, lab, port=25, use_starttls=False)
    gt.sessions.append(s)
    gt.expected_findings.append(
        ExpectedFinding(
            category="starttls_advertised_not_used", severity="MEDIUM", session=s.session,
            rationale="STARTTLS offered in EHLO response but never requested; message body traversed in cleartext.",
            evidence=[marks["ehlo_response"]],
        )
    )
    return gt


def scenario_starttls_stripping(writer: PcapWriter, lab: Lab) -> GroundTruth:
    """The headline scenario.

    The same server, in the same capture, advertises STARTTLS on most
    connections and emits a length-preserving mangled token on two. No
    single-session analysis can see this -- it only exists as a cross-session
    differential, which is precisely the gap between us and a packet viewer.
    """
    gt = GroundTruth(
        scenario="09-starttls-stripping",
        label="starttls_stripping",
        description=(
            "On-path stripping of the STARTTLS capability: 6 sessions to mail01 "
            "advertise it, 2 carry a length-preserving mangled token and fall back "
            "to cleartext."
        ),
        notes=(
            "Length-preserving rewrite (250-STARTTLS -> 250-XXXXXXXA) keeps TCP "
            "sequence numbers valid, which is what makes the attack invisible to "
            "the endpoints. Detection requires comparing the server's advertised "
            "capabilities across sessions."
        ),
    )

    for seed in range(6):
        s, _ = smtp_session(writer, lab, port=25, seed=seed)
        gt.sessions.append(s)

    for seed in (10, 11):
        s, marks = smtp_session(
            writer, lab, port=25, mangle_starttls=True, use_starttls=False,
            cleartext_auth=True, seed=seed,
        )
        gt.sessions.append(s)
        gt.expected_findings.append(
            ExpectedFinding(
                category="starttls_stripping", severity="CRITICAL", session=s.session,
                rationale=(
                    "mail01.corp.local advertises STARTTLS in 6 of 8 sessions in this "
                    "capture; this session's EHLO response carries a same-length "
                    "mangled token instead. Consistent with on-path capability stripping."
                ),
                evidence=[marks["ehlo_response"]],
            )
        )
        gt.expected_findings.append(
            ExpectedFinding(
                category="cleartext_credential_exposure", severity="CRITICAL", session=s.session,
                rationale="AUTH LOGIN completed without TLS; credentials recoverable from the capture.",
                evidence=[marks["auth_username"], marks["auth_password"]],
            )
        )
    return gt


def scenario_downgrade_fallback(writer: PcapWriter, lab: Lab) -> GroundTruth:
    gt = GroundTruth(
        scenario="10-downgrade-fallback",
        label="downgrade_fallback",
        description="Client requests STARTTLS, server refuses with 454, client continues in cleartext.",
        notes=(
            "Worse than never trying: the client demonstrably wanted encryption "
            "and shipped the message anyway."
        ),
    )
    s, marks = smtp_session(
        writer, lab, port=25, starttls_succeeds=False, cleartext_auth=True
    )
    gt.sessions.append(s)
    gt.expected_findings.append(
        ExpectedFinding(
            category="starttls_downgrade_fallback", severity="CRITICAL", session=s.session,
            rationale="STARTTLS requested, rejected with 454, session continued in cleartext.",
            evidence=[marks["starttls_request"], marks["starttls_rejected"]],
        )
    )
    gt.expected_findings.append(
        ExpectedFinding(
            category="cleartext_credential_exposure", severity="CRITICAL", session=s.session,
            rationale="AUTH LOGIN sent after the failed upgrade.",
            evidence=[marks["auth_username"], marks["auth_password"]],
        )
    )
    return gt


def scenario_credential_exposure(writer: PcapWriter, lab: Lab) -> GroundTruth:
    gt = GroundTruth(
        scenario="11-credential-exposure",
        label="credential_exposure",
        description="Cleartext credentials across all three protocols: SMTP AUTH LOGIN, IMAP LOGIN, POP3 USER/PASS.",
        notes=(
            "The detector must report that this happened without persisting the "
            "credential -- redacted username, hash prefix, length only."
        ),
    )
    s, marks = smtp_session(
        writer, lab, port=25, advertise_starttls=False, use_starttls=False,
        cleartext_auth=True,
    )
    gt.sessions.append(s)
    gt.expected_findings.append(
        ExpectedFinding(
            category="cleartext_credential_exposure", severity="CRITICAL", session=s.session,
            rationale="SMTP AUTH LOGIN base64 credentials sent without TLS.",
            evidence=[marks["auth_username"], marks["auth_password"]],
        )
    )

    s, marks = imap_session(
        writer, lab, advertise_starttls=False, use_starttls=False, cleartext_login=True
    )
    gt.sessions.append(s)
    gt.expected_findings.append(
        ExpectedFinding(
            category="cleartext_credential_exposure", severity="CRITICAL", session=s.session,
            rationale="IMAP LOGIN sends credentials as unencoded literals without TLS.",
            evidence=[marks["login_command"]],
        )
    )

    s, marks = pop3_session(
        writer, lab, advertise_stls=False, use_stls=False, cleartext_auth=True
    )
    gt.sessions.append(s)
    gt.expected_findings.append(
        ExpectedFinding(
            category="cleartext_credential_exposure", severity="CRITICAL", session=s.session,
            rationale="POP3 USER/PASS sent without TLS.",
            evidence=[marks["user_command"], marks["pass_command"]],
        )
    )
    return gt


def scenario_implicit_tls(writer: PcapWriter, lab: Lab) -> GroundTruth:
    gt = GroundTruth(
        scenario="12-implicit-tls",
        label="secure_implicit",
        description="Implicit TLS on 465/993/995 with no plaintext phase (RFC 8314 preferred).",
        notes="Exercises the IMPLICIT_TLS state: no STARTTLS to find, and that is correct.",
    )
    s, _ = smtp_session(writer, lab, port=465, implicit_tls=True)
    gt.sessions.append(s)

    for port, proto in ((993, "IMAP"), (995, "POP3")):
        convo = TCPConversation(
            writer=writer, client_ip=CLIENT_IP, server_ip=MAIL01[0],
            client_port=lab.next_port(), server_port=port,
            start_time=lab.advance(0.3),
        )
        convo.open()
        _tls_handshake(
            convo, version=tls.TLS1_3, cipher=tls.TLS_AES_256_GCM_SHA384,
            sni=MAIL01[1], seed=port,
        )
        convo.close()
        gt.sessions.append(
            SessionTruth(
                session=lab.next_name(proto), protocol=proto, client=CLIENT_IP,
                server=MAIL01[1], server_port=port, encryption_state="IMPLICIT_TLS",
                tls_version="TLS 1.3", cipher_suite=hex(tls.TLS_AES_256_GCM_SHA384),
                forward_secrecy=True,
            )
        )
    return gt


def scenario_pqc_ready(writer: PcapWriter, lab: Lab) -> GroundTruth:
    gt = GroundTruth(
        scenario="15-pqc-readiness",
        label="pqc_ready",
        description=(
            "Mixed capture where some clients offer the hybrid group "
            "X25519MLKEM768 (0x11EC) and the server never selects it."
        ),
        notes=(
            "Drives the PQC readiness report: clients are migrating, the server "
            "is not. Reported as migration exposure, never as an attack."
        ),
    )
    for seed in range(3):
        s, _ = smtp_session(writer, lab, port=587, offer_pqc=True, seed=seed + 60)
        s.notes = "client offered X25519MLKEM768; server selected x25519"
        gt.sessions.append(s)
    for seed in range(4):
        s, _ = smtp_session(writer, lab, port=587, seed=seed + 70)
        gt.sessions.append(s)
    gt.expected_findings.append(
        ExpectedFinding(
            category="pqc_server_not_ready", severity="LOW", session="(server-level)",
            rationale=(
                "3 of 7 clients offered hybrid PQC key exchange; mail01.corp.local "
                "selected classical x25519 in every session."
            ),
        )
    )
    return gt


def scenario_split_command(writer: PcapWriter, lab: Lab) -> GroundTruth:
    gt = GroundTruth(
        scenario="17-segmented-starttls",
        label="secure",
        description="STARTTLS split across two TCP segments, then a clean TLS 1.3 upgrade.",
        notes=(
            "Regression test for stream reassembly. A packet-oriented parser sees "
            "'STAR' and 'TTLS' and reports STARTTLS_ADVERTISED_NOT_USED -- a false "
            "positive this fixture exists to catch."
        ),
    )
    s, _ = smtp_session(writer, lab, port=587, split_starttls=True)
    gt.sessions.append(s)
    return gt


def scenario_incomplete(writer: PcapWriter, lab: Lab) -> GroundTruth:
    gt = GroundTruth(
        scenario="16-incomplete-evidence",
        label="incomplete_evidence",
        description="Capture stops mid-handshake, as if tcpdump was killed during collection.",
        notes=(
            "The platform must report UNKNOWN for these sessions. Emitting a PASS "
            "or a FAIL here is the single worst failure mode in a forensic tool."
        ),
    )
    s, _ = smtp_session(writer, lab, port=587)
    gt.sessions.append(s)
    s2, _ = smtp_session(writer, lab, port=587, seed=9)
    s2.encryption_state = "TRUNCATED"
    s2.tls_version = None
    s2.cipher_suite = None
    s2.forward_secrecy = None
    s2.notes = "capture ends mid-session; verdict must be UNKNOWN"
    gt.sessions.append(s2)
    # Cut the file partway through the second session.
    gt.truncate_after = len(writer.packets) - 18
    gt.expected_findings.append(
        ExpectedFinding(
            category="incomplete_evidence", severity="INFO", session=s2.session,
            rationale="Session has no observable termination; posture verdict must be UNKNOWN.",
        )
    )
    return gt


def scenario_enterprise(writer: PcapWriter, lab: Lab) -> GroundTruth:
    """The demo capture: mostly-healthy enterprise traffic with real problems in it."""
    gt = GroundTruth(
        scenario="13-enterprise-mixed",
        label="enterprise_normal",
        description=(
            "Two mail servers, ~40 sessions across SMTP/IMAP/POP3, predominantly "
            "healthy, with a realistic tail of misconfiguration."
        ),
        notes="Primary demo capture and the training set for the baseline model.",
    )

    for seed in range(14):
        s, _ = smtp_session(writer, lab, port=587, seed=seed)
        gt.sessions.append(s)
    for seed in range(6):
        s, _ = smtp_session(writer, lab, server=MAIL02, port=587, seed=seed + 100)
        gt.sessions.append(s)
    for seed in range(8):
        s, _ = imap_session(writer, lab, seed=seed + 20)
        gt.sessions.append(s)
    for seed in range(4):
        s, _ = pop3_session(writer, lab, tls_version=tls.TLS1_3,
                            cipher=tls.TLS_AES_256_GCM_SHA384, seed=seed + 40)
        gt.sessions.append(s)

    # mail02 is the weak one: TLS 1.2 with a CBC suite on legacy relay.
    for seed in range(3):
        s, marks = smtp_session(
            writer, lab, server=MAIL02, port=25, tls_version=tls.TLS1_2,
            cipher=tls.TLS_ECDHE_RSA_AES_128_CBC_SHA256, seed=seed + 120,
        )
        s.notes = "legacy relay path"
        gt.sessions.append(s)
        if seed == 0:
            gt.expected_findings.append(
                ExpectedFinding(
                    category="weak_cipher_suite", severity="MEDIUM", session=s.session,
                    rationale="CBC-mode cipher negotiated on mail02; AEAD available on mail01.",
                    evidence=[marks["server_hello"]],
                )
            )

    # One stripped session hiding in otherwise normal traffic.
    s, marks = smtp_session(
        writer, lab, port=25, mangle_starttls=True, use_starttls=False,
        cleartext_auth=True, seed=150,
    )
    gt.sessions.append(s)
    gt.expected_findings.append(
        ExpectedFinding(
            category="starttls_stripping", severity="CRITICAL", session=s.session,
            rationale="Single mangled capability line against a server that advertises STARTTLS everywhere else.",
            evidence=[marks["ehlo_response"]],
        )
    )
    gt.expected_findings.append(
        ExpectedFinding(
            category="cleartext_credential_exposure", severity="CRITICAL", session=s.session,
            rationale="AUTH LOGIN without TLS.",
            evidence=[marks["auth_username"], marks["auth_password"]],
        )
    )

    # One unencrypted POP3 mailbox poll, the classic forgotten legacy client.
    s, marks = pop3_session(writer, lab, use_stls=False, cleartext_auth=True, seed=200)
    gt.sessions.append(s)
    gt.expected_findings.append(
        ExpectedFinding(
            category="cleartext_credential_exposure", severity="CRITICAL", session=s.session,
            rationale="POP3 USER/PASS without STLS.",
            evidence=[marks["user_command"], marks["pass_command"]],
        )
    )
    return gt


def scenario_nonstandard_port(writer: PcapWriter, lab: Lab) -> GroundTruth:
    """SMTP on port 8025 -- found by payload signature, not by port.

    Exists to prove candidate selection is not port-only. A mail service on an
    unexpected port is exactly the misconfiguration a posture assessment should
    surface, and a port-table lookup would silently skip it.
    """
    gt = GroundTruth(
        scenario="18-nonstandard-port",
        label="port_mismatch",
        description="SMTP server listening on 8025, detected from its greeting rather than its port.",
    )
    s, _ = smtp_session(writer, lab, port=8025, use_starttls=False, cleartext_auth=True)
    s.notes = "detected by payload signature on a non-registered port"
    gt.sessions.append(s)
    gt.expected_findings.append(
        ExpectedFinding(
            category="protocol_port_mismatch", severity="LOW", session=s.session,
            rationale="SMTP greeting observed on port 8025, which is not a registered mail port.",
        )
    )
    return gt


def scenario_dns_policy(writer: PcapWriter, lab: Lab) -> GroundTruth:
    """DNS policy correlation: the MTA-STS violation demo.

    partner.example publishes MTA-STS and the sender fetches it, then the
    session to its MX goes out in cleartext. No single session shows this --
    it only exists as a correlation between the DNS and the SMTP in the same
    capture, which is the whole point.
    """
    gt = GroundTruth(
        scenario="19-dns-policy",
        label="mta_sts_violation",
        description=(
            "Sender resolves MX, fetches an MTA-STS policy, then delivers in cleartext. "
            "A second domain publishes no policy at all."
        ),
        notes=(
            "Correlates DNS against observed TLS behaviour. Absence of DNS would mean "
            "'cannot assess', never 'not published'."
        ),
    )
    resolver = "10.10.2.1"

    # --- partner.example: policy published, then violated -----------------
    dnsgen.emit_lookup(writer, lab, client_ip=CLIENT_IP, resolver_ip=resolver,
        qname="partner.example", qtype=dnsgen.TYPE_MX, txid=0x1001,
        answers=[dnsgen.mx_answer(10, "mx1.partner.example")])
    dnsgen.emit_lookup(writer, lab, client_ip=CLIENT_IP, resolver_ip=resolver,
        qname="mx1.partner.example", qtype=dnsgen.TYPE_A, txid=0x1002,
        answers=[dnsgen.a_answer("10.10.2.60")])
    dnsgen.emit_lookup(writer, lab, client_ip=CLIENT_IP, resolver_ip=resolver,
        qname="_mta-sts.partner.example", qtype=dnsgen.TYPE_TXT, txid=0x1003,
        answers=[dnsgen.txt_answer("v=STSv1; id=20260302T091500;")])
    dnsgen.emit_lookup(writer, lab, client_ip=CLIENT_IP, resolver_ip=resolver,
        qname="_smtp._tls.partner.example", qtype=dnsgen.TYPE_TXT, txid=0x1004,
        answers=[], nxdomain=True)
    dnsgen.emit_lookup(writer, lab, client_ip=CLIENT_IP, resolver_ip=resolver,
        qname="_dmarc.partner.example", qtype=dnsgen.TYPE_TXT, txid=0x1005,
        answers=[dnsgen.txt_answer("v=DMARC1; p=none; rua=mailto:dmarc@partner.example")])

    PARTNER = ("10.10.2.60", "mx1.partner.example")
    s1, _ = smtp_session(writer, lab, server=PARTNER, port=25,
                         advertise_starttls=False, use_starttls=False, seed=210)
    s1.notes = "cleartext delivery despite a fetched MTA-STS policy"
    gt.sessions.append(s1)
    gt.expected_findings.append(
        ExpectedFinding(
            category="mta_sts_policy_violation", severity="CRITICAL", session=s1.session,
            rationale="MTA-STS policy retrieved for partner.example, then mail delivered without TLS.",
        )
    )
    gt.expected_findings.append(
        ExpectedFinding(
            category="dmarc_policy_none", severity="LOW", session="(domain-level)",
            rationale="partner.example publishes DMARC p=none, which enforces nothing.",
        )
    )

    # --- legacy.example: no policy published at all -----------------------
    dnsgen.emit_lookup(writer, lab, client_ip=CLIENT_IP, resolver_ip=resolver,
        qname="legacy.example", qtype=dnsgen.TYPE_MX, txid=0x2001,
        answers=[dnsgen.mx_answer(10, "mail.legacy.example")])
    dnsgen.emit_lookup(writer, lab, client_ip=CLIENT_IP, resolver_ip=resolver,
        qname="mail.legacy.example", qtype=dnsgen.TYPE_A, txid=0x2002,
        answers=[dnsgen.a_answer("10.10.2.61")])
    dnsgen.emit_lookup(writer, lab, client_ip=CLIENT_IP, resolver_ip=resolver,
        qname="_mta-sts.legacy.example", qtype=dnsgen.TYPE_TXT, txid=0x2003,
        answers=[], nxdomain=True)
    dnsgen.emit_lookup(writer, lab, client_ip=CLIENT_IP, resolver_ip=resolver,
        qname="_dmarc.legacy.example", qtype=dnsgen.TYPE_TXT, txid=0x2004,
        answers=[], nxdomain=True)

    LEGACY = ("10.10.2.61", "mail.legacy.example")
    s2, _ = smtp_session(writer, lab, server=LEGACY, port=25, seed=220)
    gt.sessions.append(s2)
    gt.expected_findings.append(
        ExpectedFinding(
            category="mta_sts_not_published", severity="MEDIUM", session="(domain-level)",
            rationale="legacy.example was queried for an MTA-STS policy and has none.",
        )
    )
    return gt


def scenario_certificates(writer: PcapWriter, lab: Lab) -> GroundTruth:
    """Real X.509 certificates carried in TLS 1.2 handshakes.

    TLS 1.2 on purpose: under TLS 1.3 the Certificate message is encrypted and
    there would be nothing to analyse. The certificates themselves are genuine
    -- generated by the same library a CA uses, committed as fixtures, with
    validity windows anchored to this capture's epoch so "expired" stays
    expired.
    """
    gt = GroundTruth(
        scenario="20-certificates",
        label="certificate_problems",
        description=(
            "Eight TLS 1.2 sessions to mail01, each presenting a different real "
            "certificate: valid, expired, expiring soon, not yet valid, wrong host, "
            "1024-bit key, SHA-1 signature, and self-signed."
        ),
        notes=(
            "Validity is judged against capture time, not wall-clock now. A "
            "certificate that expires after the traffic was recorded was not a "
            "problem at the time."
        ),
    )

    cases = [
        ("valid", None, None),
        ("expired", "certificate_expired", "CRITICAL"),
        ("expiring_soon", "certificate_expiring_soon", "MEDIUM"),
        ("not_yet_valid", "certificate_not_yet_valid", "HIGH"),
        ("wrong_host", "certificate_hostname_mismatch", "HIGH"),
        ("weak_key", "certificate_weak_key", "HIGH"),
        ("sha1_signed", "certificate_weak_signature", "HIGH"),
        ("self_signed", "certificate_self_signed", "MEDIUM"),
    ]

    for index, (fixture, category, severity) in enumerate(cases):
        s, marks = smtp_session(
            writer, lab, port=587,
            tls_version=tls.TLS1_2,
            cipher=tls.TLS_ECDHE_RSA_AES_256_GCM_SHA384,
            certificate=fixture, seed=300 + index,
        )
        s.notes = f"certificate fixture: {fixture}"
        gt.sessions.append(s)
        if category:
            gt.expected_findings.append(
                ExpectedFinding(
                    category=category, severity=severity, session=s.session,
                    rationale=f"Certificate fixture {fixture} presented over TLS 1.2.",
                    evidence=[marks["server_hello"]],
                )
            )
    return gt


SCENARIOS: dict[str, Callable[[PcapWriter, Lab], GroundTruth]] = {
    "01-secure-tls13": scenario_secure_tls13,
    "03-deprecated-tls": scenario_deprecated_tls,
    "07-no-forward-secrecy": scenario_no_forward_secrecy,
    "08-starttls-not-enforced": scenario_starttls_not_enforced,
    "09-starttls-stripping": scenario_starttls_stripping,
    "10-downgrade-fallback": scenario_downgrade_fallback,
    "11-credential-exposure": scenario_credential_exposure,
    "12-implicit-tls": scenario_implicit_tls,
    "13-enterprise-mixed": scenario_enterprise,
    "15-pqc-readiness": scenario_pqc_ready,
    "16-incomplete-evidence": scenario_incomplete,
    "17-segmented-starttls": scenario_split_command,
    "18-nonstandard-port": scenario_nonstandard_port,
    "19-dns-policy": scenario_dns_policy,
    "20-certificates": scenario_certificates,
}
