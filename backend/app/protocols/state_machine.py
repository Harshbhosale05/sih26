"""The Encryption State Machine.

Drives every email session through an explicit encryption lifecycle and records
each transition with the frame that caused it. The terminal state is the single
most important fact we derive about a session -- almost every finding in the
product is a statement about it.

Design rule: the machine never guesses. If the capture does not show what
happened, the session ends in an UNKNOWN-bearing state rather than an
optimistic one. A forensic tool that reports PASS on absent evidence is worse
than one that reports nothing.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from app.protocols.events import EventKind, ProtocolEvent


class EncryptionState(str, enum.Enum):
    UNKNOWN = "UNKNOWN"
    TCP_CONNECTED = "TCP_CONNECTED"
    PLAINTEXT_EMAIL = "PLAINTEXT_EMAIL"
    TLS_REQUESTED = "TLS_REQUESTED"
    TLS_NEGOTIATION = "TLS_NEGOTIATION"
    TLS_ESTABLISHED = "TLS_ESTABLISHED"
    IMPLICIT_TLS = "IMPLICIT_TLS"

    # Terminal states that carry a security verdict.
    STARTTLS_ADVERTISED_NOT_USED = "STARTTLS_ADVERTISED_NOT_USED"
    STARTTLS_NOT_ADVERTISED = "STARTTLS_NOT_ADVERTISED"
    STARTTLS_REJECTED = "STARTTLS_REJECTED"
    STARTTLS_NEGOTIATION_FAILED = "STARTTLS_NEGOTIATION_FAILED"
    PLAINTEXT_AFTER_FAILURE = "PLAINTEXT_AFTER_FAILURE"
    PLAINTEXT_THROUGHOUT = "PLAINTEXT_THROUGHOUT"
    TRUNCATED = "TRUNCATED"


# States in which the session's security posture cannot be judged from the
# capture alone. Downstream must emit UNKNOWN, never PASS or FAIL.
INDETERMINATE_STATES = {EncryptionState.UNKNOWN, EncryptionState.TRUNCATED}

# States where application data provably crossed the network in the clear.
CLEARTEXT_STATES = {
    EncryptionState.PLAINTEXT_THROUGHOUT,
    EncryptionState.PLAINTEXT_AFTER_FAILURE,
    EncryptionState.STARTTLS_ADVERTISED_NOT_USED,
    EncryptionState.STARTTLS_NOT_ADVERTISED,
    EncryptionState.STARTTLS_REJECTED,
}


@dataclass
class Transition:
    from_state: EncryptionState
    to_state: EncryptionState
    frame_number: int
    timestamp: float
    trigger: str

    def serialise(self) -> dict:
        return {
            "from": self.from_state.value,
            "to": self.to_state.value,
            "frame": self.frame_number,
            "timestamp": self.timestamp,
            "trigger": self.trigger,
        }


@dataclass
class EncryptionAnalysis:
    final_state: EncryptionState
    transitions: list[Transition] = field(default_factory=list)
    upgrade_advertised: bool = False
    upgrade_advertised_mangled: bool = False
    upgrade_requested: bool = False
    upgrade_succeeded: bool = False
    tls_established: bool = False
    cleartext_auth_observed: bool = False
    cleartext_mail_observed: bool = False
    credential_events: list[ProtocolEvent] = field(default_factory=list)
    advertised_capabilities: list[str] = field(default_factory=list)

    @property
    def is_indeterminate(self) -> bool:
        return self.final_state in INDETERMINATE_STATES

    @property
    def is_cleartext(self) -> bool:
        return self.final_state in CLEARTEXT_STATES


def analyse(
    events: list[ProtocolEvent],
    *,
    implicit_tls: bool,
    session_complete: bool,
    has_gaps: bool,
) -> EncryptionAnalysis:
    """Run the state machine over an ordered event stream.

    `session_complete` means the capture contains the connection's termination.
    `has_gaps` means the reassembler found missing bytes. Either being false
    caps the result at a state that admits uncertainty.
    """
    state = EncryptionState.IMPLICIT_TLS if implicit_tls else EncryptionState.TCP_CONNECTED
    result = EncryptionAnalysis(final_state=state)

    def go(to: EncryptionState, event: ProtocolEvent, trigger: str) -> None:
        nonlocal state
        if to is state:
            return
        result.transitions.append(
            Transition(state, to, event.frame_number, event.timestamp, trigger)
        )
        state = to

    for event in events:
        kind = event.kind

        if kind == EventKind.GREETING and state is EncryptionState.TCP_CONNECTED:
            go(EncryptionState.PLAINTEXT_EMAIL, event, "server greeting")

        elif kind == EventKind.UPGRADE_ADVERTISED:
            result.upgrade_advertised = True
            keyword = event.metadata.get("keyword")
            if keyword and keyword not in result.advertised_capabilities:
                result.advertised_capabilities.append(keyword)

        elif kind == EventKind.UPGRADE_ADVERTISED_MANGLED:
            # Recorded, but NOT treated as "advertised". The session genuinely
            # never received a usable upgrade offer -- that is the whole point
            # of the attack.
            result.upgrade_advertised_mangled = True

        elif kind == EventKind.UPGRADE_REQUESTED:
            result.upgrade_requested = True
            go(EncryptionState.TLS_REQUESTED, event, f"{event.metadata.get('command', 'upgrade')} requested")

        elif kind == EventKind.UPGRADE_ACCEPTED:
            go(EncryptionState.TLS_NEGOTIATION, event, "server accepted upgrade")

        elif kind == EventKind.UPGRADE_REJECTED:
            go(EncryptionState.STARTTLS_REJECTED, event,
               f"server rejected upgrade ({event.metadata.get('reply_code', '')})".strip())

        elif kind == EventKind.TLS_CLIENT_HELLO:
            # Implicit TLS keeps its own terminal state: "this connection never
            # had a plaintext phase" is a distinct and better posture than
            # "this connection successfully upgraded", and collapsing both into
            # TLS_ESTABLISHED would discard it.
            if state in (EncryptionState.TLS_REQUESTED, EncryptionState.TLS_NEGOTIATION,
                         EncryptionState.TCP_CONNECTED):
                go(EncryptionState.TLS_NEGOTIATION, event, "ClientHello")

        elif kind == EventKind.TLS_SERVER_HELLO:
            if state is not EncryptionState.IMPLICIT_TLS:
                go(EncryptionState.TLS_NEGOTIATION, event, "ServerHello")

        elif kind == EventKind.TLS_APPLICATION_DATA:
            # The strongest honest signal available passively. TLS 1.3 encrypts
            # Finished, so application data flowing is as close to "established"
            # as a passive observer can get.
            if state is EncryptionState.TLS_NEGOTIATION:
                go(EncryptionState.TLS_ESTABLISHED, event, "encrypted application data")
                result.tls_established = True
                result.upgrade_succeeded = result.upgrade_requested
            elif state is EncryptionState.IMPLICIT_TLS:
                result.tls_established = True

        elif kind == EventKind.AUTH_CREDENTIAL:
            if not result.tls_established:
                result.cleartext_auth_observed = True
                result.credential_events.append(event)

        elif kind == EventKind.MAIL_TRANSACTION:
            if not result.tls_established:
                result.cleartext_mail_observed = True

        elif kind == EventKind.MAILBOX_ACCESS:
            if not result.tls_established:
                result.cleartext_mail_observed = True

    result.final_state = _terminal_state(
        state, result, session_complete=session_complete, has_gaps=has_gaps
    )
    return result


def _terminal_state(
    state: EncryptionState,
    result: EncryptionAnalysis,
    *,
    session_complete: bool,
    has_gaps: bool,
) -> EncryptionState:
    """Resolve the running state into a verdict-bearing terminal state."""
    if state in (EncryptionState.TLS_ESTABLISHED, EncryptionState.IMPLICIT_TLS):
        return state

    # Evidence quality gates everything below. An incomplete capture cannot
    # support a claim about what the session ultimately did.
    if has_gaps or not session_complete:
        if state in (EncryptionState.TLS_NEGOTIATION, EncryptionState.TLS_REQUESTED):
            return EncryptionState.TRUNCATED
        if state in (EncryptionState.TCP_CONNECTED, EncryptionState.UNKNOWN):
            return EncryptionState.TRUNCATED

    if state is EncryptionState.TLS_NEGOTIATION:
        # Handshake started, never carried application data.
        return EncryptionState.STARTTLS_NEGOTIATION_FAILED

    if state is EncryptionState.STARTTLS_REJECTED:
        # Refused -- but did the client give up, or send anyway? The second is
        # materially worse and deserves its own state.
        if result.cleartext_auth_observed or result.cleartext_mail_observed:
            return EncryptionState.PLAINTEXT_AFTER_FAILURE
        return EncryptionState.STARTTLS_REJECTED

    if state is EncryptionState.TLS_REQUESTED:
        return EncryptionState.STARTTLS_NEGOTIATION_FAILED

    if state is EncryptionState.PLAINTEXT_EMAIL:
        if result.upgrade_advertised:
            return EncryptionState.STARTTLS_ADVERTISED_NOT_USED
        if result.cleartext_auth_observed or result.cleartext_mail_observed:
            return EncryptionState.STARTTLS_NOT_ADVERTISED
        return EncryptionState.PLAINTEXT_THROUGHOUT

    if state is EncryptionState.TCP_CONNECTED:
        return EncryptionState.TRUNCATED

    return state
