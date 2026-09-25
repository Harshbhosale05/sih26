"""Protocol events: the common vocabulary between parsers and the state machine.

SMTP, IMAP and POP3 say the same things in different words -- "STARTTLS" vs
"STLS", "250-STARTTLS" vs "* CAPABILITY ... STARTTLS" vs "STLS" in a CAPA list.
Each parser translates its own syntax into these events, so the encryption
state machine is written once and is protocol-agnostic.

Every event carries its frame number. An event that cannot say which frame it
came from is not evidence, and would be unusable downstream.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class EventKind(str, enum.Enum):
    GREETING = "greeting"
    CAPABILITY_REQUEST = "capability_request"
    CAPABILITY_RESPONSE = "capability_response"
    UPGRADE_ADVERTISED = "upgrade_advertised"
    UPGRADE_ADVERTISED_MANGLED = "upgrade_advertised_mangled"
    UPGRADE_REQUESTED = "upgrade_requested"
    UPGRADE_ACCEPTED = "upgrade_accepted"
    UPGRADE_REJECTED = "upgrade_rejected"
    AUTH_REQUESTED = "auth_requested"
    AUTH_CREDENTIAL = "auth_credential"
    AUTH_SUCCEEDED = "auth_succeeded"
    AUTH_FAILED = "auth_failed"
    MAIL_TRANSACTION = "mail_transaction"
    MAILBOX_ACCESS = "mailbox_access"
    TLS_CLIENT_HELLO = "tls_client_hello"
    TLS_SERVER_HELLO = "tls_server_hello"
    TLS_APPLICATION_DATA = "tls_application_data"
    TLS_ALERT = "tls_alert"
    SESSION_END = "session_end"


@dataclass
class ProtocolEvent:
    kind: EventKind
    frame_number: int
    timestamp: float
    direction: str
    # The line or a redacted summary of it. Never a raw credential -- see
    # `redacted` and the credential handling in the parsers.
    detail: str = ""
    offset: int = 0
    metadata: dict = field(default_factory=dict)

    def serialise(self) -> dict:
        return {
            "kind": self.kind.value,
            "frame": self.frame_number,
            "timestamp": self.timestamp,
            "direction": self.direction,
            "detail": self.detail,
            "metadata": self.metadata,
        }
