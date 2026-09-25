"""POP3 dialogue parser (RFC 1939, RFC 2595).

POP3 upgrades with **STLS**, not STARTTLS. The upgrade keyword is carried as
data here rather than hardcoded across the codebase, so the state machine stays
protocol-agnostic.
"""

from __future__ import annotations

from app.flows import S2C, Line
from app.protocols import credentials
from app.protocols.events import EventKind, ProtocolEvent

UPGRADE_COMMAND = "STLS"


def parse(lines: list[Line]) -> list[ProtocolEvent]:
    events: list[ProtocolEvent] = []
    saw_greeting = False
    in_capa = False
    pending_upgrade = False
    last_username: str | None = None

    for line in lines:
        raw = line.raw
        upper = raw.upper()
        text = line.text

        if line.direction == S2C:
            if not saw_greeting and upper.startswith(b"+OK"):
                saw_greeting = True
                events.append(
                    ProtocolEvent(
                        EventKind.GREETING, line.frame_number, line.timestamp,
                        line.direction, detail=text, offset=line.offset,
                        metadata={"banner": text[3:].strip()},
                    )
                )
                continue

            if pending_upgrade:
                kind = (
                    EventKind.UPGRADE_ACCEPTED if upper.startswith(b"+OK")
                    else EventKind.UPGRADE_REJECTED
                )
                events.append(
                    ProtocolEvent(
                        kind, line.frame_number, line.timestamp, line.direction,
                        detail=text, offset=line.offset,
                    )
                )
                pending_upgrade = False
                continue

            if in_capa:
                if raw.strip() == b".":
                    in_capa = False
                elif upper.strip() == UPGRADE_COMMAND.encode():
                    events.append(
                        ProtocolEvent(
                            EventKind.UPGRADE_ADVERTISED, line.frame_number,
                            line.timestamp, line.direction, detail=text,
                            offset=line.offset, metadata={"keyword": UPGRADE_COMMAND},
                        )
                    )
                continue

            if upper.startswith(b"+OK CAPABILITY") or upper.startswith(b"+OK CAPA"):
                in_capa = True
            continue

        # ---- client -> server ----
        if upper.startswith(b"CAPA"):
            in_capa = True
            events.append(
                ProtocolEvent(
                    EventKind.CAPABILITY_REQUEST, line.frame_number, line.timestamp,
                    line.direction, detail=text, offset=line.offset,
                )
            )
        elif upper.startswith(UPGRADE_COMMAND.encode()):
            pending_upgrade = True
            events.append(
                ProtocolEvent(
                    EventKind.UPGRADE_REQUESTED, line.frame_number, line.timestamp,
                    line.direction, detail=text, offset=line.offset,
                    metadata={"command": UPGRADE_COMMAND},
                )
            )
        elif upper.startswith(b"USER "):
            last_username = text[5:].strip()
            events.append(
                ProtocolEvent(
                    EventKind.AUTH_REQUESTED, line.frame_number, line.timestamp,
                    line.direction, detail="USER", offset=line.offset,
                    metadata={"mechanism": "USER/PASS"},
                )
            )
        elif upper.startswith(b"PASS "):
            evidence = credentials.from_literal(
                text[5:].strip(), "POP3 USER/PASS", last_username
            )
            events.append(
                ProtocolEvent(
                    EventKind.AUTH_CREDENTIAL, line.frame_number, line.timestamp,
                    line.direction, detail="POP3 PASS credential",
                    offset=line.offset, metadata=evidence.serialise(),
                )
            )
        elif upper.startswith((b"STAT", b"LIST", b"RETR", b"UIDL", b"TOP ")):
            events.append(
                ProtocolEvent(
                    EventKind.MAILBOX_ACCESS, line.frame_number, line.timestamp,
                    line.direction, detail=text.split()[0], offset=line.offset,
                )
            )
        elif upper.startswith(b"QUIT"):
            events.append(
                ProtocolEvent(
                    EventKind.SESSION_END, line.frame_number, line.timestamp,
                    line.direction, detail="QUIT", offset=line.offset,
                )
            )

    return events
