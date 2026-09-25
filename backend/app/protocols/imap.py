"""IMAP dialogue parser (RFC 3501, RFC 2595).

IMAP commands are tag-prefixed (`a001 STARTTLS`), so the verb is the second
token, not the first -- parsing it like SMTP silently finds nothing.
"""

from __future__ import annotations

import re

from app.flows import S2C, Line
from app.protocols import credentials
from app.protocols.events import EventKind, ProtocolEvent

_STARTTLS_IN_CAPS = re.compile(rb"\bSTARTTLS\b", re.IGNORECASE)
_LOGINDISABLED = re.compile(rb"\bLOGINDISABLED\b", re.IGNORECASE)
# a003 LOGIN "user" "pass"  |  a003 LOGIN user pass
_LOGIN = re.compile(
    r'^\S+\s+LOGIN\s+(?:"([^"]*)"|(\S+))\s+(?:"([^"]*)"|(\S+))\s*$', re.IGNORECASE
)


def _split_tag(text: str) -> tuple[str, str, str]:
    """Return (tag, verb, remainder)."""
    parts = text.split(None, 2)
    if len(parts) == 1:
        return parts[0], "", ""
    if len(parts) == 2:
        return parts[0], parts[1].upper(), ""
    return parts[0], parts[1].upper(), parts[2]


def parse(lines: list[Line]) -> list[ProtocolEvent]:
    events: list[ProtocolEvent] = []
    saw_greeting = False
    pending_tag: str | None = None
    awaiting_sasl = False

    for line in lines:
        raw = line.raw
        text = line.text

        if line.direction == S2C:
            if not saw_greeting and (raw.startswith(b"* OK") or raw.startswith(b"* PREAUTH")):
                saw_greeting = True
                events.append(
                    ProtocolEvent(
                        EventKind.GREETING, line.frame_number, line.timestamp,
                        line.direction, detail=text, offset=line.offset,
                        metadata={"banner": text[4:].strip()},
                    )
                )

            if raw.upper().startswith(b"* CAPABILITY") or b"[CAPABILITY" in raw.upper():
                advertised = bool(_STARTTLS_IN_CAPS.search(raw))
                events.append(
                    ProtocolEvent(
                        EventKind.CAPABILITY_RESPONSE, line.frame_number, line.timestamp,
                        line.direction, detail=text, offset=line.offset,
                        metadata={
                            "starttls": advertised,
                            "login_disabled": bool(_LOGINDISABLED.search(raw)),
                        },
                    )
                )
                if advertised:
                    events.append(
                        ProtocolEvent(
                            EventKind.UPGRADE_ADVERTISED, line.frame_number,
                            line.timestamp, line.direction, detail=text,
                            offset=line.offset, metadata={"keyword": "STARTTLS"},
                        )
                    )

            if pending_tag and text.upper().startswith(pending_tag.upper() + " "):
                status = text[len(pending_tag):].strip().split(None, 1)[0].upper()
                kind = (
                    EventKind.UPGRADE_ACCEPTED if status == "OK"
                    else EventKind.UPGRADE_REJECTED
                )
                events.append(
                    ProtocolEvent(
                        kind, line.frame_number, line.timestamp, line.direction,
                        detail=text, offset=line.offset, metadata={"status": status},
                    )
                )
                pending_tag = None
            continue

        # ---- client -> server ----
        tag, verb, remainder = _split_tag(text)

        if awaiting_sasl:
            evidence = credentials.from_base64_token(
                text.strip(), "IMAP AUTHENTICATE", is_username=True
            )
            events.append(
                ProtocolEvent(
                    EventKind.AUTH_CREDENTIAL, line.frame_number, line.timestamp,
                    line.direction, detail="IMAP AUTHENTICATE credential",
                    offset=line.offset, metadata=evidence.serialise(),
                )
            )
            awaiting_sasl = False
            continue

        if verb == "CAPABILITY":
            events.append(
                ProtocolEvent(
                    EventKind.CAPABILITY_REQUEST, line.frame_number, line.timestamp,
                    line.direction, detail=text, offset=line.offset,
                )
            )
        elif verb == "STARTTLS":
            pending_tag = tag
            events.append(
                ProtocolEvent(
                    EventKind.UPGRADE_REQUESTED, line.frame_number, line.timestamp,
                    line.direction, detail=text, offset=line.offset,
                    metadata={"command": "STARTTLS"},
                )
            )
        elif verb == "LOGIN":
            match = _LOGIN.match(text)
            username = (match.group(1) or match.group(2)) if match else ""
            password = (match.group(3) or match.group(4)) if match else ""
            events.append(
                ProtocolEvent(
                    EventKind.AUTH_REQUESTED, line.frame_number, line.timestamp,
                    line.direction, detail="LOGIN", offset=line.offset,
                    metadata={"mechanism": "LOGIN"},
                )
            )
            if password:
                # IMAP LOGIN sends the password as a bare literal: no encoding
                # at all, not even base64.
                evidence = credentials.from_literal(password, "IMAP LOGIN", username)
                events.append(
                    ProtocolEvent(
                        EventKind.AUTH_CREDENTIAL, line.frame_number, line.timestamp,
                        line.direction, detail="IMAP LOGIN credential",
                        offset=line.offset, metadata=evidence.serialise(),
                    )
                )
        elif verb == "AUTHENTICATE":
            mechanism = remainder.split()[0].upper() if remainder else "UNKNOWN"
            events.append(
                ProtocolEvent(
                    EventKind.AUTH_REQUESTED, line.frame_number, line.timestamp,
                    line.direction, detail=f"AUTHENTICATE {mechanism}",
                    offset=line.offset, metadata={"mechanism": mechanism},
                )
            )
            awaiting_sasl = True
        elif verb in ("SELECT", "EXAMINE", "FETCH", "LIST"):
            events.append(
                ProtocolEvent(
                    EventKind.MAILBOX_ACCESS, line.frame_number, line.timestamp,
                    line.direction, detail=verb, offset=line.offset,
                )
            )
        elif verb == "LOGOUT":
            events.append(
                ProtocolEvent(
                    EventKind.SESSION_END, line.frame_number, line.timestamp,
                    line.direction, detail="LOGOUT", offset=line.offset,
                )
            )

    return events
