"""SMTP dialogue parser (RFC 5321, RFC 3207)."""

from __future__ import annotations

import re

from app.flows import C2S, S2C, Line
from app.protocols import credentials
from app.protocols.events import EventKind, ProtocolEvent

# "250-STARTTLS" / "250 STARTTLS", case-insensitive per RFC 5321.
_STARTTLS_CAPABILITY = re.compile(rb"^250[- ]STARTTLS\s*$", re.IGNORECASE)
_CAPABILITY_LINE = re.compile(rb"^250[- ]")
_AUTH_CAPABILITY = re.compile(rb"^250[- ]AUTH\s+(.+)$", re.IGNORECASE)


def _is_mangled_capability(raw: bytes) -> bool:
    """Detect a capability token that has been overwritten in place.

    An on-path stripper rewrites `250-STARTTLS` to something of identical
    length so TCP sequence numbers stay valid -- `250-XXXXXXXA` is the
    canonical observed form. The tell is a capability token that is not a
    plausible ESMTP keyword: repeated filler characters, or non-ASCII bytes
    where a keyword belongs.

    This flags the *shape*; the decision that stripping occurred belongs to the
    cross-session detector, which can see that the same server advertises
    STARTTLS normally elsewhere in the capture.
    """
    if not _CAPABILITY_LINE.match(raw):
        return False

    token = raw[4:].strip()
    if not token:
        return False

    # Non-ASCII in an ESMTP keyword is never legitimate.
    if any(b > 0x7E or (b < 0x20 and b not in (0x09,)) for b in token):
        return True

    # A run of one repeated character covering most of the token is the
    # signature of in-place overwriting, not a real keyword.
    keyword = token.split()[0] if token.split() else token
    if len(keyword) >= 6:
        most_common = max(set(keyword), key=keyword.count)
        if keyword.count(most_common) >= len(keyword) - 1:
            return True

    return False


def parse(lines: list[Line]) -> list[ProtocolEvent]:
    events: list[ProtocolEvent] = []
    awaiting_credential: str | None = None
    saw_greeting = False

    for line in lines:
        raw = line.raw
        upper = raw.upper()

        if line.direction == S2C:
            if not saw_greeting and upper.startswith(b"220"):
                saw_greeting = True
                events.append(
                    ProtocolEvent(
                        EventKind.GREETING, line.frame_number, line.timestamp,
                        line.direction, detail=line.text, offset=line.offset,
                        metadata={"banner": line.text[4:].strip()},
                    )
                )
                continue

            if _STARTTLS_CAPABILITY.match(raw):
                events.append(
                    ProtocolEvent(
                        EventKind.UPGRADE_ADVERTISED, line.frame_number, line.timestamp,
                        line.direction, detail=line.text, offset=line.offset,
                        metadata={"keyword": "STARTTLS"},
                    )
                )
                continue

            if _is_mangled_capability(raw):
                events.append(
                    ProtocolEvent(
                        EventKind.UPGRADE_ADVERTISED_MANGLED, line.frame_number,
                        line.timestamp, line.direction, detail=line.text,
                        offset=line.offset,
                        metadata={"observed_token": line.text[4:].strip()},
                    )
                )
                continue

            match = _AUTH_CAPABILITY.match(raw)
            if match:
                events.append(
                    ProtocolEvent(
                        EventKind.CAPABILITY_RESPONSE, line.frame_number, line.timestamp,
                        line.direction, detail=line.text, offset=line.offset,
                        metadata={"auth_mechanisms": match.group(1).decode(
                            "utf-8", "replace").split()},
                    )
                )
                continue

            if upper.startswith(b"220") and b"TLS" in upper:
                events.append(
                    ProtocolEvent(
                        EventKind.UPGRADE_ACCEPTED, line.frame_number, line.timestamp,
                        line.direction, detail=line.text, offset=line.offset,
                    )
                )
            elif upper.startswith((b"454", b"502", b"500", b"421")) and awaiting_upgrade(events):
                events.append(
                    ProtocolEvent(
                        EventKind.UPGRADE_REJECTED, line.frame_number, line.timestamp,
                        line.direction, detail=line.text, offset=line.offset,
                        metadata={"reply_code": line.text[:3]},
                    )
                )
            elif upper.startswith(b"235"):
                events.append(
                    ProtocolEvent(
                        EventKind.AUTH_SUCCEEDED, line.frame_number, line.timestamp,
                        line.direction, detail=line.text, offset=line.offset,
                    )
                )
            elif upper.startswith(b"535"):
                events.append(
                    ProtocolEvent(
                        EventKind.AUTH_FAILED, line.frame_number, line.timestamp,
                        line.direction, detail=line.text, offset=line.offset,
                    )
                )
            elif upper.startswith(b"334"):
                # Server prompt inside AUTH LOGIN: base64 of "Username:"/"Password:".
                prompt = raw[4:].strip()
                awaiting_credential = (
                    "username" if prompt == b"VXNlcm5hbWU6" else "password"
                )
            continue

        # ---- client -> server ----
        if upper.startswith((b"EHLO", b"HELO")):
            events.append(
                ProtocolEvent(
                    EventKind.CAPABILITY_REQUEST, line.frame_number, line.timestamp,
                    line.direction, detail=line.text, offset=line.offset,
                    metadata={"identity": line.text[5:].strip()},
                )
            )
        elif upper.startswith(b"STARTTLS"):
            events.append(
                ProtocolEvent(
                    EventKind.UPGRADE_REQUESTED, line.frame_number, line.timestamp,
                    line.direction, detail=line.text, offset=line.offset,
                    metadata={"command": "STARTTLS"},
                )
            )
        elif upper.startswith(b"AUTH "):
            parts = line.text.split()
            mechanism = parts[1].upper() if len(parts) > 1 else "UNKNOWN"
            event = ProtocolEvent(
                EventKind.AUTH_REQUESTED, line.frame_number, line.timestamp,
                line.direction, detail=f"AUTH {mechanism}", offset=line.offset,
                metadata={"mechanism": mechanism},
            )
            events.append(event)
            # AUTH PLAIN carries the credential inline on the same line.
            if mechanism == "PLAIN" and len(parts) > 2:
                evidence = credentials.from_plain_sasl(parts[2])
                events.append(
                    ProtocolEvent(
                        EventKind.AUTH_CREDENTIAL, line.frame_number, line.timestamp,
                        line.direction, detail="AUTH PLAIN credential",
                        offset=line.offset, metadata=evidence.serialise(),
                    )
                )
            elif mechanism == "LOGIN":
                awaiting_credential = "username"
        elif awaiting_credential:
            evidence = credentials.from_base64_token(
                line.text.strip(), "AUTH LOGIN",
                is_username=(awaiting_credential == "username"),
            )
            events.append(
                ProtocolEvent(
                    EventKind.AUTH_CREDENTIAL, line.frame_number, line.timestamp,
                    line.direction, detail=f"AUTH LOGIN {awaiting_credential}",
                    offset=line.offset,
                    metadata={**evidence.serialise(), "field": awaiting_credential},
                )
            )
            awaiting_credential = None
        elif upper.startswith((b"MAIL FROM", b"RCPT TO", b"DATA")):
            events.append(
                ProtocolEvent(
                    EventKind.MAIL_TRANSACTION, line.frame_number, line.timestamp,
                    line.direction, detail=line.text.split(":")[0].strip(),
                    offset=line.offset,
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


def awaiting_upgrade(events: list[ProtocolEvent]) -> bool:
    """True if an upgrade was requested and not yet resolved.

    Without this, an unrelated 4xx/5xx reply elsewhere in the dialogue would be
    misread as a STARTTLS rejection.
    """
    for event in reversed(events):
        if event.kind == EventKind.UPGRADE_REQUESTED:
            return True
        if event.kind in (EventKind.UPGRADE_ACCEPTED, EventKind.UPGRADE_REJECTED):
            return False
    return False
