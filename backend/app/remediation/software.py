"""Identify mail server software from what it said on the wire.

Remediation is only actionable when it is written for the software actually in
front of the administrator: "disable TLS 1.0" means a different line in Postfix,
Exim, Exchange and Dovecot. The SMTP banner, IMAP greeting and POP3 greeting
usually name the product; when they do not, we say so and fall back to generic
OpenSSL-level guidance rather than guessing.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict

from app.models.session import EmailSession

# (key, display name, family, pattern). First match wins, so specific before generic.
_SIGNATURES = [
    ("exchange", "Microsoft Exchange", "smtp", re.compile(r"Microsoft ESMTP|Microsoft Exchange|Exchange Server", re.I)),
    ("postfix", "Postfix", "smtp", re.compile(r"\bPostfix\b", re.I)),
    ("exim", "Exim", "smtp", re.compile(r"\bExim\b", re.I)),
    ("sendmail", "Sendmail", "smtp", re.compile(r"\bSendmail\b", re.I)),
    ("zimbra", "Zimbra", "smtp", re.compile(r"\bZimbra\b", re.I)),
    ("dovecot", "Dovecot", "mailbox", re.compile(r"\bDovecot\b", re.I)),
    ("courier", "Courier", "mailbox", re.compile(r"\bCourier\b", re.I)),
    ("cyrus", "Cyrus IMAP", "mailbox", re.compile(r"\bCyrus\b", re.I)),
]

_VERSION = re.compile(r"(\d+\.\d+(?:\.\d+)?)")


def _greetings(session: EmailSession) -> list[str]:
    lines = [session.server_banner] if session.server_banner else []
    lines += [
        e.get("detail") or ""
        for e in (session.events or [])
        if e.get("kind") in ("greeting", "capability_response") and e.get("direction") == "s2c"
    ]
    return [line for line in lines if line]


def identify(session: EmailSession) -> dict:
    text = " ".join(_greetings(session))
    for key, name, family, pattern in _SIGNATURES:
        match = pattern.search(text)
        if match:
            version = _VERSION.search(text[match.end(): match.end() + 40])
            return {
                "key": key, "name": name, "family": family,
                "version": version.group(1) if version else None,
                "evidence": next((g for g in _greetings(session) if pattern.search(g)), text)[:160],
                "confidence": "banner",
            }
    fallback = "generic_smtp" if session.protocol == "SMTP" else "generic_mailbox"
    return {
        "key": fallback,
        "name": "Unidentified SMTP server" if session.protocol == "SMTP" else "Unidentified IMAP/POP3 server",
        "family": "smtp" if session.protocol == "SMTP" else "mailbox",
        "version": None,
        "evidence": (text or "no banner observed")[:160],
        "confidence": "none",
    }


def hostname_for(session: EmailSession) -> str:
    """Best name for the server in commands: SNI, then banner host, then IP."""
    if session.tls_sni:
        return session.tls_sni
    banner = (session.server_banner or "").split()
    if banner and "." in banner[0] and not banner[0][0].isdigit():
        return banner[0]
    return session.server_ip


def by_server(sessions: list[EmailSession]) -> dict[str, dict]:
    """Software per server:port, picked by majority across its sessions."""
    seen: dict[str, list[dict]] = defaultdict(list)
    hosts: dict[str, Counter] = defaultdict(Counter)
    protocols: dict[str, Counter] = defaultdict(Counter)
    for s in sessions:
        if not s.protocol:
            continue
        key = f"{s.server_ip}:{s.server_port}"
        seen[key].append(identify(s))
        hosts[key][hostname_for(s)] += 1
        protocols[key][s.protocol] += 1

    result = {}
    for key, ids in seen.items():
        best = Counter(i["key"] for i in ids).most_common(1)[0][0]
        chosen = next(i for i in ids if i["key"] == best)
        result[key] = {
            **chosen,
            "server": key,
            "hostname": hosts[key].most_common(1)[0][0],
            "port": int(key.rsplit(":", 1)[1]),
            "protocol": protocols[key].most_common(1)[0][0],
        }
    return result
