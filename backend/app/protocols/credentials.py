"""Credential detection that never retains the credential.

Finding cleartext authentication is the single highest-impact thing in a mail
capture. Storing what we found would make this tool a liability -- a database of
plaintext passwords harvested from a customer's network.

So we record proof that it happened and nothing that could be replayed:
  * the username, redacted to first character + domain
  * a short sha256 prefix, enough for an admin to confirm *which* credential
    without us holding it
  * the length

The full secret is never written to the database, the logs, or a report.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class CredentialEvidence:
    mechanism: str
    username_redacted: str | None
    credential_sha256_prefix: str
    credential_length: int
    encoding: str

    def serialise(self) -> dict:
        return {
            "mechanism": self.mechanism,
            "username_redacted": self.username_redacted,
            "credential_sha256_prefix": self.credential_sha256_prefix,
            "credential_length": self.credential_length,
            "encoding": self.encoding,
            "credential_stored": False,
        }


def redact_username(username: str) -> str:
    """j****@corp.local -- identifies the account without exposing it."""
    if not username:
        return ""
    local, sep, domain = username.partition("@")
    if not local:
        return "****"
    masked = local[0] + "*" * max(len(local) - 1, 3)
    return f"{masked}{sep}{domain}" if sep else masked


def _fingerprint(secret: str) -> tuple[str, int]:
    digest = hashlib.sha256(secret.encode("utf-8", errors="replace")).hexdigest()
    return digest[:6], len(secret)


def from_base64_token(token: str, mechanism: str, *, is_username: bool) -> CredentialEvidence:
    """Evidence from a base64 SASL token (SMTP AUTH LOGIN / IMAP AUTHENTICATE).

    Base64 is an encoding, not encryption -- these bytes are the credential in
    the clear. We decode only far enough to redact the username, then discard.
    """
    try:
        decoded = base64.b64decode(token, validate=True).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        decoded = token

    prefix, length = _fingerprint(decoded)
    return CredentialEvidence(
        mechanism=mechanism,
        username_redacted=redact_username(decoded) if is_username else None,
        credential_sha256_prefix=prefix,
        credential_length=length,
        encoding="base64",
    )


def from_plain_sasl(token: str) -> CredentialEvidence:
    """AUTH PLAIN: base64 of authzid\\0authcid\\0password, all in one token."""
    try:
        decoded = base64.b64decode(token, validate=True).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        decoded = token

    parts = decoded.split("\x00")
    username = parts[1] if len(parts) >= 2 else ""
    password = parts[2] if len(parts) >= 3 else ""

    prefix, length = _fingerprint(password or decoded)
    return CredentialEvidence(
        mechanism="AUTH PLAIN",
        username_redacted=redact_username(username),
        credential_sha256_prefix=prefix,
        credential_length=length,
        encoding="base64",
    )


def from_literal(secret: str, mechanism: str, username: str | None = None) -> CredentialEvidence:
    """POP3 PASS / IMAP LOGIN -- not even base64, just the password on the wire."""
    prefix, length = _fingerprint(secret)
    return CredentialEvidence(
        mechanism=mechanism,
        username_redacted=redact_username(username) if username else None,
        credential_sha256_prefix=prefix,
        credential_length=length,
        encoding="cleartext",
    )
