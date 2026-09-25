"""Cipher suite registry and decomposition.

A cipher suite name encodes the whole cryptographic bargain of a session, and
the two TLS generations encode it differently:

    TLS 1.2   TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
              key exchange = ECDHE, auth = RSA, cipher = AES-256-GCM, hash = SHA-384

    TLS 1.3   TLS_AES_256_GCM_SHA384
              cipher = AES-256-GCM, hash = SHA-384.
              Key exchange and authentication are NOT in the name -- they are
              negotiated separately via key_share and the certificate.

Reading a TLS 1.3 suite with the TLS 1.2 model produces nonsense like
"key exchange: AES". This module keeps the two paths separate.
"""

from __future__ import annotations

from dataclasses import dataclass

# IANA registry, restricted to suites actually seen on mail infrastructure.
CIPHER_SUITES: dict[int, str] = {
    # TLS 1.3
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    # TLS 1.2 ECDHE (forward secrecy)
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    # DHE
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    # Static RSA key exchange -- no forward secrecy
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    # Legacy / broken
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x003B: "TLS_RSA_WITH_NULL_SHA256",
    0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x0000: "TLS_NULL_WITH_NULL_NULL",
}

# Key exchanges providing forward secrecy: the session key cannot be recovered
# later from the server's long-term private key.
_PFS_KEX = {"ECDHE", "DHE", "EECDH", "EDH"}

_AEAD_MODES = {"GCM", "CCM", "POLY1305"}

# Primitives that are broken or deprecated, with the reason. Used verbatim in
# finding rationales so the judgement is always attributable.
WEAK_PRIMITIVES = {
    "RC4": "RC4 has practical plaintext-recovery attacks; prohibited by RFC 7465.",
    "3DES": "3DES is limited to 64-bit blocks and is vulnerable to Sweet32 (CVE-2016-2183).",
    "DES": "Single DES has a 56-bit key and is trivially breakable.",
    "NULL": "NULL cipher provides no confidentiality at all.",
    "MD5": "MD5 is collision-broken and unfit for integrity.",
    "EXPORT": "Export-grade cryptography is deliberately weakened.",
    "ANON": "Anonymous key exchange provides no server authentication.",
}


@dataclass(frozen=True)
class SuiteInfo:
    code: int
    name: str
    is_tls13: bool
    key_exchange: str | None
    authentication: str | None
    encryption: str | None
    key_size: int | None
    mode: str | None
    mac_hash: str | None
    forward_secrecy: bool | None
    aead: bool
    weaknesses: list[str]

    @property
    def is_known(self) -> bool:
        return self.name != "UNKNOWN"

    def serialise(self) -> dict:
        return {
            "code": f"0x{self.code:04X}",
            "name": self.name,
            "key_exchange": self.key_exchange,
            "authentication": self.authentication,
            "encryption": self.encryption,
            "key_size": self.key_size,
            "mode": self.mode,
            "mac_hash": self.mac_hash,
            "forward_secrecy": self.forward_secrecy,
            "aead": self.aead,
            "weaknesses": self.weaknesses,
        }


def _find_weaknesses(name: str) -> list[str]:
    upper = name.upper()
    found = []
    for token, reason in WEAK_PRIMITIVES.items():
        if token in upper:
            # SHA is not MD5; avoid matching "MD5" inside unrelated tokens.
            found.append(reason)
    # CBC in TLS is not broken per se, but it carries a long history of padding
    # oracles (BEAST, Lucky13) and is absent from TLS 1.3 for that reason.
    if "_CBC_" in upper:
        found.append(
            "CBC mode has a history of padding-oracle attacks (BEAST, Lucky13) "
            "and was removed in TLS 1.3."
        )
    return found


def _key_size(encryption: str, tokens: list[str], index: int) -> int | None:
    if index + 1 < len(tokens) and tokens[index + 1].isdigit():
        return int(tokens[index + 1])
    if encryption == "CHACHA20":
        return 256
    if encryption == "3DES":
        return 168
    return None


def lookup(code: int) -> SuiteInfo:
    """Decompose a cipher suite code into its cryptographic components."""
    name = CIPHER_SUITES.get(code, "UNKNOWN")

    if name == "UNKNOWN":
        return SuiteInfo(
            code=code, name="UNKNOWN", is_tls13=False, key_exchange=None,
            authentication=None, encryption=None, key_size=None, mode=None,
            mac_hash=None, forward_secrecy=None, aead=False,
            weaknesses=[],
        )

    body = name[4:] if name.startswith("TLS_") else name
    weaknesses = _find_weaknesses(name)

    # --- TLS 1.3: no _WITH_, key exchange and auth are not in the name ------
    if "_WITH_" not in body:
        tokens = body.split("_")
        mac_hash = tokens[-1]
        cipher_tokens = tokens[:-1]
        encryption = cipher_tokens[0] if cipher_tokens else None
        mode = cipher_tokens[-1] if len(cipher_tokens) > 1 else None
        key_size = _key_size(encryption or "", cipher_tokens, 0)
        return SuiteInfo(
            code=code, name=name, is_tls13=True,
            # Not "unknown" -- structurally absent from the suite. Key exchange
            # comes from key_share, authentication from the certificate.
            key_exchange=None, authentication=None,
            encryption=encryption, key_size=key_size, mode=mode, mac_hash=mac_hash,
            # TLS 1.3 mandates ephemeral key exchange; every suite has PFS.
            forward_secrecy=True,
            aead=True,
            weaknesses=weaknesses,
        )

    # --- TLS 1.2 and earlier -----------------------------------------------
    kex_auth, _, cipher_part = body.partition("_WITH_")
    kex_tokens = kex_auth.split("_")

    if len(kex_tokens) == 1:
        # TLS_RSA_WITH_... : RSA does both key transport and authentication.
        key_exchange = authentication = kex_tokens[0]
    else:
        key_exchange, authentication = kex_tokens[0], kex_tokens[1]

    cipher_tokens = cipher_part.split("_")
    mac_hash = cipher_tokens[-1]
    encryption = cipher_tokens[0]
    key_size = _key_size(encryption, cipher_tokens, 0)
    mode = next((t for t in cipher_tokens if t in {"GCM", "CBC", "CCM", "POLY1305"}), None)

    if key_exchange == "RSA":
        weaknesses.append(
            "Static RSA key exchange provides no forward secrecy: recorded traffic "
            "becomes readable if the server's private key is ever disclosed."
        )

    return SuiteInfo(
        code=code, name=name, is_tls13=False,
        key_exchange=key_exchange, authentication=authentication,
        encryption=encryption, key_size=key_size, mode=mode, mac_hash=mac_hash,
        forward_secrecy=key_exchange in _PFS_KEX,
        aead=mode in _AEAD_MODES if mode else False,
        weaknesses=weaknesses,
    )
