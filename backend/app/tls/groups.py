"""Named groups (key exchange) and post-quantum classification.

Hybrid post-quantum key exchange is deployed in production today and is visible
in cleartext in every ClientHello, so PQC readiness is a fact we can report
passively rather than a projection.

`X25519MLKEM768` (0x11EC) pairs X25519 with ML-KEM-768 (FIPS 203). The hybrid
construction means a break of either component alone is not sufficient, which
is why it is the migration path rather than pure ML-KEM.
"""

from __future__ import annotations

# Classical elliptic curve and finite-field groups.
GROUP_NAMES: dict[int, str] = {
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001D: "x25519",
    0x001E: "x448",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0102: "ffdhe4096",
    # Hybrid post-quantum
    0x11EC: "X25519MLKEM768",
    0x11EB: "SecP256r1MLKEM768",
    0x11ED: "SecP384r1MLKEM1024",
    0x6399: "X25519Kyber768Draft00",
    0x639A: "P256Kyber768Draft00",
}

# Groups that include a post-quantum KEM alongside a classical exchange.
PQC_HYBRID_GROUPS = {0x11EC, 0x11EB, 0x11ED, 0x6399, 0x639A}

# Groups below current guidance. secp256r1 is fine; these are not.
WEAK_GROUPS = {
    0x0016: "secp256k1 is not approved for TLS use",
    0x0100: "ffdhe2048 provides roughly 112-bit security, below the 128-bit floor",
}

# Classical asymmetric primitives whose security is broken by a CRQC. Used by
# the PQC readiness inventory -- an inventory of exposure, never a claim that
# an attack is occurring.
QUANTUM_VULNERABLE_KEX = {"ECDHE", "DHE", "RSA", "ECDH", "DH"}
QUANTUM_VULNERABLE_AUTH = {"RSA", "ECDSA", "DSS", "DSA"}


def is_grease(value: int) -> bool:
    """GREASE values (RFC 8701) are deliberate nonsense sent to keep the
    ecosystem tolerant of unknown values.

    They must be stripped before fingerprinting: clients randomise them per
    connection, so a JA3 computed with GREASE included changes every session
    and fingerprints nothing.

    All GREASE values have the form 0x?A?A where both bytes are identical.
    """
    return (value & 0x0F0F) == 0x0A0A and ((value >> 8) & 0xFF) == (value & 0xFF)


def is_pqc_hybrid(group: int) -> bool:
    return group in PQC_HYBRID_GROUPS


def name(group: int) -> str:
    return GROUP_NAMES.get(group, f"unknown (0x{group:04X})")
