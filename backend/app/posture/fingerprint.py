"""Per-server cryptographic behaviour fingerprints and deviation detection.

The premise: a server's cryptographic behaviour is consistent. It has a TLS
configuration, so across many sessions it negotiates the same versions, the same
handful of cipher suites, the same groups, and presents the same JA4S. That
consistency *is* the baseline -- we do not need a training corpus, because the
capture contains the server's own normal behaviour.

A session that deviates from its own server's established profile is therefore
interesting in a way that "TLS 1.2 detected" never is. It says: this connection
was handled differently from the other N connections to the same server.

Deviation detection here is deterministic and per-dimension, so every deviation
names the exact attribute that differed and what was expected. The ML layer in
`app.ml.anomaly` sits on top of this and adds multivariate context; it does not
replace it.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from app.models.session import EmailSession

# A profile needs enough sessions to mean anything. Below this we record the
# profile for display but refuse to call anything a deviation from it -- two
# sessions do not establish a norm.
MIN_SESSIONS_FOR_BASELINE = 4

# Share of sessions an attribute value must reach to count as "this server's
# normal". Below it the server genuinely varies and deviation is meaningless.
DOMINANCE_THRESHOLD = 0.7


@dataclass
class Dimension:
    """One observable attribute of a server's crypto behaviour."""

    name: str
    distribution: Counter = field(default_factory=Counter)

    @property
    def total(self) -> int:
        return sum(self.distribution.values())

    @property
    def dominant(self) -> tuple[str, float] | None:
        if not self.total:
            return None
        value, count = self.distribution.most_common(1)[0]
        return value, count / self.total

    def serialise(self) -> dict:
        total = self.total or 1
        return {
            "name": self.name,
            "values": [
                {"value": v, "count": c, "share": round(c / total, 3)}
                for v, c in self.distribution.most_common()
            ],
        }


@dataclass
class ServerFingerprint:
    server: str
    host: str
    port: int
    sessions: int = 0
    protocols: Counter = field(default_factory=Counter)
    dimensions: dict[str, Dimension] = field(default_factory=dict)
    handshake_times: list[float] = field(default_factory=list)
    banner: str | None = None

    @property
    def has_baseline(self) -> bool:
        return self.sessions >= MIN_SESSIONS_FOR_BASELINE

    @property
    def median_handshake_ms(self) -> float | None:
        if not self.handshake_times:
            return None
        ordered = sorted(self.handshake_times)
        mid = len(ordered) // 2
        if len(ordered) % 2:
            return round(ordered[mid], 2)
        return round((ordered[mid - 1] + ordered[mid]) / 2, 2)

    def expected(self, dimension: str) -> tuple[str, float] | None:
        """The server's normal value for a dimension, if it has one."""
        dim = self.dimensions.get(dimension)
        if dim is None:
            return None
        dominant = dim.dominant
        if dominant is None or dominant[1] < DOMINANCE_THRESHOLD:
            return None
        return dominant

    def serialise(self) -> dict:
        return {
            "server": self.server,
            "host": self.host,
            "port": self.port,
            "sessions": self.sessions,
            "protocols": dict(self.protocols),
            "banner": self.banner,
            "has_baseline": self.has_baseline,
            "median_handshake_ms": self.median_handshake_ms,
            "dimensions": {k: v.serialise() for k, v in self.dimensions.items()},
        }


# The attributes that make up a fingerprint. Kept as data so adding a dimension
# is a one-line change here rather than edits scattered through the module.
_DIMENSIONS: dict[str, str] = {
    "tls_version": "TLS version",
    "tls_cipher_suite": "Cipher suite",
    "tls_selected_group": "Key exchange group",
    "tls_ja4s": "Server fingerprint (JA4S)",
    "encryption_state": "Encryption outcome",
}


def build_fingerprints(sessions: list[EmailSession]) -> dict[str, ServerFingerprint]:
    profiles: dict[str, ServerFingerprint] = {}

    for session in sessions:
        if session.protocol is None or session.is_indeterminate:
            continue

        key = f"{session.server_ip}:{session.server_port}"
        profile = profiles.get(key)
        if profile is None:
            profile = ServerFingerprint(
                server=key, host=session.server_ip, port=session.server_port
            )
            profiles[key] = profile

        profile.sessions += 1
        profile.protocols[session.protocol] += 1
        if session.server_banner and not profile.banner:
            profile.banner = session.server_banner
        if session.tls_handshake_ms is not None:
            profile.handshake_times.append(session.tls_handshake_ms)

        for attr in _DIMENSIONS:
            value = getattr(session, attr, None)
            if value is None:
                continue
            dim = profile.dimensions.setdefault(attr, Dimension(name=_DIMENSIONS[attr]))
            dim.distribution[str(value)] += 1

    return profiles


@dataclass
class Deviation:
    dimension: str
    label: str
    expected: str
    expected_share: float
    observed: str

    def serialise(self) -> dict:
        return {
            "dimension": self.dimension,
            "label": self.label,
            "expected": self.expected,
            "expected_share": round(self.expected_share, 3),
            "observed": self.observed,
        }


def deviations_for(
    session: EmailSession, profile: ServerFingerprint
) -> list[Deviation]:
    """Attributes where this session differs from its server's established norm.

    Returns nothing when the profile lacks a baseline. Reporting a deviation
    from a norm built on two sessions would manufacture findings out of small
    samples, which is the classic way anomaly detection becomes noise.
    """
    if not profile.has_baseline:
        return []

    found: list[Deviation] = []
    for attr, label in _DIMENSIONS.items():
        observed = getattr(session, attr, None)
        if observed is None:
            continue
        expectation = profile.expected(attr)
        if expectation is None:
            continue  # server genuinely varies here; nothing to deviate from
        expected_value, share = expectation
        if str(observed) != expected_value:
            found.append(
                Deviation(
                    dimension=attr,
                    label=label,
                    expected=expected_value,
                    expected_share=share,
                    observed=str(observed),
                )
            )
    return found


def deviation_score(deviations: list[Deviation]) -> float:
    """0.0 (matches the baseline) to 1.0 (differs on every dimension).

    Weighted by how dominant the expected value was: differing from something
    the server does 100% of the time is a stronger signal than differing from
    something it does 75% of the time.
    """
    if not deviations:
        return 0.0
    total = sum(d.expected_share for d in deviations)
    return round(min(total / len(_DIMENSIONS), 1.0), 3)
