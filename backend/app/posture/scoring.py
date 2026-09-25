"""The SecureMailScope Posture Score.

Six dimensions, each scored independently and each reported **with its own
evidence coverage**. This is the honesty mechanism that the rest of the product
is built around:

    Certificate Security   94/100   coverage 0%

A 94 computed from zero observations is worthless, and a tool that prints it
without the denominator is lying by omission. So a dimension with no coverage
is reported as NOT ASSESSED and is excluded from the overall score entirely --
never scored 0 (which would punish the operator for our blind spot) and never
scored 100 (which would invent a clean result).

The overall score is a coverage-weighted mean of the dimensions that could
actually be assessed, and it always ships with the list of which ones those
were. It is our methodology, anchored to published standards, stated openly --
not an industry-certified rating.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.detection.engine import load_policy
from app.models.session import EmailSession
from app.posture.fingerprint import build_fingerprints, deviations_for

# Penalty applied per session, by severity of what was observed. Scores start
# at 100 and lose ground for what the capture actually shows.
NOT_ASSESSED = "NOT_ASSESSED"


@dataclass
class DimensionScore:
    key: str
    label: str
    score: int | None
    assessed: int
    total: int
    weight: float
    standard: str
    detail: str
    contributors: list[str] = field(default_factory=list)

    @property
    def coverage_pct(self) -> float | None:
        if not self.total:
            return None
        return round(100 * self.assessed / self.total, 1)

    @property
    def is_assessed(self) -> bool:
        return self.score is not None and self.assessed > 0

    def serialise(self) -> dict:
        return {
            "key": self.key,
            "label": self.label,
            "score": self.score,
            "status": "assessed" if self.is_assessed else NOT_ASSESSED,
            "assessed": self.assessed,
            "total": self.total,
            "coverage_pct": self.coverage_pct,
            "weight": self.weight,
            "standard": self.standard,
            "detail": self.detail,
            "contributors": self.contributors,
        }


@dataclass
class PostureReport:
    overall: int | None
    dimensions: list[DimensionScore]
    assessed_weight: float
    note: str

    def calculation(self) -> dict:
        """The arithmetic behind the overall score, term by term.

        Published because a single opaque number invites exactly the wrong kind
        of scrutiny: a reader who cannot reproduce it either trusts it blindly
        or dismisses it. Both are worse than showing the sum.
        """
        terms = [
            {
                "dimension": d.label,
                "score": d.score,
                "weight": round(d.weight, 3),
                "product": round(d.score * d.weight, 2),
            }
            for d in self.dimensions
            if d.is_assessed
        ]
        numerator = round(sum(t["product"] for t in terms), 2)
        denominator = round(sum(t["weight"] for t in terms), 3)
        return {
            "formula": "sum(score x weight) / sum(weight), over assessed dimensions only",
            "terms": terms,
            "numerator": numerator,
            "denominator": denominator,
            "result": round(numerator / denominator, 2) if denominator else None,
            "rounded": self.overall,
            "excluded": [
                {"dimension": d.label, "reason": d.detail, "weight": round(d.weight, 3)}
                for d in self.dimensions
                if not d.is_assessed
            ],
            "coverage_meaning": (
                "Coverage is how much evidence existed for a dimension — the share of "
                "sessions carrying the data it needs. It is NOT the score. A dimension "
                "can have 100% coverage and a low score, or high coverage and a capped "
                "score."
            ),
        }

    def serialise(self) -> dict:
        return {
            "overall": self.overall,
            "dimensions": [d.serialise() for d in self.dimensions],
            "assessed_weight": round(self.assessed_weight, 3),
            "dimensions_assessed": sum(1 for d in self.dimensions if d.is_assessed),
            "dimensions_total": len(self.dimensions),
            "note": self.note,
            "calculation": self.calculation(),
        }


def _pct(good: int, total: int) -> int:
    return round(100 * good / total) if total else 0


def _transport_score(sessions: list[EmailSession]) -> DimensionScore:
    """Did traffic actually get encrypted?"""
    assessable = [s for s in sessions if not s.is_indeterminate]
    protected = [
        s for s in assessable
        if s.encryption_state in ("TLS_ESTABLISHED", "IMPLICIT_TLS")
    ]
    cleartext = len(assessable) - len(protected)

    score = _pct(len(protected), len(assessable)) if assessable else None
    contributors = []
    if cleartext:
        contributors.append(
            f"{cleartext} of {len(assessable)} observable session(s) did not establish TLS"
        )
    implicit = sum(1 for s in protected if s.encryption_state == "IMPLICIT_TLS")
    if implicit:
        contributors.append(f"{implicit} used implicit TLS (RFC 8314 preferred)")

    return DimensionScore(
        key="transport",
        label="Transport Security",
        score=score,
        assessed=len(assessable),
        total=len(sessions),
        weight=0.30,
        standard="RFC 3207, RFC 8314, RFC 8461",
        detail=(
            "Score = sessions reaching TLS_ESTABLISHED or IMPLICIT_TLS, over sessions "
            "whose outcome could be observed. Coverage = how many sessions were "
            "observable at all; indeterminate sessions are excluded from both."
        ),
        contributors=contributors,
    )


def _tls_version_score(sessions: list[EmailSession]) -> DimensionScore:
    tls = [s for s in sessions if s.tls_version]
    if not tls:
        return DimensionScore(
            key="tls_version", label="TLS Configuration", score=None, assessed=0,
            total=len(sessions), weight=0.20, standard="RFC 8996, NIST SP 800-52r2",
            detail="No TLS handshake was observed in this capture.",
        )

    weights = {"TLS 1.3": 100, "TLS 1.2": 80, "TLS 1.1": 20, "TLS 1.0": 10, "SSL 3.0": 0}
    total = sum(weights.get(s.tls_version, 50) for s in tls)
    deprecated = [s for s in tls if s.tls_version in ("TLS 1.0", "TLS 1.1", "SSL 3.0")]

    contributors = []
    if deprecated:
        contributors.append(
            f"{len(deprecated)} session(s) negotiated a version deprecated by RFC 8996"
        )
    modern = sum(1 for s in tls if s.tls_version == "TLS 1.3")
    contributors.append(f"{modern}/{len(tls)} negotiated TLS 1.3")

    return DimensionScore(
        key="tls_version", label="TLS Configuration", score=round(total / len(tls)),
        assessed=len(tls), total=len(sessions), weight=0.20,
        standard="RFC 8996, NIST SP 800-52r2 §3.1",
        detail="Weighted by negotiated protocol version across observed handshakes.",
        contributors=contributors,
    )


def _crypto_strength_score(sessions: list[EmailSession]) -> DimensionScore:
    tls = [s for s in sessions if s.tls_cipher_suite]
    if not tls:
        return DimensionScore(
            key="crypto", label="Cryptographic Strength", score=None, assessed=0,
            total=len(sessions), weight=0.20, standard="NIST SP 800-52r2 §3.3",
            detail="No cipher suite could be observed.",
        )

    total = 0
    weak = 0
    for s in tls:
        suite = (s.tls_detail or {}).get("cipher_suite") or {}
        if suite.get("weaknesses"):
            weak += 1
            total += 40
        elif s.tls_aead:
            total += 100
        else:
            total += 70

    contributors = []
    aead = sum(1 for s in tls if s.tls_aead)
    contributors.append(f"{aead}/{len(tls)} used an AEAD cipher")
    if weak:
        contributors.append(f"{weak} negotiated a suite with a known weakness")

    return DimensionScore(
        key="crypto", label="Cryptographic Strength", score=round(total / len(tls)),
        assessed=len(tls), total=len(sessions), weight=0.20,
        standard="NIST SP 800-52r2 §3.3, Mozilla Server Side TLS",
        detail="AEAD construction and absence of known-weak primitives.",
        contributors=contributors,
    )


def _forward_secrecy_score(sessions: list[EmailSession]) -> DimensionScore:
    tls = [s for s in sessions if s.tls_forward_secrecy is not None]
    if not tls:
        return DimensionScore(
            key="pfs", label="Forward Secrecy", score=None, assessed=0,
            total=len(sessions), weight=0.15, standard="NIST SP 800-52r2 §3.3.1",
            detail="No key exchange could be observed.",
        )

    with_pfs = [s for s in tls if s.tls_forward_secrecy]
    contributors = [f"{len(with_pfs)}/{len(tls)} sessions had an ephemeral key exchange"]
    if len(with_pfs) < len(tls):
        contributors.append(
            "Sessions without forward secrecy stay decryptable if the server key leaks"
        )

    return DimensionScore(
        key="pfs", label="Forward Secrecy", score=_pct(len(with_pfs), len(tls)),
        assessed=len(tls), total=len(sessions), weight=0.15,
        standard="NIST SP 800-52r2 §3.3.1, RFC 8446 §1.2",
        detail="Share of handshakes using an ephemeral (ECDHE/DHE) key exchange.",
        contributors=contributors,
    )


def _certificate_score(sessions: list[EmailSession]) -> DimensionScore:
    """Almost always NOT ASSESSED, and that is the correct answer.

    TLS 1.3 encrypts the Certificate message, so on modern infrastructure there
    is nothing to examine passively. Reporting a confident certificate score
    here would be the exact failure this product is built to avoid.
    """
    tls = [s for s in sessions if s.tls_version]
    observable = [s for s in tls if s.cert_observable]

    if not observable:
        reason = next(
            (s.cert_unobservable_reason for s in tls if s.cert_unobservable_reason),
            "No certificate was present in the captured bytes.",
        )
        return DimensionScore(
            key="certificate", label="Certificate Security", score=None, assessed=0,
            total=len(tls), weight=0.10, standard="CA/Browser Forum Baseline Requirements",
            detail=reason,
        )

    # Certificate parsing itself lands with the tier-2 testbed; until then an
    # observable certificate is recorded as observable and nothing more.
    return DimensionScore(
        key="certificate", label="Certificate Security", score=None,
        assessed=0, total=len(tls), weight=0.10,
        standard="CA/Browser Forum Baseline Requirements",
        detail=(
            f"{len(observable)} certificate(s) are present in the capture but X.509 "
            "analysis is not yet implemented (pending tier-2 testbed)."
        ),
    )


def _behavioural_score(sessions: list[EmailSession]) -> DimensionScore:
    """Consistency of each server against its own established behaviour."""
    profiles = build_fingerprints(sessions)
    with_baseline = {k: p for k, p in profiles.items() if p.has_baseline}

    assessable = [
        s for s in sessions
        if not s.is_indeterminate
        and f"{s.server_ip}:{s.server_port}" in with_baseline
    ]
    if not assessable:
        return DimensionScore(
            key="behaviour", label="Behavioural Consistency", score=None, assessed=0,
            total=len(sessions), weight=0.05,
            standard="SecureMailScope baseline model",
            detail=(
                "No server in this capture has enough sessions to establish a "
                "behavioural baseline."
            ),
        )

    deviating = 0
    for session in assessable:
        profile = with_baseline[f"{session.server_ip}:{session.server_port}"]
        if deviations_for(session, profile):
            deviating += 1

    contributors = [
        f"{len(with_baseline)} server(s) had a usable baseline",
        f"{deviating} session(s) deviated from their server's established profile",
    ]

    return DimensionScore(
        key="behaviour", label="Behavioural Consistency",
        score=_pct(len(assessable) - deviating, len(assessable)),
        assessed=len(assessable), total=len(sessions), weight=0.05,
        standard="SecureMailScope baseline model (not an external standard)",
        detail="Share of sessions matching their own server's established crypto profile.",
        contributors=contributors,
    )


# Which finding categories bear on which dimension. A severe finding caps its
# dimension: averaging over sessions otherwise lets 35 healthy sessions dilute
# one credential exposure into near-invisibility, which is exactly backwards.
# Posture is about worst observed state, not average state.
_DIMENSION_CATEGORIES = {
    "transport": {
        "cleartext_credential_exposure",
        "starttls_stripping",
        "starttls_downgrade_fallback",
        "starttls_not_advertised",
        "starttls_advertised_not_used",
        "cleartext_mail_transaction",
    },
    "tls_version": {"deprecated_tls_version"},
    "crypto": {"weak_cipher_suite"},
    "pfs": {"no_forward_secrecy"},
    "behaviour": {"starttls_stripping"},
}

# Ceiling imposed on a dimension by the worst finding affecting it.
_SEVERITY_CEILING = {"CRITICAL": 40, "HIGH": 60, "MEDIUM": 75, "LOW": 90}


def _apply_finding_ceilings(
    dimensions: list[DimensionScore], findings: list
) -> None:
    """Cap each dimension by the most severe finding that bears on it."""
    if not findings:
        return

    worst: dict[str, tuple[str, str]] = {}
    for finding in findings:
        severity = getattr(finding, "severity", None)
        category = getattr(finding, "category", None)
        if severity not in _SEVERITY_CEILING or not category:
            continue
        for key, categories in _DIMENSION_CATEGORIES.items():
            if category not in categories:
                continue
            current = worst.get(key)
            if current is None or _SEVERITY_CEILING[severity] < _SEVERITY_CEILING[current[0]]:
                worst[key] = (severity, category)

    for dim in dimensions:
        entry = worst.get(dim.key)
        if entry is None or dim.score is None:
            continue
        severity, category = entry
        ceiling = _SEVERITY_CEILING[severity]
        if dim.score > ceiling:
            dim.contributors.append(
                f"Capped at {ceiling} by a {severity} finding "
                f"({category.replace('_', ' ')}) — posture reflects the worst "
                f"observed state, not the average"
            )
            dim.score = ceiling


def compute(sessions: list[EmailSession], findings: list | None = None) -> PostureReport:
    weights = load_policy().get("posture_weights", {})

    dimensions = [
        _transport_score(sessions),
        _tls_version_score(sessions),
        _crypto_strength_score(sessions),
        _forward_secrecy_score(sessions),
        _certificate_score(sessions),
        _behavioural_score(sessions),
    ]

    # Policy file overrides the built-in weights, so the methodology is
    # editable without touching code.
    for dim in dimensions:
        if dim.key in weights:
            dim.weight = float(weights[dim.key])

    _apply_finding_ceilings(dimensions, findings or [])

    assessed = [d for d in dimensions if d.is_assessed]
    if not assessed:
        return PostureReport(
            overall=None, dimensions=dimensions, assessed_weight=0.0,
            note="No dimension could be assessed from this capture.",
        )

    total_weight = sum(d.weight for d in assessed)
    overall = round(sum(d.score * d.weight for d in assessed) / total_weight)

    skipped = [d.label for d in dimensions if not d.is_assessed]
    note = (
        f"Computed from {len(assessed)} of {len(dimensions)} dimensions "
        f"({round(100 * total_weight / sum(d.weight for d in dimensions))}% of total weight). "
    )
    if skipped:
        note += (
            f"Not assessed: {', '.join(skipped)} — excluded rather than assumed, "
            "because the capture does not contain the evidence."
        )

    return PostureReport(
        overall=overall, dimensions=dimensions, assessed_weight=total_weight, note=note
    )
