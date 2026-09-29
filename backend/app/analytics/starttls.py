"""STARTTLS failure-point and adoption analytics.

The encryption state machine says *whether* a session ended up encrypted. This
module says *where* it stopped. An opportunistic upgrade is a chain of five
steps, and each one can break for a different reason with a different owner:

    advertised -> requested -> accepted -> handshake -> established
    (server)      (client)     (server)    (both)        (both)

A server that never advertises is a configuration fix on the server. A client
that ignores the advertisement is a client policy fix. A handshake that starts
and dies is usually a version or cipher mismatch. Reporting all of these as
"cleartext" hides who has to act, so every session is classified by the first
step it failed, and the result is aggregated per server, per protocol and over
the capture's own timeline.

Implicit-TLS sessions never had an upgrade step. They are counted separately as
"bypassed" rather than folded into the funnel, where they would inflate the
success rate of a mechanism they did not use.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from app.models.session import EmailSession

# Ordered: a session's failure point is the first stage it did not reach.
STAGES = ["connected", "advertised", "requested", "accepted", "handshake", "established"]

STAGE_LABELS = {
    "connected": "Plaintext session opened",
    "advertised": "Server advertised STARTTLS",
    "requested": "Client requested upgrade",
    "accepted": "Server accepted upgrade",
    "handshake": "TLS handshake negotiated",
    "established": "Encrypted data flowing",
}

# Failure points, with who owns the fix. Order is presentation order.
FAILURE_POINTS: dict[str, dict] = {
    "success": {
        "label": "Upgraded successfully",
        "owner": None,
        "severity": "ok",
        "explanation": "The session completed the full STARTTLS upgrade.",
    },
    "capability_stripped": {
        "label": "Capability stripped in transit",
        "owner": "network",
        "severity": "critical",
        "explanation": (
            "The STARTTLS capability line arrived mangled, so the client never saw a "
            "usable offer. Consistent with an on-path device rewriting the response."
        ),
    },
    "not_advertised": {
        "label": "Server did not advertise",
        "owner": "server",
        "severity": "high",
        "explanation": "The server never offered STARTTLS, so an upgrade was impossible.",
    },
    "client_skipped": {
        "label": "Client ignored the offer",
        "owner": "client",
        "severity": "high",
        "explanation": (
            "The server offered STARTTLS and the client carried on in plaintext. "
            "Opportunistic TLS without enforcement (no MTA-STS / DANE / client policy)."
        ),
    },
    "server_rejected": {
        "label": "Server rejected the upgrade",
        "owner": "server",
        "severity": "high",
        "explanation": "The client asked to upgrade and the server refused.",
    },
    "handshake_not_started": {
        "label": "Accepted, handshake never started",
        "owner": "client",
        "severity": "medium",
        "explanation": (
            "The server agreed to upgrade but no ClientHello followed. Often a client "
            "TLS library failure or a middlebox dropping the handshake."
        ),
    },
    "handshake_failed": {
        "label": "Handshake failed",
        "owner": "both",
        "severity": "medium",
        "explanation": (
            "A ClientHello was sent but no usable handshake completed — typically a "
            "version or cipher-suite mismatch, or a certificate the client rejected."
        ),
    },
    "no_application_data": {
        "label": "Handshake done, no encrypted data",
        "owner": "both",
        "severity": "low",
        "explanation": (
            "ServerHello was observed but no application data followed, so the "
            "session cannot be shown to have used the encrypted channel."
        ),
    },
    "unobservable": {
        "label": "Not observable in capture",
        "owner": None,
        "severity": "unknown",
        "explanation": (
            "The capture does not contain enough of this session to say where it "
            "stopped. Reported as unknown, never as success or failure."
        ),
    },
}

_REJECTED_STATES = {"STARTTLS_REJECTED", "PLAINTEXT_AFTER_FAILURE"}
_MAX_BUCKETS = 12
_EXAMPLE_LIMIT = 8


def _event_kinds(session: EmailSession) -> set[str]:
    return {e.get("kind") for e in (session.events or [])}


def _first_frame(session: EmailSession, kinds: set[str]) -> int | None:
    for event in session.events or []:
        if event.get("kind") in kinds:
            return event.get("frame")
    return None


@dataclass
class SessionOutcome:
    ref: str
    server: str
    protocol: str | None
    failure_point: str
    reached: list[str]
    fell_back_to_cleartext: bool
    evidence_frame: int | None
    start_time: float

    def serialise(self) -> dict:
        return {
            "session_ref": self.ref,
            "server": self.server,
            "protocol": self.protocol,
            "failure_point": self.failure_point,
            "reached": self.reached,
            "fell_back_to_cleartext": self.fell_back_to_cleartext,
            "evidence_frame": self.evidence_frame,
        }


def classify(session: EmailSession) -> SessionOutcome:
    """Place one plaintext-start session on the funnel."""
    kinds = _event_kinds(session)
    server = f"{session.server_ip}:{session.server_port}"
    reached = ["connected"]

    def outcome(point: str, frame: int | None) -> SessionOutcome:
        return SessionOutcome(
            ref=session.ref,
            server=server,
            protocol=session.protocol,
            failure_point=point,
            reached=reached,
            fell_back_to_cleartext=bool(
                session.cleartext_auth_observed or session.cleartext_mail_observed
            )
            and not session.tls_established,
            evidence_frame=frame,
            start_time=session.start_time,
        )

    if session.is_indeterminate:
        return outcome("unobservable", session.first_frame)

    if session.upgrade_advertised_mangled and not session.upgrade_advertised:
        return outcome(
            "capability_stripped", _first_frame(session, {"upgrade_advertised_mangled"})
        )

    if session.upgrade_advertised:
        reached.append("advertised")
    elif not session.upgrade_requested:
        # A client may request without an advertisement (e.g. a policy-driven
        # MTA). Only an unrequested, unadvertised session failed here.
        return outcome("not_advertised", _first_frame(session, {"capability_response"})
                       or session.first_frame)

    if not session.upgrade_requested:
        return outcome("client_skipped", _first_frame(session, {"upgrade_advertised"}))
    reached.append("requested")

    accepted = "upgrade_accepted" in kinds or "tls_client_hello" in kinds
    if session.encryption_state in _REJECTED_STATES or "upgrade_rejected" in kinds:
        return outcome("server_rejected", _first_frame(session, {"upgrade_rejected"}))
    if not accepted:
        return outcome("server_rejected", _first_frame(session, {"upgrade_requested"}))
    reached.append("accepted")

    if "tls_client_hello" not in kinds:
        return outcome("handshake_not_started", _first_frame(session, {"upgrade_accepted"}))

    if session.tls_version is None and "tls_server_hello" not in kinds:
        return outcome(
            "handshake_failed",
            _first_frame(session, {"tls_alert", "tls_client_hello"}),
        )
    reached.append("handshake")

    if not session.tls_established:
        return outcome(
            "no_application_data", _first_frame(session, {"tls_server_hello"})
        )
    reached.append("established")
    return outcome("success", _first_frame(session, {"tls_application_data"}))


@dataclass
class _Group:
    key: str
    outcomes: list[SessionOutcome] = field(default_factory=list)

    def serialise(self) -> dict:
        observable = [o for o in self.outcomes if o.failure_point != "unobservable"]
        points = Counter(o.failure_point for o in self.outcomes)
        stage_counts = {
            stage: sum(1 for o in observable if stage in o.reached) for stage in STAGES
        }
        success = points.get("success", 0)
        worst = next(
            (
                p for p in FAILURE_POINTS
                if p not in ("success", "unobservable") and points.get(p)
            ),
            None,
        )
        return {
            "key": self.key,
            "sessions": len(self.outcomes),
            "observable": len(observable),
            "adoption_pct": round(100 * success / len(observable), 1) if observable else None,
            "advertise_pct": (
                round(100 * stage_counts["advertised"] / len(observable), 1)
                if observable else None
            ),
            "stage_counts": stage_counts,
            "failure_points": dict(points),
            "dominant_failure": worst,
            "cleartext_fallbacks": sum(1 for o in self.outcomes if o.fell_back_to_cleartext),
        }


def analyse(sessions: list[EmailSession]) -> dict:
    email = [s for s in sessions if s.protocol]
    implicit = [s for s in email if s.encryption_state == "IMPLICIT_TLS"]
    outcomes = [classify(s) for s in email if s.encryption_state != "IMPLICIT_TLS"]
    observable = [o for o in outcomes if o.failure_point != "unobservable"]

    # --- Funnel ------------------------------------------------------------
    funnel = []
    previous = None
    for stage in STAGES:
        count = sum(1 for o in observable if stage in o.reached)
        funnel.append(
            {
                "stage": stage,
                "label": STAGE_LABELS[stage],
                "count": count,
                "pct_of_start": round(100 * count / len(observable), 1) if observable else None,
                # A client may request without an advertisement, so a later
                # stage can exceed an earlier one; that is not a "drop".
                "drop_from_previous": max(0, previous - count) if previous is not None else 0,
            }
        )
        previous = count

    # --- Failure points ------------------------------------------------------
    by_point: dict[str, list[SessionOutcome]] = defaultdict(list)
    for o in outcomes:
        by_point[o.failure_point].append(o)

    failure_points = []
    for key, meta in FAILURE_POINTS.items():
        items = by_point.get(key, [])
        if not items:
            continue
        failure_points.append(
            {
                "key": key,
                **meta,
                "count": len(items),
                "pct": round(100 * len(items) / len(outcomes), 1) if outcomes else 0.0,
                "servers": sorted({o.server for o in items}),
                "cleartext_fallbacks": sum(1 for o in items if o.fell_back_to_cleartext),
                "examples": [o.serialise() for o in items[:_EXAMPLE_LIMIT]],
            }
        )

    # --- Per server / per protocol ------------------------------------------
    servers: dict[str, _Group] = {}
    protocols: dict[str, _Group] = {}
    for o in outcomes:
        servers.setdefault(o.server, _Group(o.server)).outcomes.append(o)
        protocols.setdefault(o.protocol or "UNKNOWN", _Group(o.protocol or "UNKNOWN")).outcomes.append(o)

    implicit_by_server = Counter(f"{s.server_ip}:{s.server_port}" for s in implicit)
    server_rows = []
    for key, group in servers.items():
        row = group.serialise()
        row["implicit_tls_sessions"] = implicit_by_server.pop(key, 0)
        server_rows.append(row)
    for key, count in implicit_by_server.items():
        server_rows.append(
            {
                "key": key, "sessions": 0, "observable": 0, "adoption_pct": None,
                "advertise_pct": None, "stage_counts": {s: 0 for s in STAGES},
                "failure_points": {}, "dominant_failure": None,
                "cleartext_fallbacks": 0, "implicit_tls_sessions": count,
            }
        )
    server_rows.sort(
        key=lambda r: (r["adoption_pct"] if r["adoption_pct"] is not None else 101, -r["sessions"])
    )

    # --- Timeline -------------------------------------------------------------
    timeline = _timeline(outcomes)

    success = sum(1 for o in observable if o.failure_point == "success")
    return {
        "summary": {
            "email_sessions": len(email),
            "starttls_eligible": len(outcomes),
            "observable": len(observable),
            "unobservable": len(outcomes) - len(observable),
            "implicit_tls": len(implicit),
            "upgraded": success,
            "adoption_pct": round(100 * success / len(observable), 1) if observable else None,
            "cleartext_fallbacks": sum(1 for o in outcomes if o.fell_back_to_cleartext),
            "stripped": len(by_point.get("capability_stripped", [])),
        },
        "funnel": funnel,
        "failure_points": failure_points,
        "servers": server_rows,
        "protocols": [g.serialise() for g in protocols.values()],
        "timeline": timeline,
        "sessions": [o.serialise() for o in outcomes],
        "method": (
            "Each plaintext-start session is placed at the first STARTTLS stage it "
            "failed to reach, using the parsed protocol events and TLS records. "
            "Implicit-TLS sessions are counted separately; sessions the capture does "
            "not fully show are reported as unobservable, never as success or failure."
        ),
    }


def _timeline(outcomes: list[SessionOutcome]) -> list[dict]:
    """Bucket the capture's own time range so behaviour changes are visible."""
    if not outcomes:
        return []
    start = min(o.start_time for o in outcomes)
    end = max(o.start_time for o in outcomes)
    span = end - start
    buckets = min(_MAX_BUCKETS, max(1, len(outcomes) // 2)) if span > 0 else 1
    width = span / buckets if span > 0 else 1.0

    rows = [
        {"bucket": i, "start": start + i * width, "end": start + (i + 1) * width,
         "attempts": 0, "upgraded": 0, "failed": 0, "unobservable": 0}
        for i in range(buckets)
    ]
    for o in outcomes:
        index = min(int((o.start_time - start) / width), buckets - 1) if span > 0 else 0
        row = rows[index]
        row["attempts"] += 1
        if o.failure_point == "success":
            row["upgraded"] += 1
        elif o.failure_point == "unobservable":
            row["unobservable"] += 1
        else:
            row["failed"] += 1

    for row in rows:
        seen = row["upgraded"] + row["failed"]
        row["adoption_pct"] = round(100 * row["upgraded"] / seen, 1) if seen else None
        row["offset_seconds"] = round(row["start"] - start, 3)
    return rows


def adoption_rate(sessions: list[EmailSession]) -> float | None:
    """Single number used by drift snapshots."""
    return analyse(sessions)["summary"]["adoption_pct"]
