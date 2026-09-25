"""STARTTLS capability-stripping detector.

This is the detector a packet viewer structurally cannot replicate, because the
evidence does not exist inside any single session.

The attack: an on-path device rewrites the `250-STARTTLS` line in an EHLO
response so the client never learns the server supports encryption, and sends
mail in the clear. The rewrite preserves line length so TCP sequence numbers
stay valid and neither endpoint notices. It is the reason MTA-STS (RFC 8461)
exists, and it has been observed stripping a large share of mail in some
networks.

The detection: build a per-server capability profile across every session in
the capture. A server that advertises STARTTLS in most sessions and emits a
mangled token in a handful is not misconfigured -- misconfiguration is
consistent. Inconsistency against the *same server in the same capture* is the
signal.

Deliberately deterministic. No model is involved, and the finding states its
own baseline so an analyst can audit the reasoning.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from app.detection.engine import DraftFinding, load_policy
from app.models.session import EmailSession


@dataclass
class ServerCapabilityProfile:
    """How one server:port behaved across the whole capture."""

    server: str
    total_sessions: int = 0
    advertised: list[EmailSession] = field(default_factory=list)
    mangled: list[EmailSession] = field(default_factory=list)
    silent: list[EmailSession] = field(default_factory=list)

    @property
    def advertise_ratio(self) -> float:
        observable = len(self.advertised) + len(self.mangled) + len(self.silent)
        return len(self.advertised) / observable if observable else 0.0

    def serialise(self) -> dict:
        return {
            "server": self.server,
            "sessions_observed": self.total_sessions,
            "advertised_starttls": len(self.advertised),
            "mangled_capability": len(self.mangled),
            "no_capability": len(self.silent),
            "advertise_ratio": round(self.advertise_ratio, 3),
        }


def build_profiles(sessions: list[EmailSession]) -> dict[str, ServerCapabilityProfile]:
    """Group sessions by server:port and classify each one's capability outcome.

    Implicit-TLS sessions are excluded: there is no capability line to strip
    when there was never a plaintext phase, and counting them would dilute the
    baseline.
    """
    profiles: dict[str, ServerCapabilityProfile] = {}

    for session in sessions:
        if session.protocol is None or session.encryption_state == "IMPLICIT_TLS":
            continue
        # A session we could not observe says nothing about the server.
        if session.is_indeterminate:
            continue

        key = f"{session.server_ip}:{session.server_port}"
        profile = profiles.setdefault(key, ServerCapabilityProfile(server=key))
        profile.total_sessions += 1

        if session.upgrade_advertised_mangled:
            profile.mangled.append(session)
        elif session.upgrade_advertised:
            profile.advertised.append(session)
        else:
            profile.silent.append(session)

    return profiles


def build_host_profiles(
    profiles: dict[str, ServerCapabilityProfile]
) -> dict[str, dict]:
    """Roll per-port profiles up to the host.

    A host that advertises STARTTLS consistently on 587 tells us something
    about a mangled token seen on 25 -- weaker than same-port evidence, since
    the two ports legitimately carry different configurations, but far from
    nothing.
    """
    hosts: dict[str, dict] = defaultdict(
        lambda: {"advertised": 0, "mangled": 0, "silent": 0, "ports": []}
    )

    for key, profile in profiles.items():
        host = key.rsplit(":", 1)[0]
        port = key.rsplit(":", 1)[1]
        entry = hosts[host]
        entry["advertised"] += len(profile.advertised)
        entry["mangled"] += len(profile.mangled)
        entry["silent"] += len(profile.silent)
        if profile.advertised and port not in entry["ports"]:
            entry["ports"].append(port)

    for entry in hosts.values():
        observable = entry["advertised"] + entry["mangled"] + entry["silent"]
        entry["ratio"] = round(entry["advertised"] / observable, 3) if observable else 0.0
        entry["ports"].sort()

    return dict(hosts)


def detect(sessions: list[EmailSession]) -> list[DraftFinding]:
    rule = load_policy()["rules"]["starttls_stripping"]
    min_baseline = rule.get("min_sessions_for_baseline", 3)
    min_ratio = rule.get("min_advertise_ratio", 0.5)

    drafts: list[DraftFinding] = []

    profiles = build_profiles(sessions)
    host_profiles = build_host_profiles(profiles)

    for profile in profiles.values():
        if not profile.mangled:
            continue

        # Baseline strength is tiered, because the strength of the claim
        # genuinely differs:
        #   same server:port  -> the server's own normal behaviour (strongest)
        #   same host, other port -> the host advertises STARTTLS elsewhere;
        #       suggestive, but 25 and 587 legitimately carry different configs
        #   none -> suspicious shape, unprovable from this capture
        host = profile.server.rsplit(":", 1)[0]
        host_profile = host_profiles.get(host)

        if (
            len(profile.advertised) >= min_baseline
            and profile.advertise_ratio >= min_ratio
        ):
            baseline = "server_port"
            confidence = rule.get("confidence", 0.9)
        elif (
            host_profile
            and host_profile["advertised"] >= min_baseline
            and host_profile["ratio"] >= min_ratio
        ):
            baseline = "host"
            confidence = 0.7
        else:
            baseline = "none"
            confidence = 0.5

        has_baseline = baseline != "none"

        for session in profile.mangled:
            observed_token = _mangled_token(session)
            frames = [
                e["frame"]
                for e in (session.events or [])
                if e.get("kind") == "upgrade_advertised_mangled"
            ] or [session.first_frame]

            if baseline == "server_port":
                rationale = (
                    f"{profile.server} advertised STARTTLS normally in "
                    f"{len(profile.advertised)} of {profile.total_sessions} sessions in "
                    f"this capture. In {session.ref} the capability token arrived as "
                    f"'{observed_token}' — same length, not a valid ESMTP keyword. "
                    "Consistent with in-place rewriting by an on-path device; a "
                    "misconfigured server would behave identically in every session."
                )
            elif baseline == "host":
                ports = ", ".join(host_profile["ports"])
                rationale = (
                    f"The capability token in {session.ref} arrived as '{observed_token}', "
                    "which is not a valid ESMTP keyword. This capture contains no other "
                    f"session to {profile.server}, but host {host} advertised STARTTLS "
                    f"normally in {host_profile['advertised']} session(s) on port(s) "
                    f"{ports}. Suggestive of stripping rather than a server that lacks "
                    "TLS — though ports 25 and 587 can legitimately carry different "
                    "configurations, so same-port traffic is needed to confirm."
                )
            else:
                rationale = (
                    f"The capability token in {session.ref} arrived as '{observed_token}', "
                    "which is not a valid ESMTP keyword. This capture contains too few "
                    f"clean sessions against {profile.server} or host {host} to establish "
                    "normal behaviour — capture more traffic to confirm."
                )

            drafts.append(
                DraftFinding(
                    category="starttls_stripping",
                    session_ref=session.ref,
                    session_id=session.id,
                    description=(
                        f"The STARTTLS capability advertised by {profile.server} was "
                        f"altered in transit for {session.ref}, and the session then "
                        "proceeded without encryption."
                    ),
                    rationale=rationale,
                    confidence_override=confidence,
                    evidence={
                        "server_profile": profile.serialise(),
                        "host_profile": host_profile,
                        "observed_token": observed_token,
                        "expected_token": "STARTTLS",
                        "clean_sessions": [s.ref for s in profile.advertised[:10]],
                        "affected_session": session.ref,
                        "baseline_established": has_baseline,
                        "baseline_scope": baseline,
                    },
                    evidence_frames=frames,
                    wireshark_filter=session.wireshark_filter,
                    affected_sessions=len(profile.mangled),
                )
            )

    return drafts


def _mangled_token(session: EmailSession) -> str:
    for event in session.events or []:
        if event.get("kind") == "upgrade_advertised_mangled":
            return event.get("metadata", {}).get("observed_token") or event.get("detail", "")
    return ""


def server_profiles_payload(sessions: list[EmailSession]) -> list[dict]:
    """Per-server capability profiles for the dashboard's server view."""
    return [p.serialise() for p in build_profiles(sessions).values()]
