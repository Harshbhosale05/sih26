"""Deterministic detection engine.

Everything here is computed, never inferred by a model. Certificate expiry is
arithmetic; a mangled capability line is a string comparison; a cleartext
credential is an observed fact. Using ML for any of it would be a bug.

ML enters later and only to add *context* -- anomaly scores and prioritisation
on top of findings that were already established deterministically.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from app.models.finding import SEVERITY_ORDER
from app.models.session import EmailSession
from app.protocols import EncryptionState

POLICY_PATH = Path(__file__).parent / "policy.json"

VERDICT_FAIL = "FAIL"
VERDICT_PASS = "PASS"
VERDICT_UNKNOWN = "UNKNOWN"


@lru_cache(maxsize=1)
def load_policy() -> dict:
    return json.loads(POLICY_PATH.read_text())


@dataclass
class DraftFinding:
    """A finding before it is persisted and assigned a ref."""

    category: str
    session_ref: str | None
    session_id: str | None
    description: str
    rationale: str
    evidence: dict = field(default_factory=dict)
    evidence_frames: list[int] = field(default_factory=list)
    wireshark_filter: str | None = None
    affected_sessions: int = 1
    verdict: str = VERDICT_FAIL
    detection_method: str = "deterministic"
    severity_override: str | None = None
    confidence_override: float | None = None

    def resolve(self) -> dict:
        rule = load_policy()["rules"].get(self.category, {})
        severity = self.severity_override or rule.get("severity", "INFO")
        confidence = (
            self.confidence_override
            if self.confidence_override is not None
            else rule.get("confidence", 0.5)
        )
        return {
            "category": self.category,
            "severity": severity,
            "severity_rank": SEVERITY_ORDER.get(severity, 9),
            "verdict": self.verdict,
            "confidence": confidence,
            "detection_method": self.detection_method,
            "title": rule.get("title", self.category.replace("_", " ").title()),
            "description": self.description,
            "rationale": self.rationale,
            "recommendation": rule.get("recommendation"),
            "standard_refs": rule.get("standards", []),
            "evidence": self.evidence,
            "evidence_frames": sorted(set(self.evidence_frames)),
            "wireshark_filter": self.wireshark_filter,
            "session_id": self.session_id,
            "session_ref": self.session_ref,
            "affected_sessions": self.affected_sessions,
            "first_frame": min(self.evidence_frames) if self.evidence_frames else None,
            "last_frame": max(self.evidence_frames) if self.evidence_frames else None,
        }


def _credential_events(session: EmailSession) -> list[dict]:
    return [e for e in (session.events or []) if e.get("kind") == "auth_credential"]


def _frames_for(session: EmailSession, kinds: set[str]) -> list[int]:
    return [e["frame"] for e in (session.events or []) if e.get("kind") in kinds]


def session_findings(session: EmailSession) -> list[DraftFinding]:
    """Rules that can be decided from a single session."""
    drafts: list[DraftFinding] = []
    state = session.encryption_state

    # --- Evidence quality gate -------------------------------------------
    # Comes first and short-circuits: a session we could not fully observe
    # must not generate confident FAIL findings about what it did.
    if session.is_indeterminate:
        reason = []
        if session.has_gaps:
            reason.append("missing bytes in the reassembled stream")
        if not session.session_complete:
            reason.append("no observed session termination")
        drafts.append(
            DraftFinding(
                category="incomplete_evidence",
                session_ref=session.ref,
                session_id=session.id,
                description=(
                    f"{session.ref} could not be fully observed in this capture, so its "
                    "transport security posture cannot be determined."
                ),
                rationale="; ".join(reason) or "session state indeterminate",
                verdict=VERDICT_UNKNOWN,
                evidence={
                    "encryption_state": state,
                    "has_gaps": session.has_gaps,
                    "session_complete": session.session_complete,
                },
                evidence_frames=[session.first_frame, session.last_frame],
                wireshark_filter=session.wireshark_filter,
            )
        )
        return drafts

    # --- Credential exposure ---------------------------------------------
    creds = _credential_events(session)
    if session.cleartext_auth_observed and creds:
        mechanisms = sorted({c["metadata"].get("mechanism", "?") for c in creds})
        accounts = sorted(
            {
                c["metadata"]["username_redacted"]
                for c in creds
                if c["metadata"].get("username_redacted")
            }
        )
        drafts.append(
            DraftFinding(
                category="cleartext_credential_exposure",
                session_ref=session.ref,
                session_id=session.id,
                description=(
                    f"{session.protocol} authentication completed on {session.server_ip}:"
                    f"{session.server_port} without TLS. Credentials for "
                    f"{len(accounts) or 1} account(s) are recoverable from this capture "
                    "by anyone holding it."
                ),
                rationale=(
                    f"{', '.join(mechanisms)} observed while the session was in state "
                    f"{state}. Base64 is an encoding, not encryption."
                ),
                evidence={
                    "mechanisms": mechanisms,
                    "accounts": accounts,
                    # Fingerprints only: never the credential itself.
                    "credentials": [c["metadata"] for c in creds],
                    "server": f"{session.server_ip}:{session.server_port}",
                },
                evidence_frames=[c["frame"] for c in creds],
                wireshark_filter=session.wireshark_filter,
            )
        )

    # --- Transport security ----------------------------------------------
    if state == EncryptionState.PLAINTEXT_AFTER_FAILURE.value:
        frames = _frames_for(session, {"upgrade_requested", "upgrade_rejected"})
        drafts.append(
            DraftFinding(
                category="starttls_downgrade_fallback",
                session_ref=session.ref,
                session_id=session.id,
                description=(
                    f"{session.ref} requested a TLS upgrade, the server refused, and the "
                    "client continued sending in cleartext."
                ),
                rationale=(
                    "The client demonstrably wanted encryption and transmitted anyway. "
                    "This is worse than never attempting an upgrade."
                ),
                evidence={"server": f"{session.server_ip}:{session.server_port}"},
                evidence_frames=frames or [session.first_frame],
                wireshark_filter=session.wireshark_filter,
            )
        )

    elif state == EncryptionState.STARTTLS_NOT_ADVERTISED.value:
        drafts.append(
            DraftFinding(
                category="starttls_not_advertised",
                session_ref=session.ref,
                session_id=session.id,
                description=(
                    f"{session.server_ip}:{session.server_port} did not offer a TLS "
                    f"upgrade to {session.ref}, and the session proceeded in cleartext."
                ),
                rationale=(
                    "No STARTTLS/STLS capability was received on a port where cleartext "
                    "is the default state."
                ),
                evidence={
                    "server": f"{session.server_ip}:{session.server_port}",
                    "capability_mangled": session.upgrade_advertised_mangled,
                },
                evidence_frames=_frames_for(
                    session, {"capability_response", "upgrade_advertised_mangled", "greeting"}
                ) or [session.first_frame],
                wireshark_filter=session.wireshark_filter,
            )
        )

    elif state == EncryptionState.STARTTLS_ADVERTISED_NOT_USED.value:
        drafts.append(
            DraftFinding(
                category="starttls_advertised_not_used",
                session_ref=session.ref,
                session_id=session.id,
                description=(
                    f"{session.server_ip}:{session.server_port} offered STARTTLS but "
                    f"{session.ref} never requested it."
                ),
                rationale=(
                    "Encryption was available and unused. The server permits cleartext "
                    "rather than requiring an upgrade."
                ),
                evidence={"server": f"{session.server_ip}:{session.server_port}"},
                evidence_frames=_frames_for(session, {"upgrade_advertised"})
                or [session.first_frame],
                wireshark_filter=session.wireshark_filter,
            )
        )

    # --- Content exposure -------------------------------------------------
    if session.cleartext_mail_observed and not session.tls_established:
        drafts.append(
            DraftFinding(
                category="cleartext_mail_transaction",
                session_ref=session.ref,
                session_id=session.id,
                description=(
                    f"{session.protocol} message or mailbox data was transferred without "
                    f"TLS on {session.server_ip}:{session.server_port}."
                ),
                rationale=f"Mail activity observed while session state was {state}.",
                evidence={"server": f"{session.server_ip}:{session.server_port}"},
                evidence_frames=_frames_for(session, {"mail_transaction", "mailbox_access"})
                or [session.first_frame],
                wireshark_filter=session.wireshark_filter,
            )
        )

    if session.detection_method in (
        "payload_signature_port_mismatch",
        "payload_signature_nonstandard_port",
    ):
        drafts.append(
            DraftFinding(
                category="protocol_port_mismatch",
                session_ref=session.ref,
                session_id=session.id,
                description=(
                    f"{session.protocol} observed on port {session.server_port}, which is "
                    "not the registered port for this service."
                ),
                rationale=(
                    "Protocol identified from the server greeting, not the port. Mail "
                    "services on unexpected ports commonly escape the TLS policy, "
                    "monitoring and firewall rules applied to the standard ports."
                ),
                evidence={"server": f"{session.server_ip}:{session.server_port}"},
                evidence_frames=[session.first_frame],
                wireshark_filter=session.wireshark_filter,
            )
        )

    return drafts
