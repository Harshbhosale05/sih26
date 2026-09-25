"""Certificate findings.

Every check is arithmetic or a table lookup against the parsed X.509, evaluated
at the capture's own timestamp. Nothing here is a prediction.

Note what is deliberately absent: a "certificate untrusted" finding. Trust
cannot be established from a capture without the relying party's trust store,
so the chain trust result stays UNKNOWN rather than becoming a confident and
possibly wrong FAIL.
"""

from __future__ import annotations

from app.detection.engine import DraftFinding
from app.models.session import EmailSession


def _frames(session: EmailSession) -> list[int]:
    frames = [
        e["frame"]
        for e in (session.events or [])
        if e.get("kind") in {"tls_server_hello", "tls_certificate"}
    ]
    return frames or [session.first_frame]


def session_certificate_findings(session: EmailSession) -> list[DraftFinding]:
    detail = (session.tls_detail or {}).get("certificate") or {}
    if not detail.get("observed"):
        return []

    chain = detail.get("chain") or []
    leaf = chain[0] if chain else {}
    server = f"{session.server_ip}:{session.server_port}"
    frames = _frames(session)

    def draft(category: str, description: str, rationale: str, **extra) -> DraftFinding:
        return DraftFinding(
            category=category,
            session_ref=session.ref,
            session_id=session.id,
            description=description,
            rationale=rationale,
            evidence={
                "server": server,
                "subject": leaf.get("subject"),
                "issuer": leaf.get("issuer"),
                "serial": leaf.get("serial"),
                "not_before": leaf.get("not_before"),
                "not_after": leaf.get("not_after"),
                "public_key": f"{leaf.get('public_key_algorithm')} {leaf.get('public_key_bits')}",
                "signature_algorithm": leaf.get("signature_algorithm"),
                "san": leaf.get("san"),
                "fingerprint_sha256": leaf.get("fingerprint_sha256"),
                "evaluated_at_capture_time": detail.get("evaluated_at"),
                **extra,
            },
            evidence_frames=frames,
            wireshark_filter=session.wireshark_filter,
        )

    drafts: list[DraftFinding] = []
    reasons = detail.get("reasons") or []

    def reason_for(*tokens: str) -> str:
        for r in reasons:
            if any(t in r.lower() for t in tokens):
                return r
        return ""

    if detail.get("expired"):
        drafts.append(draft(
            "certificate_expired",
            f"{server} presented a certificate that had already expired when this "
            "traffic was captured.",
            reason_for("expired"),
        ))

    if detail.get("not_yet_valid"):
        drafts.append(draft(
            "certificate_not_yet_valid",
            f"{server} presented a certificate whose validity period had not begun at "
            "capture time.",
            reason_for("not valid until"),
        ))

    if detail.get("expiring_soon"):
        drafts.append(draft(
            "certificate_expiring_soon",
            f"{server} presented a certificate close to expiry "
            f"({detail.get('days_to_expiry')} days remaining at capture time).",
            reason_for("validity remaining"),
            days_to_expiry=detail.get("days_to_expiry"),
        ))

    if detail.get("hostname_match") is False:
        drafts.append(draft(
            "certificate_hostname_mismatch",
            f"The certificate presented by {server} does not cover the hostname the "
            "client requested.",
            reason_for("does not cover"),
            checked_hostname=detail.get("checked_hostname"),
        ))

    if detail.get("weak_key"):
        drafts.append(draft(
            "certificate_weak_key",
            f"{server} presented a certificate with a public key below current minimum "
            "strength.",
            reason_for("below the", "bits"),
        ))

    if detail.get("broken_signature"):
        drafts.append(draft(
            "certificate_weak_signature",
            f"{server} presented a certificate signed with a broken hash algorithm "
            f"({leaf.get('signature_algorithm')}).",
            reason_for("collision-broken", "obsolete"),
        ))

    if detail.get("self_signed"):
        drafts.append(draft(
            "certificate_self_signed",
            f"{server} presented a self-signed certificate.",
            reason_for("self-signed"),
        ))
    elif detail.get("chain_incomplete"):
        drafts.append(draft(
            "certificate_chain_incomplete",
            f"{server} presented only a leaf certificate with no issuer chain.",
            reason_for("issuer chain"),
        ))

    return drafts
