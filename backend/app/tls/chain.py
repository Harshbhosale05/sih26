"""Certificate chain validation: link signatures and trust anchoring.

Two questions, answered separately because they fail for different reasons and
are fixed by different people:

1. **Does the presented chain hold together?** Each certificate must name the
   next one as its issuer, and its signature must verify under that issuer's
   public key. This needs nothing but the captured bytes, so it is always
   decidable -- a broken link is a hard fact, not an opinion.

2. **Does it end somewhere trusted?** That needs a trust store. We check the
   public Mozilla root programme (via certifi) and, when configured, the
   enterprise's own roots. A private CA that is simply not loaded is reported
   as UNTRUSTED_ANCHOR with the exact root to add -- not as a failure, because
   an internal mail relay signed by a corporate CA is normal.

Every link carries its own verdict so the UI can draw the chain and mark the
exact place it breaks.
"""

from __future__ import annotations

import logging
from datetime import datetime
from functools import lru_cache
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID

from app.config import get_settings

logger = logging.getLogger(__name__)

TRUSTED = "TRUSTED"
UNTRUSTED_ANCHOR = "UNTRUSTED_ANCHOR"
INVALID = "INVALID"
INCOMPLETE = "INCOMPLETE"
UNKNOWN = "UNKNOWN"


def _fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return bool(cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca)
    except x509.ExtensionNotFound:
        # v1 roots predate basicConstraints; tolerated only for self-issued roots.
        return cert.subject == cert.issuer


def _load_pem_bundle(path: Path) -> list[x509.Certificate]:
    try:
        return x509.load_pem_x509_certificates(path.read_bytes())
    except Exception as exc:  # noqa: BLE001 - a bad bundle must not break analysis
        logger.warning("could not load trust bundle %s: %s", path, exc)
        return []


@lru_cache(maxsize=1)
def trust_store() -> dict[str, list[tuple[x509.Certificate, str]]]:
    """Roots indexed by subject (RFC 4514), each tagged with its source."""
    store: dict[str, list[tuple[x509.Certificate, str]]] = {}

    def add(certs: list[x509.Certificate], source: str) -> None:
        for cert in certs:
            store.setdefault(cert.subject.rfc4514_string(), []).append((cert, source))

    try:
        import certifi

        add(_load_pem_bundle(Path(certifi.where())), "public")
    except ImportError:
        logger.info("certifi not installed; public trust store unavailable")

    enterprise_dir = get_settings().data_dir / "trust"
    if enterprise_dir.is_dir():
        for pem in sorted(enterprise_dir.glob("*.pem")) + sorted(enterprise_dir.glob("*.crt")):
            add(_load_pem_bundle(pem), "enterprise")
    return store


def trust_store_summary() -> dict:
    store = trust_store()
    sources: dict[str, int] = {}
    for entries in store.values():
        for _, source in entries:
            sources[source] = sources.get(source, 0) + 1
    return {
        "roots": sources,
        "enterprise_path": str(get_settings().data_dir / "trust"),
    }


def _verify_raw(child: x509.Certificate, issuer: x509.Certificate) -> None:
    """Verify the signature with the issuer key directly.

    Used for hashes the high-level API refuses (SHA-1). Whether SHA-1 is
    *acceptable* is a separate finding; whether the link holds is a fact.
    """
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    key = issuer.public_key()
    algorithm = child.signature_hash_algorithm
    if isinstance(key, rsa.RSAPublicKey):
        key.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), algorithm)
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(algorithm))
    else:
        raise TypeError(f"unsupported issuer key type {type(key).__name__}")


def _verify(child: x509.Certificate, issuer: x509.Certificate) -> tuple[bool, str | None]:
    if child.issuer != issuer.subject:
        return False, "issuer name does not match the next certificate's subject"
    try:
        child.verify_directly_issued_by(issuer)
        return True, None
    except InvalidSignature:
        return False, "signature does not verify under the issuer's public key"
    except (ValueError, TypeError):
        # e.g. "Unsupported signature algorithm" for SHA-1 — fall back to a raw check.
        try:
            _verify_raw(child, issuer)
            return True, None
        except InvalidSignature:
            return False, "signature does not verify under the issuer's public key"
        except Exception as exc:  # noqa: BLE001
            return False, f"signature could not be verified: {exc}"


def _anchor_for(cert: x509.Certificate) -> tuple[x509.Certificate, str] | None:
    """A trust-store root that issued `cert` (or is `cert`)."""
    fp = _fingerprint(cert)
    for candidate, source in trust_store().get(cert.issuer.rfc4514_string(), []):
        if _fingerprint(candidate) == fp:
            return candidate, source
        ok, _ = _verify(cert, candidate)
        if ok:
            return candidate, source
    return None


def validate(parsed: list[x509.Certificate], capture_time: datetime) -> dict:
    """Validate a presented chain. `parsed[0]` is the leaf."""
    if not parsed:
        return {"chain_trust": UNKNOWN, "chain_trust_reason": "No certificate presented.", "links": []}

    links: list[dict] = []
    broken: list[str] = []

    for i in range(len(parsed) - 1):
        child, issuer = parsed[i], parsed[i + 1]
        ok, why = _verify(child, issuer)
        problems = [] if ok else [why]
        if ok and not _is_ca(issuer):
            ok = False
            problems.append("issuer is not marked as a CA (basicConstraints)")
        if not issuer.not_valid_before_utc <= capture_time <= issuer.not_valid_after_utc:
            problems.append("issuer certificate was outside its validity period at capture time")
        links.append({
            "child": i,
            "issuer": i + 1,
            "status": "valid" if ok and not problems else ("invalid" if not ok else "warning"),
            "problems": [p for p in problems if p],
        })
        if not ok:
            broken.append(f"certificate {i} → {i + 1}: {'; '.join(p for p in problems if p)}")

    top = parsed[-1]
    top_self_issued = top.subject == top.issuer
    anchor = _anchor_for(top)
    anchor_info = None
    if anchor is not None:
        root, source = anchor
        anchor_info = {
            "subject": root.subject.rfc4514_string(),
            "source": source,
            "fingerprint_sha256": _fingerprint(root),
            "presented": _fingerprint(root) == _fingerprint(top),
        }
        if not anchor_info["presented"]:
            links.append({"child": len(parsed) - 1, "issuer": "trust_store", "status": "valid", "problems": []})
    elif top_self_issued:
        ok, why = _verify(top, top)
        links.append({
            "child": len(parsed) - 1, "issuer": len(parsed) - 1,
            "status": "valid" if ok else "invalid", "problems": [] if ok else [why],
        })
        if not ok:
            broken.append(f"self-signed root does not verify: {why}")

    top_name = top.issuer.rfc4514_string()
    if broken:
        trust, reason = INVALID, "Chain signature verification failed — " + " | ".join(broken)
    elif anchor_info:
        trust = TRUSTED
        reason = (
            f"Every link verifies and the chain anchors to "
            f"{'a public root (Mozilla programme)' if anchor_info['source'] == 'public' else 'a configured enterprise root'}: "
            f"{anchor_info['subject']}."
        )
    elif top_self_issued:
        trust = UNTRUSTED_ANCHOR
        reason = (
            f"Every link verifies, but the root '{top.subject.rfc4514_string()}' is not in the "
            "configured trust store. If this is your enterprise CA, add its PEM to the trust "
            "directory and re-run analysis."
        )
    else:
        trust = INCOMPLETE
        reason = (
            f"Links verify as far as they go, but the issuer '{top_name}' was neither presented "
            "nor found in the trust store, so the path to a root cannot be built."
        )

    return {
        "chain_trust": trust,
        "chain_trust_reason": reason,
        "links": links,
        "anchor": anchor_info,
    }


def der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)
