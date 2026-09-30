"""Remediation simulator: what would this capture look like after the fix?

The simulator is a digital twin of the observed sessions. It copies them,
applies the concrete, protocol-level effect of each fix -- "this session would
have upgraded with STARTTLS and negotiated the server's best observed TLS
profile", "this TLS 1.0 handshake would have been TLS 1.2" -- and then re-runs
the *same* deterministic rules, posture scoring, risk model and dependency
graph used on real evidence.

Nothing is hand-waved into the result. A fix only changes the sessions it can
physically change: enabling hybrid PQC does nothing for a client that never
offered it; renewing a certificate does nothing for a TLS 1.3 session whose
certificate we could not see. Findings that remain after a fix remain in the
projection, which is the honest answer to "is that enough?".

Projections are clearly labelled as such everywhere they appear. They answer
"what would a re-capture show if the change works as specified", and the
verification commands in each playbook are how the administrator checks it did.
"""

from __future__ import annotations

import copy
from collections import Counter
from datetime import datetime, timedelta
from types import SimpleNamespace

from sqlalchemy import inspect as sa_inspect

from app.analytics import graph as dep_graph
from app.detection import session_findings, starttls_stripping
from app.detection.cert_rules import session_certificate_findings
from app.detection.tls_rules import session_tls_findings
from app.ml import risk as ml_risk
from app.models.capture import Capture
from app.models.finding import Finding
from app.models.session import EmailSession
from app.posture import compute
from app.pqc import readiness_finding
from app.pqc.readiness import assess as assess_pqc
from app.protocols import CLEARTEXT_STATES
from app.remediation.playbooks import FIXES
from app.tls.suites import lookup as suite_lookup

_CLEARTEXT = {s.value for s in CLEARTEXT_STATES} | {"STARTTLS_NEGOTIATION_FAILED"}
_DEPRECATED = {"SSL 3.0", "TLS 1.0", "TLS 1.1"}
_VERSION_RANK = {"SSL 3.0": 1, "TLS 1.0": 2, "TLS 1.1": 3, "TLS 1.2": 4, "TLS 1.3": 5}
_IMPLICIT_PORTS = {465, 993, 995}

# Findings that come from DNS in the capture and cannot be re-derived from the
# sessions alone; they carry over unless a fix resolves them.
_DNS_CATEGORIES = {
    "mta_sts_policy_violation", "mta_sts_not_published", "dane_not_deployed",
    "tlsrpt_not_configured", "dmarc_not_published", "dmarc_policy_none",
    "dns_correlation_incomplete",
}

# Policy target when a server has no healthy TLS session to copy from.
_TARGET_TLS13 = 0x1302         # TLS_AES_256_GCM_SHA384
_TARGET_TLS12 = 0xC030         # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
_TARGET_TLS12_EC = 0xC02C      # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384

# Apply order: transport first (so newly encrypted sessions inherit a profile),
# then protocol, cipher, certificate, PQC.
_ORDER = ["enforce_tls", "deploy_mta_sts_dane", "disable_legacy_tls", "modern_ciphers",
          "renew_certificate", "fix_certificate_chain", "enable_hybrid_pqc",
          "publish_dmarc", "standard_ports"]


def _server(s: EmailSession) -> str:
    return f"{s.server_ip}:{s.server_port}"


def clone(sessions: list[EmailSession]) -> list[EmailSession]:
    columns = [c.key for c in sa_inspect(EmailSession).mapper.column_attrs]
    return [EmailSession(**copy.deepcopy({k: getattr(s, k) for k in columns})) for s in sessions]


# --------------------------------------------------------------------------- #
# Session transformations
# --------------------------------------------------------------------------- #

def _suite_detail(code: int) -> dict:
    return suite_lookup(code).serialise()


def _set_suite(s: EmailSession, code: int) -> None:
    info = suite_lookup(code)
    s.tls_cipher_suite = info.name
    s.tls_cipher_code = f"0x{code:04X}"
    s.tls_key_exchange = info.key_exchange
    s.tls_authentication = info.authentication
    s.tls_forward_secrecy = info.forward_secrecy
    s.tls_aead = info.aead
    detail = dict(s.tls_detail or {})
    detail["cipher_suite"] = _suite_detail(code)
    s.tls_detail = detail


def _healthiness(s: EmailSession) -> tuple:
    suite = (s.tls_detail or {}).get("cipher_suite") or {}
    cert = (s.tls_detail or {}).get("certificate") or {}
    return (
        _VERSION_RANK.get(s.tls_version or "", 0),
        bool(s.tls_forward_secrecy), bool(s.tls_aead),
        -len(suite.get("weaknesses") or []),
        not any(cert.get(k) for k in ("expired", "weak_key", "broken_signature", "self_signed")),
    )


def _best_profiles(sessions: list[EmailSession]) -> dict[str, EmailSession]:
    best: dict[str, EmailSession] = {}
    for s in sessions:
        if not s.tls_established or not s.tls_version:
            continue
        key = _server(s)
        if key not in best or _healthiness(s) > _healthiness(best[key]):
            best[key] = s
    return best


def _encrypt(s: EmailSession, template: EmailSession | None) -> None:
    """Turn a cleartext session into the TLS session it would have been."""
    implicit = s.server_port in _IMPLICIT_PORTS
    s.encryption_state = "IMPLICIT_TLS" if implicit else "TLS_ESTABLISHED"
    s.upgrade_advertised = not implicit
    s.upgrade_advertised_mangled = False
    s.upgrade_requested = not implicit
    s.upgrade_succeeded = not implicit
    s.tls_established = True
    s.cleartext_auth_observed = False
    s.cleartext_mail_observed = False
    s.is_indeterminate = False

    if template is not None:
        for attr in ("tls_version", "tls_cipher_suite", "tls_cipher_code", "tls_key_exchange",
                     "tls_authentication", "tls_forward_secrecy", "tls_aead", "tls_selected_group",
                     "tls_ja4s", "cert_observable", "cert_unobservable_reason"):
            setattr(s, attr, getattr(template, attr))
        s.tls_pqc_selected = bool(template.tls_pqc_selected and s.tls_pqc_offered)
        s.tls_detail = copy.deepcopy(template.tls_detail)
    else:
        s.tls_version = "TLS 1.3"
        _set_suite(s, _TARGET_TLS13)
        s.tls_selected_group = "x25519"
        s.cert_observable = False
        s.cert_unobservable_reason = (
            "TLS 1.3 encrypts the Certificate message; projected session inherits no "
            "observable certificate."
        )
        detail = dict(s.tls_detail or {})
        detail.update({"negotiated_version": "TLS 1.3", "selected_group": "x25519", "observed": True})
        s.tls_detail = detail
    s.tls_handshake_ms = s.tls_handshake_ms or (template.tls_handshake_ms if template else None)


def _encrypt_from_profile(s, profiles, ctx) -> None:
    template = profiles.get(_server(s))
    ctx["profile_source"][s.ref] = (
        f"server's best observed session ({template.ref})" if template is not None
        else "policy target (TLS 1.3, AES-256-GCM, X25519) — no TLS session to this server was observed"
    )
    _encrypt(s, template)


def _t_enforce_tls(s, profiles, ctx):
    if s.is_indeterminate or s.upgrade_advertised_mangled or s.encryption_state not in _CLEARTEXT:
        return False
    _encrypt_from_profile(s, profiles, ctx)
    return True


def _t_mta_sts(s, profiles, ctx):
    if s.is_indeterminate or not s.upgrade_advertised_mangled:
        return False
    _encrypt_from_profile(s, profiles, ctx)
    return True


def _t_legacy(s, _profiles, _ctx):
    if s.tls_version not in _DEPRECATED:
        return False
    s.tls_version = "TLS 1.2"
    detail = dict(s.tls_detail or {})
    detail["negotiated_version"] = "TLS 1.2"
    s.tls_detail = detail
    return True


def _t_ciphers(s, _profiles, _ctx):
    if not s.tls_version or s.tls_version == "TLS 1.3":
        return False
    suite = (s.tls_detail or {}).get("cipher_suite") or {}
    if not (suite.get("weaknesses") or s.tls_forward_secrecy is False or s.tls_aead is False):
        return False
    cert = (s.tls_detail or {}).get("certificate") or {}
    leaf = (cert.get("chain") or [{}])[0]
    _set_suite(s, _TARGET_TLS12_EC if leaf.get("public_key_algorithm") == "EC" else _TARGET_TLS12)
    return True


def _t_renew(s, _profiles, ctx):
    detail = dict(s.tls_detail or {})
    cert = dict(detail.get("certificate") or {})
    if not cert.get("observed"):
        return False
    flags = ("expired", "not_yet_valid", "expiring_soon", "weak_key", "broken_signature",
             "self_signed", "chain_incomplete", "chain_invalid")
    if not any(cert.get(f) for f in flags) and cert.get("hostname_match") is not False:
        return False
    now: datetime = ctx["capture_time"]
    chain = copy.deepcopy(cert.get("chain") or [{}])
    leaf = chain[0]
    host = cert.get("checked_hostname") or leaf.get("subject_cn")
    leaf.update({
        "not_before": (now - timedelta(days=30)).isoformat(),
        "not_after": (now + timedelta(days=365)).isoformat(),
        "public_key_algorithm": "EC" if leaf.get("public_key_algorithm") == "EC" else "RSA",
        "public_key_bits": 256 if leaf.get("public_key_algorithm") == "EC" else 3072,
        "signature_algorithm": "sha256WithRSAEncryption",
        "san": sorted(set((leaf.get("san") or []) + ([host] if host else []))),
        "issuer": leaf.get("issuer") if not cert.get("self_signed") else "CN=Issuing CA (projected)",
    })
    if len(chain) < 2:
        chain.append({"index": 1, "subject": leaf["issuer"], "is_ca": True, "projected": True})
    cert.update({
        "chain": chain, "chain_length": len(chain),
        "expired": False, "not_yet_valid": False, "expiring_soon": False, "days_to_expiry": 365,
        "weak_key": False, "broken_signature": False, "self_signed": False,
        "chain_incomplete": False, "chain_invalid": False,
        "hostname_match": True if cert.get("checked_hostname") else cert.get("hostname_match"),
        "reasons": [], "projected": True,
    })
    detail["certificate"] = cert
    s.tls_detail = detail
    return True


def _t_chain(s, _profiles, _ctx):
    detail = dict(s.tls_detail or {})
    cert = dict(detail.get("certificate") or {})
    if not cert.get("observed") or not (cert.get("chain_incomplete") or cert.get("chain_invalid")):
        return False
    cert.update({"chain_incomplete": False, "chain_invalid": False, "projected": True})
    if cert.get("chain_length", 1) < 2:
        cert["chain_length"] = 2
    cert["reasons"] = [r for r in cert.get("reasons") or [] if "chain" not in r.lower()]
    detail["certificate"] = cert
    s.tls_detail = detail
    return True


def _t_pqc(s, _profiles, _ctx):
    if s.tls_version != "TLS 1.3" or not s.tls_pqc_offered or s.tls_pqc_selected:
        return False
    s.tls_pqc_selected = True
    s.tls_selected_group = "X25519MLKEM768"
    detail = dict(s.tls_detail or {})
    detail.update({"selected_group": "X25519MLKEM768", "pqc_group_selected": "X25519MLKEM768"})
    s.tls_detail = detail
    return True


def _t_ports(s, _profiles, _ctx):
    if s.detection_method not in ("payload_signature_port_mismatch", "payload_signature_nonstandard_port"):
        return False
    s.detection_method = "payload_signature"
    return True


_TRANSFORMS = {
    "enforce_tls": _t_enforce_tls,
    "deploy_mta_sts_dane": _t_mta_sts,
    "disable_legacy_tls": _t_legacy,
    "modern_ciphers": _t_ciphers,
    "renew_certificate": _t_renew,
    "fix_certificate_chain": _t_chain,
    "enable_hybrid_pqc": _t_pqc,
    "standard_ports": _t_ports,
    "publish_dmarc": None,
}


# --------------------------------------------------------------------------- #
# Re-evaluation
# --------------------------------------------------------------------------- #

def _as_finding(payload: dict, ref: str) -> SimpleNamespace:
    return SimpleNamespace(ref=ref, **payload)


def evaluate_findings(sessions: list[EmailSession], carried: list) -> list[SimpleNamespace]:
    drafts = []
    for s in sessions:
        drafts.extend(session_findings(s))
        drafts.extend(session_tls_findings(s))
        drafts.extend(session_certificate_findings(s))
    drafts.extend(starttls_stripping.detect(sessions))
    drafts.extend(readiness_finding(sessions))
    resolved = [d.resolve() for d in drafts]
    resolved.sort(key=lambda f: (f["severity_rank"], f["first_frame"] or 0))
    out = [_as_finding(p, f"P-{i:04d}") for i, p in enumerate(resolved, start=1)]
    return out + list(carried)


def _state_summary(sessions: list[EmailSession]) -> dict:
    email = [s for s in sessions if s.protocol]
    protected = sum(1 for s in email if s.encryption_state in ("TLS_ESTABLISHED", "IMPLICIT_TLS"))
    cleartext = sum(1 for s in email if s.encryption_state in _CLEARTEXT)
    return {
        "sessions": len(email),
        "protected": protected,
        "cleartext": cleartext,
        "credentials_exposed": sum(1 for s in email if s.cleartext_auth_observed),
        "by_state": dict(Counter(s.encryption_state for s in email)),
        "by_tls_version": dict(Counter(s.tls_version for s in email if s.tls_version)),
        "forward_secrecy": sum(1 for s in email if s.tls_forward_secrecy),
        "pqc_selected": sum(1 for s in email if s.tls_pqc_selected),
    }


def _finding_key(f) -> tuple:
    return (f.category, f.session_ref or ((f.evidence or {}).get("domain")) or "")


def _finding_row(f) -> dict:
    return {
        "ref": getattr(f, "ref", None), "category": f.category, "severity": f.severity,
        "title": f.title, "session_ref": f.session_ref, "verdict": f.verdict,
    }


def _session_view(s: EmailSession) -> dict:
    cert = (s.tls_detail or {}).get("certificate") or {}
    return {
        "encryption_state": s.encryption_state,
        "tls_version": s.tls_version,
        "cipher_suite": s.tls_cipher_suite,
        "forward_secrecy": s.tls_forward_secrecy,
        "pqc_selected": s.tls_pqc_selected,
        "cleartext_auth": s.cleartext_auth_observed,
        "certificate_ok": (
            None if not cert.get("observed") else not any(
                cert.get(k) for k in ("expired", "not_yet_valid", "weak_key", "broken_signature",
                                      "self_signed", "chain_incomplete", "chain_invalid")
            ) and cert.get("hostname_match") is not False
        ),
        "risk_class": s.risk_class,
        "risk_score": round(s.risk_score, 1) if s.risk_score is not None else None,
    }


def _pqc_view(sessions: list[EmailSession]) -> dict:
    """Post-quantum readiness and harvest-now-decrypt-later exposure, compactly."""
    r = assess_pqc(sessions)
    return {
        "score": r.get("score"),
        "level_label": r.get("level_label"),
        "hndl_exposed_pct": r.get("hndl_exposed_pct"),
        "exposure": [{k: t[k] for k in ("tier", "label", "sessions", "pct")} for t in r.get("exposure") or []],
    }


def normalise_fixes(fixes: list[dict]) -> list[dict]:
    seen = {}
    for f in fixes:
        fid = f.get("id")
        if fid not in FIXES:
            continue
        servers = f.get("servers") or None
        if fid in seen and seen[fid] is not None and servers is not None:
            seen[fid] = sorted(set(seen[fid]) | set(servers))
        elif fid in seen:
            seen[fid] = None
        else:
            seen[fid] = sorted(servers) if servers else None
    return [{"id": fid, "servers": seen[fid]} for fid in sorted(seen, key=_ORDER.index)]


def project(
    capture: Capture,
    sessions: list[EmailSession],
    findings: list[Finding],
    fixes: list[dict],
    *,
    with_risk: bool = True,
    with_graph: bool = True,
) -> dict:
    """Apply fixes to a copy of the sessions and re-evaluate everything."""
    fixes = normalise_fixes(fixes)
    twin = clone(sessions)
    ctx = {"capture_time": capture.first_packet_at or capture.uploaded_at, "profile_source": {}}
    profiles = _best_profiles(twin)

    changed_by: dict[str, list[str]] = {}
    resolved_categories: set[str] = set()
    for fix in fixes:
        transform = _TRANSFORMS.get(fix["id"])
        scope = set(fix["servers"]) if fix["servers"] else None
        if fix["id"] in ("deploy_mta_sts_dane", "publish_dmarc"):
            resolved_categories |= FIXES[fix["id"]].resolves & _DNS_CATEGORIES
        if transform is None:
            continue
        for s in twin:
            if scope is not None and _server(s) not in scope:
                continue
            if transform(s, profiles, ctx):
                changed_by.setdefault(s.ref, []).append(fix["id"])
        profiles = _best_profiles(twin)

    # DNS findings: carried unless resolved. An MTA-STS violation also clears
    # once none of its servers carries cleartext any more.
    by_server: dict[str, list[EmailSession]] = {}
    for s in twin:
        by_server.setdefault(_server(s), []).append(s)
    carried = []
    for f in findings:
        if f.category not in _DNS_CATEGORIES or f.category in resolved_categories:
            continue
        if f.category == "mta_sts_policy_violation":
            servers = (f.evidence or {}).get("servers") or []
            if not any(s.encryption_state in _CLEARTEXT for key in servers for s in by_server.get(key, [])):
                continue
        carried.append(f)

    projected = evaluate_findings(twin, carried)

    if with_risk and ml_risk.available():
        ml_risk.apply(twin)
        risk_after = ml_risk.capture_index(ml_risk.classify(twin))
        risk_before = ml_risk.capture_index(ml_risk.classify(sessions))
    else:
        risk_before = risk_after = None

    posture_before = compute(sessions, findings).serialise()
    posture_after = compute(twin, projected).serialise()

    before_fail = [f for f in findings if f.verdict == "FAIL"]
    after_fail = [f for f in projected if f.verdict == "FAIL"]
    after_keys = Counter(_finding_key(f) for f in after_fail)
    before_keys = Counter(_finding_key(f) for f in before_fail)

    resolved, remaining = [], []
    budget = after_keys.copy()
    for f in before_fail:
        k = _finding_key(f)
        if budget[k] > 0:
            budget[k] -= 1
            remaining.append(_finding_row(f))
        else:
            resolved.append(_finding_row(f))
    budget = before_keys.copy()
    introduced = []
    for f in after_fail:
        k = _finding_key(f)
        if budget[k] > 0:
            budget[k] -= 1
        else:
            introduced.append(_finding_row(f))

    originals = {s.ref: s for s in sessions}
    session_changes = [
        {
            "ref": s.ref,
            "server": _server(s),
            "protocol": s.protocol,
            "fixes": changed_by[s.ref],
            "tls_profile_source": ctx["profile_source"].get(s.ref),
            "before": _session_view(originals[s.ref]),
            "after": _session_view(s),
        }
        for s in twin if s.ref in changed_by
    ]

    return {
        "fixes": fixes,
        "projection": True,
        "posture": {"before": posture_before, "after": posture_after},
        "risk": {"before": risk_before, "after": risk_after},
        "pqc": {"before": _pqc_view(sessions), "after": _pqc_view(twin)},
        "state": {"before": _state_summary(sessions), "after": _state_summary(twin)},
        "findings": {
            "before": len(before_fail),
            "after": len(after_fail),
            "resolved": resolved,
            "remaining": remaining,
            "introduced": introduced,
            "by_severity_before": dict(Counter(f.severity for f in before_fail)),
            "by_severity_after": dict(Counter(f.severity for f in after_fail)),
        },
        "sessions_changed": session_changes,
        "graph": (
            {"before": dep_graph.build(sessions, findings), "after": dep_graph.build(twin, projected)}
            if with_graph else None
        ),
        "note": (
            "Projection: the observed sessions re-evaluated as if each fix had been in place when "
            "the traffic was captured. Every rule, score and model is the same one used on the real "
            "evidence. Confirm with the verification commands and a fresh capture."
        ),
    }


def score_only(capture: Capture, sessions: list[EmailSession], findings: list[Finding],
               fixes: list[dict]) -> tuple[int | None, int, dict]:
    """Cheap projection for the planner: overall score, FAIL count, severities."""
    result = project(capture, sessions, findings, fixes, with_risk=False, with_graph=False)
    return (
        result["posture"]["after"]["overall"],
        result["findings"]["after"],
        result["findings"]["by_severity_after"],
    )
