"""Client TLS fingerprint clustering.

Every client announces its TLS stack in the ClientHello: which versions,
cipher suites, extensions and key-exchange groups it offers. Clients built on
the same software produce near-identical offers, so clustering those offers
recovers the client *population* -- "these 34 sessions are one mail client
build, these 3 are something else" -- without any signature database.

Why it matters for a SOC: a mail estate normally has a handful of client
stacks. A handshake that belongs to no cluster (DBSCAN noise), or a cluster of
one, is a client nobody has seen before: a script, a scanner, an outdated
device, or an implant speaking SMTP. That is anomalous TLS behaviour detected
from the client side, complementing the per-server baseline and Isolation
Forest, which look at sessions as a whole.

Method: numeric feature vector per ClientHello -> standardise -> DBSCAN
(density clustering, no preset number of clusters) -> PCA to two components
for display. Deterministic for a given capture.
"""

from __future__ import annotations

from app.ml.runtime import native

from collections import Counter

from app.models.session import EmailSession

_VERSION_RANK = {"SSL 3.0": 1, "TLS 1.0": 2, "TLS 1.1": 3, "TLS 1.2": 4, "TLS 1.3": 5}
_COMMON_GROUPS = ["x25519", "secp256r1", "secp384r1", "secp521r1", "x448", "ffdhe2048", "ffdhe3072"]

FEATURES = [
    "max_version_offered", "versions_offered", "cipher_count", "extension_count",
    "groups_offered", "offers_pqc", "sni_present", "alpn_present",
    *[f"group_{g}" for g in _COMMON_GROUPS],
]


def _ja4_parts(ja4: str | None) -> tuple[int, int, bool, bool]:
    """(cipher count, extension count, SNI present, ALPN present) from a JA4 string."""
    if not ja4 or len(ja4) < 10:
        return 0, 0, False, False
    head = ja4.split("_")[0]
    try:
        ciphers = int(head[4:6])
        exts = int(head[6:8])
    except ValueError:
        ciphers = exts = 0
    return ciphers, exts, head[3:4] == "d", head[8:10] not in ("00", "")


def _vector(s: EmailSession) -> list[float]:
    d = s.tls_detail or {}
    versions = d.get("versions_offered") or []
    groups = [g.lower() for g in (d.get("groups_offered") or [])]
    ciphers, exts, sni, alpn = _ja4_parts(s.tls_ja4)
    return [
        float(max((_VERSION_RANK.get(v, 0) for v in versions), default=0)),
        float(len(versions)),
        float(ciphers),
        float(exts),
        float(len(groups)),
        1.0 if s.tls_pqc_offered else 0.0,
        1.0 if sni else 0.0,
        1.0 if alpn else 0.0,
        *[1.0 if g in groups else 0.0 for g in _COMMON_GROUPS],
    ]


def _describe(members: list[EmailSession]) -> dict:
    d = members[0].tls_detail or {}
    versions = d.get("versions_offered") or []
    ciphers, exts, _, _ = _ja4_parts(members[0].tls_ja4)
    return {
        "max_version": max(versions, key=lambda v: _VERSION_RANK.get(v, 0)) if versions else None,
        "offers_pqc": any(m.tls_pqc_offered for m in members),
        "cipher_count": ciphers,
        "extension_count": exts,
        "groups": (d.get("groups_offered") or [])[:6],
    }


def _analyse_impl(sessions: list[EmailSession]) -> dict:
    hellos = [s for s in sessions if s.protocol and s.tls_ja4]
    if len(hellos) < 2:
        return {
            "available": False,
            "reason": "At least two TLS ClientHellos are needed to compare client stacks.",
            "clusters": [], "points": [], "features": FEATURES,
        }

    import numpy as np
    from sklearn.cluster import DBSCAN
    from sklearn.decomposition import PCA
    from sklearn.preprocessing import StandardScaler

    X = np.array([_vector(s) for s in hellos], dtype=float)
    Xs = StandardScaler().fit_transform(X) if len(hellos) > 1 else X
    Xs = np.nan_to_num(Xs)
    labels = DBSCAN(eps=1.2, min_samples=2).fit_predict(Xs)

    n_comp = 2 if Xs.shape[1] >= 2 and len(hellos) >= 2 else 1
    try:
        coords = PCA(n_components=n_comp, random_state=0).fit_transform(Xs)
    except Exception:  # noqa: BLE001 - degenerate (identical) inputs
        coords = np.zeros((len(hellos), 2))
    if coords.shape[1] == 1:
        coords = np.hstack([coords, np.zeros_like(coords)])

    groups: dict[int, list[int]] = {}
    for i, lab in enumerate(labels):
        groups.setdefault(int(lab), []).append(i)

    clusters = []
    membership: dict[str, str] = {}
    cluster_id = {}
    ordered = sorted((k for k in groups if k != -1), key=lambda k: -len(groups[k]))
    for n, k in enumerate(ordered, start=1):
        cluster_id[k] = f"C{n}"
    total = len(hellos)
    for k, idx in groups.items():
        is_noise = k == -1
        # Each noise point is its own singleton "cluster" for display.
        units = [[i] for i in idx] if is_noise else [idx]
        for u_n, unit in enumerate(units):
            mem = [hellos[i] for i in unit]
            cid = f"N{u_n + 1}" if is_noise else cluster_id[k]
            ja4 = Counter(m.tls_ja4 for m in mem).most_common(1)[0][0]
            share = len(unit) / total
            for m in mem:
                membership[m.ref] = cid
            clusters.append({
                "id": cid,
                "size": len(unit),
                "share_pct": round(100 * share, 1),
                "novel": is_noise or (share < 0.1 and total >= 10),
                "ja4": ja4,
                "ja3": Counter(m.tls_ja3 for m in mem).most_common(1)[0][0],
                "clients": sorted({m.client_ip for m in mem})[:8],
                "servers": sorted({f"{m.server_ip}:{m.server_port}" for m in mem})[:8],
                "sessions": [m.ref for m in mem][:20],
                "profile": _describe(mem),
            })

    clusters.sort(key=lambda c: (c["novel"], -c["size"]))
    novel_ids = {c["id"] for c in clusters if c["novel"]}
    ref_to_cluster = membership
    points = [
        {
            "ref": s.ref,
            "x": round(float(coords[i][0]), 3),
            "y": round(float(coords[i][1]), 3),
            "cluster": ref_to_cluster.get(s.ref, "N"),
            "client": s.client_ip,
            "ja4": s.tls_ja4,
            "novel": ref_to_cluster.get(s.ref, "N") in novel_ids,
        }
        for i, s in enumerate(hellos)
    ]
    novel = [c for c in clusters if c["novel"]]
    return {
        "available": True,
        "sessions": total,
        "clusters": clusters,
        "cluster_count": sum(1 for c in clusters if not c["id"].startswith("N")),
        "novel_count": sum(c["size"] for c in novel),
        "points": points,
        "features": FEATURES,
        "method": (
            f"{len(FEATURES)} ClientHello features (offered versions, cipher and extension counts from "
            "JA4, key-exchange groups, PQC offer, SNI, ALPN), standardised, clustered with DBSCAN "
            "(eps 1.2, min 2 samples) and projected to two dimensions with PCA. Handshakes outside any "
            "dense cluster are reported as novel client stacks."
        ),
    }


def analyse(sessions: list[EmailSession]) -> dict:
    """Cluster client TLS stacks (runs on the ML thread)."""
    return native(_analyse_impl, sessions)
