"""Labelled training corpus for the session risk classifier.

The scenario catalogue proves detectors right on hand-picked cases. A model
needs something else: many sessions drawn across the whole configuration space,
each with a label that does not come from the detector it will sit beside.

So every session here is generated from an explicit configuration -- protocol,
upgrade behaviour, TLS version, cipher, certificate fixture, credential
behaviour -- and labelled from that configuration by an analyst-style severity
table (`label_for`). The pipeline never sees the label; it sees only packets.
Training then asks: given what the passive pipeline could observe, can a model
recover the risk an analyst would assign knowing the true configuration?

    python3 -m testbed.synthetic.corpus --sessions 1500 --seed 7
"""

from __future__ import annotations

import argparse
import json
import random
from collections import Counter
from pathlib import Path

from testbed.synthetic import tls
from testbed.synthetic.pcap import PcapWriter
from testbed.synthetic.scenarios import Lab, imap_session, pop3_session, smtp_session

OUTPUT_DIR = Path(__file__).resolve().parents[1] / "output" / "corpus"

RISK_CLASSES = ["minimal", "low", "medium", "high", "critical"]

SERVERS = [
    ("10.10.2.50", "mail01.corp.local"),
    ("10.10.2.51", "mail02.corp.local"),
    ("10.10.3.20", "relay.corp.local"),
    ("10.20.0.5", "imap.branch.corp.local"),
]

TLS13_SUITES = [tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256]
MODERN_12 = [tls.TLS_ECDHE_RSA_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_AES_256_GCM_SHA384]
CBC_FS_12 = [tls.TLS_ECDHE_RSA_AES_128_CBC_SHA256]
STATIC_RSA = [tls.TLS_RSA_AES_128_CBC_SHA, tls.TLS_RSA_AES_256_CBC_SHA]
BROKEN = [tls.TLS_RSA_3DES_EDE_CBC_SHA, tls.TLS_RSA_RC4_128_SHA]

# Analyst severity of each certificate fixture, mirroring how a reviewer who
# knows the fixture would grade it (expired leaf on a live relay = critical).
CERT_RISK = {
    "valid": 0, "expiring_soon": 2, "self_signed": 2, "wrong_host": 3,
    "weak_key": 3, "sha1_signed": 3, "not_yet_valid": 3, "expired": 4,
}


def label_for(cfg: dict) -> int:
    """Severity an analyst assigns from the *true* configuration (0..4)."""
    if not cfg["tls"]:
        if cfg.get("mangled") or cfg.get("fallback") or cfg.get("cleartext_auth"):
            return 4
        return 3  # mail content in the clear

    risk = 0
    version, cipher = cfg["version"], cfg["cipher"]
    if version in (tls.TLS1_0, tls.TLS1_1):
        risk = max(risk, 3)
    elif version == tls.TLS1_2:
        risk = max(risk, 1)
    if cipher in STATIC_RSA or cipher in BROKEN:
        risk = max(risk, 3)
    elif cipher in CBC_FS_12:
        risk = max(risk, 2)
    if cfg.get("cert"):
        risk = max(risk, CERT_RISK[cfg["cert"]])
    return risk


def _tls_params(rng: random.Random, profile: str) -> tuple[int, int]:
    if profile == "modern":
        return tls.TLS1_3, rng.choice(TLS13_SUITES)
    if profile == "acceptable":
        return tls.TLS1_2, rng.choice(MODERN_12)
    if profile == "cbc":
        return tls.TLS1_2, rng.choice(CBC_FS_12)
    if profile == "static_rsa":
        return rng.choice([tls.TLS1_2, tls.TLS1_2, tls.TLS1_1]), rng.choice(STATIC_RSA)
    if profile == "legacy":
        return rng.choice([tls.TLS1_0, tls.TLS1_1]), rng.choice(MODERN_12[:1] + STATIC_RSA + BROKEN)
    return tls.TLS1_2, rng.choice(BROKEN)  # "broken"


def _sample(rng: random.Random) -> dict:
    protocol = rng.choices(["SMTP", "IMAP", "POP3"], weights=[0.6, 0.2, 0.2])[0]
    server = rng.choice(SERVERS)
    client = f"10.10.{rng.randint(2, 9)}.{rng.randint(10, 250)}"

    transport = rng.choices(
        ["tls", "implicit", "not_used", "not_advertised", "mangled", "fallback", "cleartext_auth"],
        weights=[0.52, 0.08, 0.1, 0.08, 0.07, 0.06, 0.09],
    )[0]
    if protocol != "SMTP" and transport in ("implicit", "mangled", "fallback"):
        transport = "tls"

    profile = rng.choices(
        ["modern", "acceptable", "cbc", "static_rsa", "legacy", "broken"],
        weights=[0.34, 0.26, 0.1, 0.12, 0.12, 0.06],
    )[0]
    version, cipher = _tls_params(rng, profile)

    cfg = {
        "protocol": protocol, "server": server, "client": client, "transport": transport,
        "tls": transport in ("tls", "implicit"), "version": version, "cipher": cipher,
        "mangled": transport == "mangled", "fallback": transport == "fallback",
        "cleartext_auth": transport == "cleartext_auth", "cert": None,
        "pqc": version == tls.TLS1_3 and rng.random() < 0.25,
    }
    # Certificates are only visible on TLS <= 1.2 SMTP (the builder carries them).
    if protocol == "SMTP" and cfg["tls"] and version != tls.TLS1_3 and transport == "tls":
        cfg["cert"] = rng.choices(list(CERT_RISK), weights=[5, 1, 1, 1, 1, 1, 1, 1])[0]
    return cfg


def _emit(writer: PcapWriter, lab: Lab, cfg: dict, seed: int) -> str:
    common = dict(server=cfg["server"], client_ip=cfg["client"], seed=seed)
    t = cfg["transport"]
    if cfg["protocol"] == "SMTP":
        truth, _ = smtp_session(
            writer, lab, **common,
            port=465 if t == "implicit" else rng_port(seed),
            implicit_tls=t == "implicit",
            advertise_starttls=t not in ("not_advertised",),
            mangle_starttls=t == "mangled",
            use_starttls=t in ("tls", "fallback"),
            starttls_succeeds=t != "fallback",
            cleartext_auth=t == "cleartext_auth" or (t in ("mangled", "fallback") and seed % 2 == 0),
            tls_version=cfg["version"], cipher=cfg["cipher"],
            offer_pqc=cfg["pqc"], certificate=cfg["cert"],
        )
    elif cfg["protocol"] == "IMAP":
        truth, _ = imap_session(
            writer, lab, **common,
            advertise_starttls=t != "not_advertised",
            use_starttls=t == "tls",
            cleartext_login=t == "cleartext_auth",
            tls_version=cfg["version"], cipher=cfg["cipher"],
        )
    else:
        truth, _ = pop3_session(
            writer, lab, **common,
            advertise_stls=t != "not_advertised",
            use_stls=t == "tls",
            cleartext_auth=t == "cleartext_auth",
            tls_version=cfg["version"], cipher=cfg["cipher"],
        )
    return truth.session


def rng_port(seed: int) -> int:
    return 587 if seed % 3 else 25


def generate(sessions: int, seed: int, output_dir: Path, chunk: int = 500) -> dict:
    """Write the corpus as several pcaps (keeps each tshark pass small)."""
    rng = random.Random(seed)
    output_dir.mkdir(parents=True, exist_ok=True)
    labels: dict[str, dict] = {}
    files = []
    counts: Counter = Counter()

    for part, start in enumerate(range(0, sessions, chunk)):
        writer, lab = PcapWriter(), Lab()
        part_labels = {}
        for i in range(start, min(start + chunk, sessions)):
            cfg = _sample(rng)
            name = _emit(writer, lab, cfg, seed=i)
            risk = label_for(cfg)
            # The emitted session sends cleartext auth for some stripped/fallback
            # sessions; the label is already critical for those either way.
            part_labels[name] = {
                "risk": RISK_CLASSES[risk],
                "risk_index": risk,
                "config": {
                    **{k: v for k, v in cfg.items() if k not in ("server", "version", "cipher")},
                    "server": cfg["server"][1],
                    "version": tls.VERSION_NAMES[cfg["version"]] if cfg["tls"] else None,
                    "cipher": hex(cfg["cipher"]) if cfg["tls"] else None,
                },
            }
            counts[RISK_CLASSES[risk]] += 1
        pcap = output_dir / f"corpus-{part:02d}.pcap"
        writer.write(pcap)
        (output_dir / f"corpus-{part:02d}.labels.json").write_text(json.dumps(part_labels, indent=1))
        files.append(pcap.name)
        labels.update({f"{part:02d}/{k}": v for k, v in part_labels.items()})

    manifest = {
        "sessions": sessions, "seed": seed, "files": files,
        "class_counts": dict(counts), "classes": RISK_CLASSES,
        "labelling": (
            "Each label is assigned from the generated session's true configuration using "
            "an analyst severity table (testbed/synthetic/corpus.py:label_for). The analysis "
            "pipeline never sees labels; the model learns from passively observed features."
        ),
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the labelled risk-model corpus.")
    parser.add_argument("--sessions", type=int, default=1500)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--output", type=Path, default=OUTPUT_DIR)
    args = parser.parse_args(argv)
    manifest = generate(args.sessions, args.seed, args.output)
    print(json.dumps({k: manifest[k] for k in ("sessions", "files", "class_counts")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
