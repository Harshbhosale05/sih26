#!/usr/bin/env python3
"""Grade the pipeline against testbed ground truth.

Uploads every generated capture, runs analysis, and compares the reconstructed
sessions to the labels the generator wrote. This is the Phase 1 acceptance gate:
detectors are graded against a known oracle, not eyeballed.

    python3 scripts/validate.py [--api http://localhost:8000]
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "testbed" / "output"

# Finding categories the detection engine implements today. Categories in the
# ground truth but not here are pending phases, and are reported as such rather
# than counted as failures -- a scoreboard that hides unbuilt work is useless.
IMPLEMENTED = {
    "cleartext_credential_exposure",
    "starttls_stripping",
    "starttls_downgrade_fallback",
    "starttls_not_advertised",
    "starttls_advertised_not_used",
    "cleartext_mail_transaction",
    "incomplete_evidence",
    "protocol_port_mismatch",
    "deprecated_tls_version",
    "weak_cipher_suite",
    "no_forward_secrecy",
    "certificate_not_observable",
    "mta_sts_policy_violation",
    "mta_sts_not_published",
    "dane_not_deployed",
    "tlsrpt_not_configured",
    "dmarc_not_published",
    "dmarc_policy_none",
    "dns_correlation_incomplete",
    "pqc_server_not_ready",
    "certificate_expired",
    "certificate_not_yet_valid",
    "certificate_expiring_soon",
    "certificate_hostname_mismatch",
    "certificate_weak_key",
    "certificate_weak_signature",
    "certificate_self_signed",
    "certificate_chain_incomplete",
}


def _post_file(api: str, path: Path) -> dict:
    boundary = "----smscope"
    body = b"".join([
        f"--{boundary}\r\n".encode(),
        f'Content-Disposition: form-data; name="file"; filename="{path.name}"\r\n'.encode(),
        b"Content-Type: application/octet-stream\r\n\r\n",
        path.read_bytes(),
        f"\r\n--{boundary}--\r\n".encode(),
    ])
    req = urllib.request.Request(
        f"{api}/api/captures", data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    with urllib.request.urlopen(req, timeout=300) as resp:
        return json.load(resp)


def _post(api: str, path: str) -> dict:
    req = urllib.request.Request(f"{api}{path}", data=b"", method="POST")
    with urllib.request.urlopen(req, timeout=600) as resp:
        return json.load(resp)


def _get(api: str, path: str) -> list | dict:
    with urllib.request.urlopen(f"{api}{path}", timeout=300) as resp:
        return json.load(resp)


def grade(api: str) -> int:
    truths = sorted(OUTPUT.glob("*.truth.json"))
    if not truths:
        print("no ground truth found; run: python3 -m testbed.synthetic.generate --all")
        return 2

    failures = 0
    pending = Counter()
    print(f"{'scenario':<28} {'sessions':>10} {'findings':>10}  result")
    print("-" * 74)

    for truth_path in truths:
        truth = json.loads(truth_path.read_text())
        pcap = OUTPUT / truth["pcap_file"]
        if not pcap.exists():
            continue

        try:
            capture = _post_file(api, pcap)
            result = _post(api, f"/api/captures/{capture['capture_id']}/analyze")
            sessions = _get(api, f"/api/captures/{capture['capture_id']}/sessions")
        except urllib.error.HTTPError as exc:
            print(f"{truth['scenario']:<28} {'-':>16} {'-':>10} {'-':>8}  HTTP {exc.code}")
            failures += 1
            continue

        # Tier 2 captures live traffic, where exact session and finding counts
        # depend on the server implementation (aiosmtpd opens a readiness probe
        # connection, for instance). Asserting counts there would test the
        # testbed rather than the analyser, so tier 2 asserts only that every
        # expected finding category was detected.
        if truth.get("tier") == "docker-live":
            findings = _get(api, f"/api/captures/{capture['capture_id']}/findings")
            got = {f["category"] for f in findings}
            missing = [c for c in truth.get("expected_categories", []) if c not in got]
            status = "ok" if not missing else "FAIL"
            if missing:
                failures += 1
            print(
                f"{truth['scenario']:<28} {result['sessions']:>10} "
                f"{len(findings):>10}  {status}"
            )
            for m in missing:
                print(f"{'':<28} └─ missed {m}")
            continue

        expected_sessions = truth["session_count"]
        got_sessions = result["sessions"]

        expected_proto = Counter(s["protocol"] for s in truth["sessions"])
        got_proto = Counter(result["by_protocol"])

        expected_states = Counter(s["encryption_state"] for s in truth["sessions"])
        got_states = Counter(result["by_encryption_state"])

        problems = []
        if got_sessions != expected_sessions:
            problems.append(f"sessions {got_sessions}!={expected_sessions}")
        if got_proto != expected_proto:
            problems.append(f"protocols {dict(got_proto)}!={dict(expected_proto)}")
        if got_states != expected_states:
            diff_missing = expected_states - got_states
            diff_extra = got_states - expected_states
            problems.append(f"states -{dict(diff_missing)} +{dict(diff_extra)}")

        # --- Findings ------------------------------------------------------
        findings = _get(api, f"/api/captures/{capture['capture_id']}/findings")
        got_categories = Counter(f["category"] for f in findings)
        expected_categories = Counter(
            f["category"] for f in truth["expected_findings"]
            if f["category"] in IMPLEMENTED
        )
        for category, count in expected_categories.items():
            if got_categories.get(category, 0) < count:
                problems.append(
                    f"missed {category} ({got_categories.get(category, 0)}/{count})"
                )

        # Findings must point at the frames the generator says prove them.
        for expected in truth["expected_findings"]:
            if expected["category"] not in IMPLEMENTED or not expected["evidence_frames"]:
                continue
            match = [
                f for f in findings
                if f["category"] == expected["category"]
                and f["session_ref"] == expected["session"]
            ]
            if match and not set(expected["evidence_frames"]) & set(
                match[0]["evidence_frames"] or []
            ):
                problems.append(
                    f"{expected['category']} cites frames "
                    f"{match[0]['evidence_frames']}, expected {expected['evidence_frames']}"
                )

        # The negative controls: ANY finding above INFO on a clean capture is a
        # false positive and a hard failure.
        if truth["label"] in ("secure", "secure_implicit"):
            noisy = [f["ref"] for f in findings if f["severity"] != "INFO"]
            if noisy:
                problems.append(f"FALSE POSITIVES on clean capture: {noisy}")

        # Truncated captures must be reported as indeterminate, never resolved.
        if truth["label"] == "incomplete_evidence":
            if result["indeterminate"] == 0:
                problems.append("truncated capture produced no UNKNOWN verdict")
            if not any(f["verdict"] == "UNKNOWN" for f in findings):
                problems.append("no UNKNOWN-verdict finding for truncated session")

        status = "ok" if not problems else "FAIL"
        if problems:
            failures += 1
        for f in truth["expected_findings"]:
            if f["category"] not in IMPLEMENTED:
                pending[f["category"]] += 1
        print(
            f"{truth['scenario']:<28} {f'{got_sessions}/{expected_sessions}':>10} "
            f"{len(findings):>10}  {status}"
        )
        for problem in problems:
            print(f"{'':<28} └─ {problem}")

    print("-" * 74)
    print(f"{len(truths) - failures}/{len(truths)} scenarios passed")
    if pending:
        print("\npending (later phases, not failures):")
        for category, count in sorted(pending.items()):
            print(f"  {category:<28} {count} expected finding(s)")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://localhost:8000")
    args = parser.parse_args()
    return grade(args.api)


if __name__ == "__main__":
    sys.exit(main())
