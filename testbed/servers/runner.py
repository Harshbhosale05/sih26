#!/usr/bin/env python3
"""Tier-2 testbed: real servers, real TLS handshakes, captured with tcpdump.

Everything runs inside one container, and the capture is taken on loopback.
Server, client and tcpdump therefore share a network namespace, which removes
the entire class of multi-container networking problems — there is no bridge,
no DNS between services, and nothing to mis-wire.

What this produces that tier 1 cannot: genuine TLS handshakes negotiated by
OpenSSL, carrying real certificates served by a real SMTP implementation. It is
the check that our parser works on traffic nobody synthesised.

    docker compose --profile testbed run --rm testbed
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import signal
import smtplib
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Sink

import certs

CAPTURE_IF = "lo"
BIND = "127.0.0.1"
# Clients connect by NAME, not by address. RFC 6066 forbids an IP literal in
# SNI, so connecting to 127.0.0.1 produces a handshake with no SNI at all --
# and then certificate hostname verification has nothing to check against.
# Real MTAs resolve and connect by name; the capture has to match.
HOST = "mail.testbed.local"


@dataclass
class Scenario:
    name: str
    label: str
    description: str
    port: int
    certificate: str = "valid"
    min_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2
    max_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3
    ciphers: str | None = None
    implicit_tls: bool = False
    offer_starttls: bool = True
    client_uses_starttls: bool = True
    cleartext_auth: bool = False
    seclevel_0: bool = False
    expect: list[str] = field(default_factory=list)


SCENARIOS: list[Scenario] = [
    Scenario(
        name="t2-01-tls13", label="secure", port=3301,
        description="Real TLS 1.3 handshake over STARTTLS.",
        min_version=ssl.TLSVersion.TLSv1_3,
        expect=["certificate_not_observable"],
    ),
    Scenario(
        name="t2-02-tls12", label="acceptable", port=3302,
        description="Real TLS 1.2 handshake; certificate visible on the wire.",
        min_version=ssl.TLSVersion.TLSv1_2, max_version=ssl.TLSVersion.TLSv1_2,
        ciphers="ECDHE-RSA-AES256-GCM-SHA384",
    ),
    Scenario(
        name="t2-03-expired-cert", label="expired_cert", port=3303,
        description="Real TLS 1.2 handshake serving a genuinely expired certificate.",
        certificate="expired",
        min_version=ssl.TLSVersion.TLSv1_2, max_version=ssl.TLSVersion.TLSv1_2,
        ciphers="ECDHE-RSA-AES256-GCM-SHA384",
        expect=["certificate_expired"],
    ),
    Scenario(
        name="t2-04-weak-key", label="weak_key", port=3304,
        description="Real TLS 1.2 handshake with a 1024-bit RSA certificate.",
        certificate="weak_key",
        min_version=ssl.TLSVersion.TLSv1_2, max_version=ssl.TLSVersion.TLSv1_2,
        ciphers="ECDHE-RSA-AES256-GCM-SHA384",
        seclevel_0=True,   # OpenSSL refuses a 1024-bit key above security level 1
        expect=["certificate_weak_key"],
    ),
    Scenario(
        name="t2-05-wrong-host", label="cert_mismatch", port=3305,
        description="Certificate for a different host, served over real TLS 1.2.",
        certificate="wrong_host",
        min_version=ssl.TLSVersion.TLSv1_2, max_version=ssl.TLSVersion.TLSv1_2,
        ciphers="ECDHE-RSA-AES256-GCM-SHA384",
        expect=["certificate_hostname_mismatch"],
    ),
    Scenario(
        name="t2-06-incomplete-chain", label="chain_incomplete", port=3306,
        description="Leaf certificate served without its issuer chain.",
        certificate="chain_incomplete",
        min_version=ssl.TLSVersion.TLSv1_2, max_version=ssl.TLSVersion.TLSv1_2,
        ciphers="ECDHE-RSA-AES256-GCM-SHA384",
        expect=["certificate_chain_incomplete"],
    ),
    Scenario(
        name="t2-07-cleartext-auth", label="credential_exposure", port=3307,
        description="Server offers no STARTTLS; client authenticates in the clear.",
        offer_starttls=False, client_uses_starttls=False, cleartext_auth=True,
        expect=["cleartext_credential_exposure", "starttls_not_advertised"],
    ),
    Scenario(
        name="t2-08-implicit-tls", label="secure_implicit", port=465,
        description=(
            "Implicit TLS from the first byte on port 465. A registered port is "
            "required here: with no plaintext dialogue there is no greeting to "
            "identify, so the port is the only signal that this is mail."
        ),
        implicit_tls=True, min_version=ssl.TLSVersion.TLSv1_2,
        max_version=ssl.TLSVersion.TLSv1_2,
        ciphers="ECDHE-RSA-AES256-GCM-SHA384",
    ),
]


def server_context(scenario: Scenario, cert_paths: dict[str, Path]) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = scenario.min_version
    ctx.maximum_version = scenario.max_version
    if scenario.ciphers:
        # @SECLEVEL=0 is required for keys and algorithms modern OpenSSL
        # otherwise refuses outright -- which is correct of OpenSSL and is
        # exactly why weak configurations are hard to reproduce for testing.
        spec = scenario.ciphers + ("@SECLEVEL=0" if scenario.seclevel_0 else "")
        try:
            ctx.set_ciphers(spec)
        except ssl.SSLError:
            ctx.set_ciphers(scenario.ciphers)
    elif scenario.seclevel_0:
        ctx.set_ciphers("DEFAULT@SECLEVEL=0")
    ctx.load_cert_chain(str(cert_paths[scenario.certificate]))
    return ctx


def client_context() -> ssl.SSLContext:
    # The testbed CA is not in any trust store and several fixtures are
    # deliberately invalid. Verification is off because we are capturing the
    # handshake, not judging it -- our analyser does the judging, later, from
    # the capture.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def run_client(scenario: Scenario) -> str:
    """Drive one SMTP conversation. Returns a status string for the truth file."""
    try:
        if scenario.implicit_tls:
            smtp = smtplib.SMTP_SSL(
                HOST, scenario.port, timeout=15, context=client_context()
            )
        else:
            smtp = smtplib.SMTP(HOST, scenario.port, timeout=15)
            smtp.ehlo("client.testbed.local")
            if scenario.client_uses_starttls:
                smtp.starttls(context=client_context())
                smtp.ehlo("client.testbed.local")

        if scenario.cleartext_auth:
            # smtplib refuses AUTH without TLS, so the commands are issued
            # directly -- which is precisely the behaviour being captured.
            import base64

            smtp.docmd("AUTH", "LOGIN")
            smtp.docmd(base64.b64encode(b"analyst@testbed.local").decode())
            smtp.docmd(base64.b64encode(b"Testbed#2026").decode())

        smtp.sendmail(
            "sender@testbed.local",
            ["recipient@testbed.local"],
            "Subject: testbed\r\n\r\nGenerated by the SecureMailScope tier-2 testbed.\r\n",
        )
        smtp.quit()
        return "ok"
    except Exception as exc:  # noqa: BLE001 - a failed handshake is a valid outcome
        return f"{type(exc).__name__}: {exc}"


def ensure_hostname() -> None:
    """Point the testbed hostname at loopback so clients connect by name."""
    hosts = Path("/etc/hosts")
    entry = f"{BIND} {HOST}\n"
    try:
        if HOST not in hosts.read_text():
            with hosts.open("a") as fh:
                fh.write(entry)
    except OSError as exc:
        print(f"warning: could not add {HOST} to /etc/hosts: {exc}", file=sys.stderr)


def start_capture(outfile: Path, port: int) -> subprocess.Popen:
    proc = subprocess.Popen(
        [
            "tcpdump", "-i", CAPTURE_IF, "-s", "0", "-U",
            "-w", str(outfile), f"tcp port {port}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    time.sleep(1.2)  # let tcpdump attach before any traffic flows
    return proc


def run_scenario(scenario: Scenario, cert_paths: dict[str, Path], outdir: Path) -> dict:
    pcap = outdir / f"{scenario.name}.pcap"
    pcap.unlink(missing_ok=True)

    capture = start_capture(pcap, scenario.port)

    ctx = server_context(scenario, cert_paths)
    kwargs = {"hostname": BIND, "port": scenario.port}
    if scenario.implicit_tls:
        kwargs["ssl_context"] = ctx
    elif scenario.offer_starttls:
        kwargs["tls_context"] = ctx
        kwargs["require_starttls"] = False

    controller = Controller(Sink(), **kwargs)
    status = "not started"
    try:
        controller.start()
        time.sleep(0.4)
        status = run_client(scenario)
    except Exception as exc:  # noqa: BLE001
        status = f"server error: {type(exc).__name__}: {exc}"
    finally:
        try:
            controller.stop()
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.8)
        capture.send_signal(signal.SIGINT)
        try:
            capture.wait(timeout=8)
        except subprocess.TimeoutExpired:
            capture.kill()

    frames = 0
    sha = ""
    if pcap.exists() and pcap.stat().st_size > 24:
        data = pcap.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        result = subprocess.run(
            ["capinfos", "-M", "-c", str(pcap)], capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            if line.lower().startswith("number of packets"):
                try:
                    frames = int(line.split(":", 1)[1].strip().split()[0])
                except (ValueError, IndexError):
                    frames = 0

    truth = {
        "scenario": scenario.name,
        "label": scenario.label,
        "description": scenario.description,
        "tier": "docker-live",
        "pcap_file": pcap.name,
        "pcap_sha256": sha,
        "frame_count": frames,
        "session_count": 1,
        "client_status": status,
        "server_config": {
            "port": scenario.port,
            "certificate": scenario.certificate,
            "min_version": scenario.min_version.name,
            "max_version": scenario.max_version.name,
            "ciphers": scenario.ciphers,
            "implicit_tls": scenario.implicit_tls,
            "offers_starttls": scenario.offer_starttls,
        },
        "expected_categories": scenario.expect,
        "note": (
            "Live capture: real OpenSSL handshake, real certificate, real SMTP "
            "implementation. Session and finding counts are not asserted — this "
            "tier validates that the parser works on traffic nobody synthesised."
        ),
    }
    (outdir / f"{scenario.name}.truth.json").write_text(json.dumps(truth, indent=2) + "\n")
    return truth


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenarios", nargs="*", help="scenario names (default: all)")
    parser.add_argument("--output", type=Path, default=Path("/out"))
    args = parser.parse_args()

    selected = (
        [s for s in SCENARIOS if s.name in args.scenarios] if args.scenarios else SCENARIOS
    )
    if not selected:
        print(f"unknown scenario. available: {', '.join(s.name for s in SCENARIOS)}",
              file=sys.stderr)
        return 2

    args.output.mkdir(parents=True, exist_ok=True)
    ensure_hostname()
    cert_paths = certs.generate(Path("/tmp/testbed-certs"))
    print(f"generated {len(cert_paths)} certificate/key pairs\n")

    print(f"{'scenario':<26} {'frames':>7} {'label':<22} status")
    print("-" * 86)
    failures = 0
    for scenario in selected:
        truth = run_scenario(scenario, cert_paths, args.output)
        ok = truth["client_status"] == "ok" and truth["frame_count"] > 0
        if not ok:
            failures += 1
        print(
            f"{truth['scenario']:<26} {truth['frame_count']:>7} {truth['label']:<22} "
            f"{truth['client_status'][:38]}"
        )

    print("-" * 86)
    print(f"{len(selected) - failures}/{len(selected)} scenarios captured")
    print(f"\nwrote captures to {args.output}")
    return 0


if __name__ == "__main__":
    asyncio.set_event_loop(asyncio.new_event_loop())
    raise SystemExit(main())
