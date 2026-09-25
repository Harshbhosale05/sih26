"""CLI: generate synthetic labelled captures.

    python -m testbed.synthetic.generate --all
    python -m testbed.synthetic.generate 09-starttls-stripping
    python -m testbed.synthetic.generate --list

Each scenario writes two files to testbed/output/:
    <scenario>.pcap            the capture
    <scenario>.truth.json      ground truth, including the sha256 of the pcap

The truth file records the pcap's sha256, so a mismatch proves the capture and
its labels have drifted apart.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from testbed.synthetic.pcap import PcapWriter
from testbed.synthetic.scenarios import SCENARIOS, Lab

OUTPUT_DIR = Path(__file__).resolve().parents[1] / "output"


def generate_one(name: str, output_dir: Path) -> tuple[Path, dict]:
    builder = SCENARIOS[name]
    writer = PcapWriter()
    lab = Lab()

    truth = builder(writer, lab)

    pcap_path = output_dir / f"{name}.pcap"
    frames = writer.write(pcap_path, truncate_after=truth.truncate_after)

    payload = truth.serialise()
    payload["pcap_file"] = pcap_path.name
    payload["frame_count"] = frames
    payload["session_count"] = len(truth.sessions)
    payload["pcap_sha256"] = hashlib.sha256(pcap_path.read_bytes()).hexdigest()
    if truth.truncate_after is not None:
        payload["truncated"] = True

    truth_path = output_dir / f"{name}.truth.json"
    truth_path.write_text(json.dumps(payload, indent=2) + "\n")

    return pcap_path, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate synthetic labelled captures.")
    parser.add_argument("scenarios", nargs="*", help="scenario names (default: all)")
    parser.add_argument("--all", action="store_true", help="generate every scenario")
    parser.add_argument("--list", action="store_true", help="list available scenarios")
    parser.add_argument("--output", type=Path, default=OUTPUT_DIR)
    args = parser.parse_args(argv)

    if args.list:
        for name in SCENARIOS:
            print(name)
        return 0

    selected = args.scenarios or list(SCENARIOS)
    if args.all:
        selected = list(SCENARIOS)

    unknown = [s for s in selected if s not in SCENARIOS]
    if unknown:
        print(f"unknown scenario(s): {', '.join(unknown)}", file=sys.stderr)
        print(f"available: {', '.join(SCENARIOS)}", file=sys.stderr)
        return 2

    args.output.mkdir(parents=True, exist_ok=True)

    print(f"{'scenario':<28} {'frames':>7} {'sessions':>9}  {'findings':>8}  label")
    print("-" * 78)
    for name in selected:
        path, payload = generate_one(name, args.output)
        print(
            f"{name:<28} {payload['frame_count']:>7} {payload['session_count']:>9}"
            f"  {len(payload['expected_findings']):>8}  {payload['label']}"
        )

    print(f"\nwrote {len(selected)} capture(s) to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
