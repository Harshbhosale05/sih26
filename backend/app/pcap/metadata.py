"""Capture metadata extraction via capinfos.

capinfos is part of wireshark-common and gives us the container-level facts we
need for the evidence manifest without walking every packet.

`-M` asks for machine-readable values (raw numbers, no "bytes"/"sec" suffixes),
which is what makes this parseable at all. Note that capinfos still prints
human-readable *keys*, so we normalise them here.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from app.engines import ToolError, run_tool

logger = logging.getLogger(__name__)


@dataclass
class CaptureMetadata:
    file_encapsulation: str | None = None
    packet_count: int | None = None
    data_bytes: int | None = None
    first_packet_at: datetime | None = None
    last_packet_at: datetime | None = None
    duration_seconds: float | None = None
    snaplen: int | None = None
    snaplen_truncated: bool = False
    interface_count: int | None = None
    strict_time_order: bool | None = None
    raw: dict[str, str] = field(default_factory=dict)


def _to_int(value: str) -> int | None:
    try:
        return int(value.strip().split()[0].replace(",", ""))
    except (ValueError, IndexError):
        return None


def _to_float(value: str) -> float | None:
    try:
        return float(value.strip().split()[0].replace(",", ""))
    except (ValueError, IndexError):
        return None


def _to_datetime(value: str) -> datetime | None:
    """Parse a capinfos packet timestamp.

    With -M capinfos emits epoch seconds with fractional precision. Older
    builds emit a formatted date string, so we fall back to that.
    """
    value = value.strip()
    if not value or value.lower() in {"n/a", "unknown"}:
        return None

    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except ValueError:
        pass

    for fmt in (
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%a %b %d, %Y %H:%M:%S.%f",
        "%a %b %d, %Y %H:%M:%S",
    ):
        try:
            return datetime.strptime(value.split(" UTC")[0].strip(), fmt).replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            continue

    logger.warning("could not parse capinfos timestamp %r", value)
    return None


def _parse(stdout: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in stdout.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key and value:
            fields[key] = value
    return fields


def extract_metadata(path: Path) -> CaptureMetadata:
    """Run capinfos and normalise its output.

    Deliberately tolerant: a truncated or damaged capture is a *valid input*
    for this product, not an error. We record what capinfos could determine and
    leave the rest as None so downstream analysis can report UNKNOWN instead of
    inventing values.
    """
    # -M machine-readable, -a/-e first+last packet time, -c counts, -d data size,
    # -E encapsulation, -s snaplen, -y interfaces, -o time order, -u duration.
    argv = ["capinfos", "-M", "-a", "-e", "-c", "-d", "-E", "-s", "-u", "-y", "-o", str(path)]

    try:
        result = run_tool(argv, check=False)
    except ToolError:
        logger.exception("capinfos invocation failed for %s", path)
        return CaptureMetadata()

    if result.returncode != 0 and not result.stdout.strip():
        logger.warning("capinfos failed (%s): %s", result.returncode, result.stderr[:300])
        return CaptureMetadata()

    if result.stderr.strip():
        # capinfos warns but still emits usable output for damaged captures.
        logger.info("capinfos warnings for %s: %s", path.name, result.stderr.strip()[:300])

    fields = _parse(result.stdout)
    meta = CaptureMetadata(raw=fields)

    meta.file_encapsulation = fields.get("file encapsulation")
    meta.packet_count = _to_int(fields.get("number of packets", ""))
    meta.data_bytes = _to_int(fields.get("data size", ""))
    meta.first_packet_at = _to_datetime(fields.get("first packet time", ""))
    meta.last_packet_at = _to_datetime(fields.get("last packet time", ""))
    meta.duration_seconds = _to_float(fields.get("capture duration", ""))
    meta.interface_count = _to_int(fields.get("number of interfaces in file", ""))

    order = fields.get("strict time order", "").lower()
    if order:
        meta.strict_time_order = order.startswith(("true", "yes"))

    limit = fields.get("packet size limit", "")
    if limit and "not set" not in limit.lower() and "n/a" not in limit.lower():
        meta.snaplen = _to_int(limit)
        # A snaplen below a full Ethernet frame means payload bytes were
        # discarded at capture time. SMTP command reconstruction and
        # certificate extraction may then be impossible -- downstream must
        # report UNKNOWN rather than a false negative.
        if meta.snaplen is not None and meta.snaplen < 1500:
            meta.snaplen_truncated = True

    if meta.duration_seconds is None and meta.first_packet_at and meta.last_packet_at:
        meta.duration_seconds = (meta.last_packet_at - meta.first_packet_at).total_seconds()

    return meta
