"""Streaming upload to disk with hashing and a hard size ceiling."""

from __future__ import annotations

import hashlib
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from app.config import get_settings

CHUNK_SIZE = 1024 * 1024


class UploadTooLarge(ValueError):
    pass


@dataclass(frozen=True)
class StoredUpload:
    path: Path
    sha256: str
    size_bytes: int


def stream_to_temp(source: BinaryIO, max_bytes: int) -> StoredUpload:
    """Write an upload to a temp file, hashing as we go.

    The hash is computed during the single pass that writes the file, so the
    digest provably covers the exact bytes on disk. The size limit is enforced
    mid-stream -- checking Content-Length would let a lying client fill the
    disk before we noticed.
    """
    settings = get_settings()
    tmp_path = settings.tmp_dir / f"upload-{uuid.uuid4().hex}.part"

    digest = hashlib.sha256()
    total = 0

    try:
        with tmp_path.open("wb") as out:
            while True:
                chunk = source.read(CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise UploadTooLarge(
                        f"Upload exceeds the {max_bytes} byte limit."
                    )
                digest.update(chunk)
                out.write(chunk)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise

    if total == 0:
        tmp_path.unlink(missing_ok=True)
        raise ValueError("Uploaded file is empty.")

    return StoredUpload(path=tmp_path, sha256=digest.hexdigest(), size_bytes=total)


def promote(tmp: StoredUpload, capture_id: str, extension: str) -> Path:
    """Move a validated temp upload into its permanent evidence directory.

    Layout is one directory per capture:
        /data/captures/<capture_id>/original<ext>
        /data/captures/<capture_id>/artifacts/    (tshark/zeek output, slices)

    The stored name is derived from detected content, never from the uploaded
    filename, so no user-controlled string ever becomes a path component.
    """
    settings = get_settings()
    target_dir = settings.captures_dir / capture_id
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / "artifacts").mkdir(exist_ok=True)

    target = target_dir / f"original{extension}"
    shutil.move(str(tmp.path), str(target))
    target.chmod(0o440)  # evidence is read-only once stored
    return target
