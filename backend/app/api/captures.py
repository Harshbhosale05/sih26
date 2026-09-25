from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.models import Capture, CaptureStatus
from app.pcap import (
    InvalidCaptureFile,
    UploadTooLarge,
    detect_container,
    extract_metadata,
    promote,
    safe_extension,
    stream_to_temp,
)
from app.schemas import CaptureList, CaptureSummary, EvidenceManifest

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/captures", tags=["captures"])


@router.post(
    "",
    response_model=EvidenceManifest,
    status_code=status.HTTP_201_CREATED,
    summary="Upload a capture and build its evidence manifest",
)
def upload_capture(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> Capture:
    settings = get_settings()

    # 1. Stream to a temp file, hashing in the same pass, enforcing the ceiling.
    try:
        stored = stream_to_temp(file.file, settings.max_upload_bytes)
    except UploadTooLarge as exc:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    # 2. Decide what the file is from its bytes, not its name or content-type.
    try:
        container = detect_container(stored.path)
    except InvalidCaptureFile as exc:
        stored.path.unlink(missing_ok=True)
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, str(exc)) from exc

    # 3. Deduplicate on content hash. Re-uploading identical evidence must not
    #    create a second manifest -- the sha256 *is* the identity of the
    #    evidence, so we return the existing manifest instead.
    existing = db.scalar(select(Capture).where(Capture.sha256 == stored.sha256))
    if existing is not None:
        stored.path.unlink(missing_ok=True)
        logger.info("duplicate upload of %s, returning %s", stored.sha256[:12], existing.ref)
        return existing

    capture = Capture(
        original_filename=file.filename or "unnamed",
        stored_path="",
        sha256=stored.sha256,
        size_bytes=stored.size_bytes,
        container_format=container.container_format,
        is_compressed=container.is_compressed,
        status=CaptureStatus.UPLOADED,
    )
    db.add(capture)
    db.flush()  # assigns id and ref_number

    # 4. Move into the permanent evidence directory.
    final_path = promote(stored, capture.id, safe_extension(capture.original_filename, container))
    capture.stored_path = str(final_path)

    # 5. Container-level facts. A capture that capinfos cannot fully describe is
    #    still valid input -- we record what is knowable and leave the rest None.
    try:
        meta = extract_metadata(final_path)
        capture.file_encapsulation = meta.file_encapsulation
        capture.packet_count = meta.packet_count
        capture.data_bytes = meta.data_bytes
        capture.first_packet_at = meta.first_packet_at
        capture.last_packet_at = meta.last_packet_at
        capture.duration_seconds = meta.duration_seconds
        capture.snaplen = meta.snaplen
        capture.snaplen_truncated = meta.snaplen_truncated
        capture.interface_count = meta.interface_count
        capture.strict_time_order = meta.strict_time_order
        capture.raw_metadata = meta.raw
        capture.status = CaptureStatus.VALIDATED
    except Exception as exc:  # noqa: BLE001 - surface, never crash the upload
        logger.exception("metadata extraction failed for %s", capture.id)
        capture.status = CaptureStatus.FAILED
        capture.error_message = f"Metadata extraction failed: {exc}"

    db.commit()
    db.refresh(capture)
    return capture


@router.get("", response_model=CaptureList, summary="List uploaded captures")
def list_captures(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> CaptureList:
    total = db.scalar(select(func.count()).select_from(Capture)) or 0
    rows = db.scalars(
        select(Capture).order_by(Capture.uploaded_at.desc()).limit(limit).offset(offset)
    ).all()
    return CaptureList(
        total=total,
        items=[CaptureSummary.model_validate(r) for r in rows],
    )


@router.get(
    "/{capture_id}",
    response_model=EvidenceManifest,
    summary="Fetch a capture's evidence manifest",
)
def get_capture(capture_id: str, db: Session = Depends(get_db)) -> Capture:
    capture = db.get(Capture, capture_id)
    if capture is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Capture not found")
    return capture
