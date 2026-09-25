import enum
import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Enum, Integer, Sequence, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class CaptureStatus(str, enum.Enum):
    UPLOADED = "uploaded"
    VALIDATED = "validated"
    ANALYZING = "analyzing"
    COMPLETE = "complete"
    FAILED = "failed"


capture_ref_seq = Sequence("capture_ref_seq", start=1)


class Capture(Base):
    """The Evidence Manifest.

    This row is the root of the chain of custody. Every finding the platform
    ever emits must be traceable back to exactly one Capture, and the sha256
    here is what proves the analysed bytes are the uploaded bytes.

    Nothing in this table is ever mutated after analysis completes except
    `status` -- treat the evidence fields as write-once.
    """

    __tablename__ = "captures"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    # Human-facing identifier (CAP-0001). Sequence-backed so it is stable and
    # never reused, unlike a count(*)-derived number.
    ref_number: Mapped[int] = mapped_column(
        BigInteger, capture_ref_seq, server_default=capture_ref_seq.next_value(), unique=True
    )

    # --- Provenance -------------------------------------------------------
    original_filename: Mapped[str] = mapped_column(String(512))
    stored_path: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    uploaded_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # --- Container facts --------------------------------------------------
    container_format: Mapped[str | None] = mapped_column(String(32), nullable=True)
    is_compressed: Mapped[bool] = mapped_column(default=False)
    file_encapsulation: Mapped[str | None] = mapped_column(String(128), nullable=True)
    packet_count: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    data_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    first_packet_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_packet_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    duration_seconds: Mapped[float | None] = mapped_column(nullable=True)
    snaplen: Mapped[int | None] = mapped_column(Integer, nullable=True)
    interface_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # --- Evidence quality -------------------------------------------------
    # `snaplen_truncated` means packets were cut short at capture time, so
    # payload-dependent analysis (SMTP command reconstruction, certificate
    # extraction) may be structurally impossible. This drives UNKNOWN verdicts
    # downstream rather than false negatives, so it is recorded up front.
    snaplen_truncated: Mapped[bool] = mapped_column(default=False)
    strict_time_order: Mapped[bool | None] = mapped_column(nullable=True)

    # Raw capinfos key/values, kept verbatim for forensic reproducibility.
    raw_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    status: Mapped[CaptureStatus] = mapped_column(
        Enum(CaptureStatus, name="capture_status", values_callable=lambda e: [m.value for m in e]),
        default=CaptureStatus.UPLOADED,
        index=True,
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    @property
    def ref(self) -> str:
        return f"CAP-{self.ref_number:04d}"
