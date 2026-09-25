from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.capture import CaptureStatus


class EvidenceManifest(BaseModel):
    """What we can prove about a capture before any analysis runs.

    This is the root of the chain of custody shown in every report.
    """

    model_config = ConfigDict(from_attributes=True)

    capture_id: str = Field(validation_alias="id")
    ref: str
    original_filename: str
    sha256: str
    size_bytes: int
    container_format: str | None
    is_compressed: bool
    file_encapsulation: str | None
    packet_count: int | None
    data_bytes: int | None
    first_packet_at: datetime | None
    last_packet_at: datetime | None
    duration_seconds: float | None
    snaplen: int | None
    snaplen_truncated: bool
    strict_time_order: bool | None
    interface_count: int | None
    uploaded_at: datetime
    status: CaptureStatus
    error_message: str | None


class CaptureSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    capture_id: str = Field(validation_alias="id")
    ref: str
    original_filename: str
    sha256: str
    size_bytes: int
    packet_count: int | None
    first_packet_at: datetime | None
    last_packet_at: datetime | None
    uploaded_at: datetime
    status: CaptureStatus


class CaptureList(BaseModel):
    total: int
    items: list[CaptureSummary]
