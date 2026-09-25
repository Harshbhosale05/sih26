import uuid

from sqlalchemy import BigInteger, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class Finding(Base):
    """A security finding with the evidence that proves it.

    Three fields carry the product's core discipline:

      * `verdict` is PASS / FAIL / **UNKNOWN**. A capture that cannot support a
        conclusion produces UNKNOWN, never an optimistic PASS.
      * `detection_method` is `deterministic` or `ml`. Anything computable is
        computed; ML never produces a verdict, only context.
      * `wireshark_filter` lets an analyst verify the finding independently in
        ten seconds. A finding nobody can check is an assertion, not evidence.
    """

    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_capture_severity", "capture_id", "severity"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    capture_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("captures.id", ondelete="CASCADE"), index=True
    )
    ref: Mapped[str] = mapped_column(String(32))

    # Null for server-level or capture-level findings (e.g. cross-session
    # stripping is a property of the server, evidenced by specific sessions).
    session_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("email_sessions.id", ondelete="CASCADE"), nullable=True
    )
    session_ref: Mapped[str | None] = mapped_column(String(32), nullable=True)

    category: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    severity_rank: Mapped[int] = mapped_column(Integer)
    verdict: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[float] = mapped_column(Float)
    detection_method: Mapped[str] = mapped_column(String(32))

    title: Mapped[str] = mapped_column(String(256))
    description: Mapped[str] = mapped_column(Text)
    rationale: Mapped[str] = mapped_column(Text)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Full evidence chain: server, frames, observed values, related sessions.
    evidence: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    evidence_frames: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    wireshark_filter: Mapped[str | None] = mapped_column(Text, nullable=True)
    standard_refs: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    affected_sessions: Mapped[int] = mapped_column(Integer, default=1)
    first_frame: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    last_frame: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
