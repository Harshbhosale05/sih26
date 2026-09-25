import uuid

from sqlalchemy import BigInteger, Boolean, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class EmailSession(Base):
    """A reconstructed email session and its encryption lifecycle.

    `encryption_state` is the central fact of the whole product -- nearly every
    finding downstream is a statement about it. `state_transitions` keeps the
    frame-by-frame path that produced it, which is what the timeline renders
    and what makes the verdict auditable rather than asserted.
    """

    __tablename__ = "email_sessions"
    __table_args__ = (
        Index("ix_sessions_capture_protocol", "capture_id", "protocol"),
        Index("ix_sessions_server", "capture_id", "server_ip", "server_port"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    capture_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("captures.id", ondelete="CASCADE"), index=True
    )
    ref: Mapped[str] = mapped_column(String(32))
    stream_index: Mapped[int] = mapped_column(Integer)

    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    detection_method: Mapped[str] = mapped_column(String(48))

    client_ip: Mapped[str] = mapped_column(String(45))
    client_port: Mapped[int] = mapped_column(Integer)
    server_ip: Mapped[str] = mapped_column(String(45))
    server_port: Mapped[int] = mapped_column(Integer)
    server_banner: Mapped[str | None] = mapped_column(Text, nullable=True)

    encryption_state: Mapped[str] = mapped_column(String(48), index=True)
    state_transitions: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    events: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    upgrade_advertised: Mapped[bool] = mapped_column(Boolean, default=False)
    upgrade_advertised_mangled: Mapped[bool] = mapped_column(Boolean, default=False)
    upgrade_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    upgrade_succeeded: Mapped[bool] = mapped_column(Boolean, default=False)
    tls_established: Mapped[bool] = mapped_column(Boolean, default=False)
    cleartext_auth_observed: Mapped[bool] = mapped_column(Boolean, default=False)
    cleartext_mail_observed: Mapped[bool] = mapped_column(Boolean, default=False)

    # --- Negotiated cryptography -----------------------------------------
    # Scalars are stored inline rather than in a joined table: the relationship
    # is strictly 1:1, and Phase 5's per-server fingerprinting aggregates over
    # exactly these columns, so avoiding the join keeps that work simple.
    # `tls_detail` carries the full parse for the UI and reports.
    tls_version: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    tls_cipher_suite: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tls_cipher_code: Mapped[str | None] = mapped_column(String(8), nullable=True)
    tls_key_exchange: Mapped[str | None] = mapped_column(String(16), nullable=True)
    tls_authentication: Mapped[str | None] = mapped_column(String(16), nullable=True)
    tls_forward_secrecy: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    tls_aead: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    tls_selected_group: Mapped[str | None] = mapped_column(String(32), nullable=True)
    tls_sni: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tls_sni_status: Mapped[str | None] = mapped_column(String(24), nullable=True)
    tls_ja3: Mapped[str | None] = mapped_column(String(32), nullable=True)
    tls_ja3s: Mapped[str | None] = mapped_column(String(32), nullable=True)
    tls_ja4: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    tls_ja4s: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tls_pqc_offered: Mapped[bool] = mapped_column(Boolean, default=False)
    tls_pqc_selected: Mapped[bool] = mapped_column(Boolean, default=False)
    tls_handshake_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    # Normally False on TLS 1.3: the Certificate message is encrypted. That is
    # a property of the evidence, not a fault of the server.
    cert_observable: Mapped[bool] = mapped_column(Boolean, default=False)
    cert_unobservable_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    tls_detail: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # --- Behavioural intelligence (Phase 5) -------------------------------
    # Deterministic deviation from the server's own established profile, plus
    # the ML anomaly score. Kept separate on purpose: the first is a fact about
    # what differed, the second is multivariate context. Neither is a verdict.
    baseline_deviation_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    baseline_deviations: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    anomaly_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    anomaly_attribution: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    is_anomalous: Mapped[bool] = mapped_column(Boolean, default=False)

    # Evidence quality. These gate every verdict made about this session.
    has_gaps: Mapped[bool] = mapped_column(Boolean, default=False)
    session_complete: Mapped[bool] = mapped_column(Boolean, default=True)
    is_indeterminate: Mapped[bool] = mapped_column(Boolean, default=False)

    first_frame: Mapped[int] = mapped_column(BigInteger)
    last_frame: Mapped[int] = mapped_column(BigInteger)
    start_time: Mapped[float] = mapped_column(Float)
    end_time: Mapped[float] = mapped_column(Float)

    @property
    def wireshark_filter(self) -> str:
        """Display filter an analyst can paste straight into Wireshark.

        Frame bounds are included alongside the stream index so the filter also
        works on a merged or filtered capture where stream numbering differs.
        """
        return (
            f"tcp.stream == {self.stream_index} && "
            f"frame.number >= {self.first_frame} && frame.number <= {self.last_frame}"
        )
