from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger, CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint,
    Integer, Numeric, String, UniqueConstraint, func,
)
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base, uuid_text


class PrinterDiscoveryRunRecord(Base):
    __tablename__ = "printer_discovery_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    organisation_id: Mapped[str] = mapped_column(
        ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    participant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    agent_binding_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    agent_job_id: Mapped[str | None] = mapped_column(
        ForeignKey("agent_jobs.job_id", ondelete="SET NULL"), nullable=True, unique=True
    )
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING", index=True)
    requested_by_user_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    printer_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    safe_error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["participant_id", "organisation_id"],
            ["participants.id", "participants.organisation_id"],
            name="fk_printer_discovery_run_participant_organisation",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["agent_binding_id", "organisation_id", "participant_id"],
            ["agent_bindings.id", "agent_bindings.organisation_id", "agent_bindings.participant_id"],
            name="fk_printer_discovery_run_binding_tenant",
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "id", "organisation_id", "participant_id",
            name="uq_printer_discovery_run_id_tenant",
        ),
        CheckConstraint(
            "state IN ('PENDING','RUNNING','COMPLETED','FAILED')",
            name="ck_printer_discovery_run_state",
        ),
        CheckConstraint("printer_count >= 0", name="ck_printer_discovery_run_count"),
    )


class PrinterDiscoveryObservationRecord(Base):
    __tablename__ = "printer_discovery_observations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    organisation_id: Mapped[str] = mapped_column(
        ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    participant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    agent_binding_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    discovery_run_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    agent_printer_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    local_printer_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    display_name_sanitized: Mapped[str] = mapped_column(String(160), nullable=False)
    driver_name_sanitized: Mapped[str | None] = mapped_column(String(160), nullable=True)
    dpi_x: Mapped[int] = mapped_column(Integer, nullable=False)
    dpi_y: Mapped[int] = mapped_column(Integer, nullable=False)
    media_width_mm: Mapped[float] = mapped_column(Numeric(10, 4), nullable=False)
    media_height_mm: Mapped[float] = mapped_column(Numeric(10, 4), nullable=False)
    orientation: Mapped[str] = mapped_column(String(16), nullable=False)
    physical_width_px: Mapped[int] = mapped_column(Integer, nullable=False)
    physical_height_px: Mapped[int] = mapped_column(Integer, nullable=False)
    printable_width_px: Mapped[int] = mapped_column(Integer, nullable=False)
    printable_height_px: Mapped[int] = mapped_column(Integer, nullable=False)
    offset_x_px: Mapped[int] = mapped_column(Integer, nullable=False)
    offset_y_px: Mapped[int] = mapped_column(Integer, nullable=False)
    capability_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    availability_state: Mapped[str] = mapped_column(String(16), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    safe_error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["participant_id", "organisation_id"],
            ["participants.id", "participants.organisation_id"],
            name="fk_printer_observation_participant_organisation",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["agent_binding_id", "organisation_id", "participant_id"],
            ["agent_bindings.id", "agent_bindings.organisation_id", "agent_bindings.participant_id"],
            name="fk_printer_observation_binding_tenant",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["discovery_run_id", "organisation_id", "participant_id"],
            ["printer_discovery_runs.id", "printer_discovery_runs.organisation_id", "printer_discovery_runs.participant_id"],
            name="fk_printer_observation_run_tenant",
            ondelete="CASCADE",
        ),
        UniqueConstraint(
            "discovery_run_id", "agent_printer_id",
            name="uq_printer_observation_run_agent_printer",
        ),
        UniqueConstraint(
            "id", "organisation_id", "participant_id",
            name="uq_printer_observation_id_tenant",
        ),
        CheckConstraint(
            "orientation IN ('PORTRAIT','LANDSCAPE')",
            name="ck_printer_observation_orientation",
        ),
        CheckConstraint(
            "availability_state IN ('AVAILABLE','UNAVAILABLE','ERROR')",
            name="ck_printer_observation_availability",
        ),
        CheckConstraint(
            "dpi_x >= 0 AND dpi_y >= 0 AND physical_width_px >= 0 AND physical_height_px >= 0 "
            "AND printable_width_px >= 0 AND printable_height_px >= 0 "
            "AND offset_x_px >= 0 AND offset_y_px >= 0",
            name="ck_printer_observation_geometry_nonnegative",
        ),
    )


class PrinterProfileRecord(Base):
    __tablename__ = "printer_profiles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    organisation_id: Mapped[str] = mapped_column(
        ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    participant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    agent_binding_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    agent_printer_id: Mapped[str] = mapped_column(String(160), nullable=False)
    local_printer_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    display_name_sanitized: Mapped[str] = mapped_column(String(160), nullable=False)
    driver_name_sanitized: Mapped[str | None] = mapped_column(String(160), nullable=True)
    dpi_x: Mapped[int] = mapped_column(Integer, nullable=False)
    dpi_y: Mapped[int] = mapped_column(Integer, nullable=False)
    media_width_mm: Mapped[float] = mapped_column(Numeric(10, 4), nullable=False)
    media_height_mm: Mapped[float] = mapped_column(Numeric(10, 4), nullable=False)
    orientation: Mapped[str] = mapped_column(String(16), nullable=False)
    physical_width_px: Mapped[int] = mapped_column(Integer, nullable=False)
    physical_height_px: Mapped[int] = mapped_column(Integer, nullable=False)
    printable_width_px: Mapped[int] = mapped_column(Integer, nullable=False)
    printable_height_px: Mapped[int] = mapped_column(Integer, nullable=False)
    offset_x_px: Mapped[int] = mapped_column(Integer, nullable=False)
    offset_y_px: Mapped[int] = mapped_column(Integer, nullable=False)
    capability_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    capability_revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="ACTIVE", index=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
    created_by_user_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["participant_id", "organisation_id"],
            ["participants.id", "participants.organisation_id"],
            name="fk_printer_profile_participant_organisation",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["agent_binding_id", "organisation_id", "participant_id"],
            ["agent_bindings.id", "agent_bindings.organisation_id", "agent_bindings.participant_id"],
            name="fk_printer_profile_binding_tenant",
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "agent_binding_id", "agent_printer_id",
            name="uq_printer_profile_binding_agent_printer",
        ),
        UniqueConstraint(
            "id", "organisation_id", "participant_id",
            name="uq_printer_profile_id_tenant",
        ),
        CheckConstraint(
            "state IN ('ACTIVE','STALE','MISSING','INCOMPATIBLE','DISABLED')",
            name="ck_printer_profile_state",
        ),
        CheckConstraint(
            "orientation IN ('PORTRAIT','LANDSCAPE')",
            name="ck_printer_profile_orientation",
        ),
        CheckConstraint("capability_revision >= 1", name="ck_printer_profile_revision"),
        CheckConstraint(
            "dpi_x >= 0 AND dpi_y >= 0 AND physical_width_px >= 0 AND physical_height_px >= 0 "
            "AND printable_width_px >= 0 AND printable_height_px >= 0 "
            "AND offset_x_px >= 0 AND offset_y_px >= 0",
            name="ck_printer_profile_geometry_nonnegative",
        ),
    )
