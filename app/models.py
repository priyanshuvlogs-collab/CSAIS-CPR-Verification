from datetime import date, datetime, timezone

from sqlalchemy import JSON, Boolean, Date, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


def _now():
    return datetime.now(timezone.utc)


class Submission(Base):
    __tablename__ = "submissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # Entered by the guard
    guard_name: Mapped[str] = mapped_column(String(200))
    guard_id: Mapped[str] = mapped_column(String(100), index=True)
    email: Mapped[str | None] = mapped_column(String(200), nullable=True)
    site: Mapped[str | None] = mapped_column(String(200), nullable=True)

    # File
    original_filename: Mapped[str] = mapped_column(String(300))
    stored_path: Mapped[str] = mapped_column(String(500))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    mime: Mapped[str] = mapped_column(String(50))
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    # Scan
    scan_status: Mapped[str] = mapped_column(String(30), default="pending")  # pending|done|ai_unavailable|error
    scan_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Extracted fields
    holder_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    issuer: Mapped[str | None] = mapped_column(String(200), nullable=True)
    cert_id: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)
    course_type: Mapped[str | None] = mapped_column(String(200), nullable=True)
    issue_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    expiry_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    expiry_inferred: Mapped[bool] = mapped_column(Boolean, default=False)
    ai_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    raw_ai_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # Tamper
    tamper_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tamper_level: Mapped[str | None] = mapped_column(String(10), nullable=True)
    tamper_reasons: Mapped[list | None] = mapped_column(JSON, nullable=True)
    name_match: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    # Admin
    admin_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewed: Mapped[bool] = mapped_column(Boolean, default=False)
    dates_overridden: Mapped[bool] = mapped_column(Boolean, default=False)
