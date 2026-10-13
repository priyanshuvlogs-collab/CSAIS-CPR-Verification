"""Runs the full scan pipeline for one submission."""
import logging
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import func, select

from app.config import get_settings
from app.models import Submission
from app.services import extract, tamper
from app.services.expiry import resolve_expiry

log = logging.getLogger(__name__)


def find_duplicates(db, sub: Submission) -> list[dict]:
    """Other guards who submitted the same file or the same certificate number."""
    out, seen = [], set()
    q = select(Submission).where(Submission.id != sub.id, Submission.guard_id != sub.guard_id)
    for other in db.scalars(q.where(Submission.sha256 == sub.sha256)):
        out.append({"id": other.id, "guard_id": other.guard_id, "guard_name": other.guard_name, "match": "file"})
        seen.add(other.id)
    if sub.cert_id and len(sub.cert_id.strip()) >= 4:
        norm = sub.cert_id.strip().lower()
        for other in db.scalars(q.where(func.lower(func.trim(Submission.cert_id)) == norm)):
            if other.id not in seen:
                out.append({"id": other.id, "guard_id": other.guard_id, "guard_name": other.guard_name, "match": "cert_id"})
    return out


def scan_submission(db, sub: Submission, client=None) -> Submission:
    settings = get_settings()
    data = Path(sub.stored_path).read_bytes()

    ai = None
    try:
        ai = extract.extract_fields(data, sub.mime, client=client)
        sub.scan_status = "done"
        sub.scan_error = None
    except extract.AIUnavailable as exc:
        sub.scan_status = "ai_unavailable"
        sub.scan_error = str(exc)
    except Exception as exc:  # network / API / parsing errors
        log.exception("AI extraction failed for submission %s", sub.id)
        sub.scan_status = "error"
        sub.scan_error = f"{exc.__class__.__name__}: {exc}"[:500]

    if ai is not None:
        sub.raw_ai_json = ai
        sub.holder_name = ai.get("holder_name")
        sub.issuer = ai.get("issuer")
        sub.cert_id = ai.get("cert_id")
        sub.course_type = ai.get("course_type")
        sub.ai_confidence = ai.get("confidence")
        if not sub.dates_overridden:
            issue = extract.parse_date(ai.get("issue_date"))
            expiry = extract.parse_date(ai.get("expiry_date"))
            sub.issue_date = issue
            sub.expiry_date, sub.expiry_inferred = resolve_expiry(issue, expiry, settings.default_validity_years)

    apply_tamper(db, sub, data)
    sub.scanned_at = datetime.now(timezone.utc)
    db.commit()
    return sub


def apply_tamper(db, sub: Submission, data: bytes | None = None):
    settings = get_settings()
    data = data if data is not None else Path(sub.stored_path).read_bytes()
    result = tamper.assess(
        data=data,
        mime=sub.mime,
        ai=sub.raw_ai_json,
        issue_date=sub.issue_date,
        expiry_date=sub.expiry_date,
        expiry_inferred=sub.expiry_inferred,
        guard_name=sub.guard_name,
        holder_name=sub.holder_name,
        duplicates=find_duplicates(db, sub),
        validity_years=settings.default_validity_years,
    )
    sub.tamper_score = result.score
    sub.tamper_level = result.level
    sub.tamper_reasons = result.reasons
    sub.name_match = result.name_match


def scan_by_id(submission_id: int, client=None):
    """Entry point for background tasks (opens its own DB session)."""
    from app.db import SessionLocal

    db = SessionLocal()
    try:
        sub = db.get(Submission, submission_id)
        if sub:
            scan_submission(db, sub, client=client)
    finally:
        db.close()
