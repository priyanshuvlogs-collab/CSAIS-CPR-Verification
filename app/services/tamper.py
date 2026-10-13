"""Tamper-risk scoring.

Combines several independent signals into a 0-100 risk score. These are
*indicators* for a human reviewer, not proof of forgery.
"""
import io
from dataclasses import dataclass, field
from datetime import date, datetime

from PIL import ExifTags, Image
from rapidfuzz import fuzz

from app.services.pdf_utils import pdf_metadata

EDITING_TOOLS = [
    "photoshop", "illustrator", "gimp", "paint.net", "pixelmator", "affinity", "canva",
    "photopea", "snapseed", "lightroom", "inkscape", "coreldraw", "foxit phantompdf",
    "pdfescape", "sejda", "smallpdf", "ilovepdf", "pdffiller", "dochub", "pdf-xchange editor",
    "nitro pro", "acrobat pro", "libreoffice draw", "picsart", "fotor",
]

LOW_MAX = 29
MEDIUM_MAX = 59


@dataclass
class TamperResult:
    score: int = 0
    level: str = "Low"
    reasons: list[dict] = field(default_factory=list)
    name_match: bool | None = None

    def add(self, signal: str, detail: str, points: int):
        self.reasons.append({"signal": signal, "detail": detail, "points": points})


def level_for(score: int) -> str:
    if score <= LOW_MAX:
        return "Low"
    if score <= MEDIUM_MAX:
        return "Medium"
    return "High"


def _editing_tool(value: str | None) -> str | None:
    if not value:
        return None
    lower = value.lower()
    for tool in EDITING_TOOLS:
        if tool in lower:
            return tool
    return None


def _parse_pdf_date(value: str | None) -> datetime | None:
    # PDF dates look like D:20240101120000+00'00'
    if not value:
        return None
    v = value[2:] if value.startswith("D:") else value
    try:
        return datetime.strptime(v[:14], "%Y%m%d%H%M%S")
    except ValueError:
        try:
            return datetime.strptime(v[:8], "%Y%m%d")
        except ValueError:
            return None


# ---------- file forensics ----------

def check_pdf(data: bytes, result: TamperResult):
    try:
        meta = pdf_metadata(data)
    except Exception as exc:  # corrupt PDF is itself suspicious
        result.add("PDF structure", f"PDF could not be parsed ({exc.__class__.__name__})", 20)
        return
    for key in ("producer", "creator"):
        tool = _editing_tool(meta.get(key))
        if tool:
            result.add("PDF metadata", f"PDF {key} is an editing tool: '{meta.get(key)}'", 35)
            break
    created = _parse_pdf_date(meta.get("creationDate"))
    modified = _parse_pdf_date(meta.get("modDate"))
    if created and modified and (modified - created).total_seconds() > 86400:
        result.add(
            "PDF metadata",
            f"PDF modified {modified:%Y-%m-%d} after creation {created:%Y-%m-%d}",
            15,
        )
    if meta.get("eof_markers", 0) > 1:
        result.add(
            "PDF structure",
            f"PDF has {meta['eof_markers']} revisions (incremental saves after original creation)",
            15,
        )


def check_image_exif(data: bytes, result: TamperResult):
    try:
        img = Image.open(io.BytesIO(data))
        exif = img.getexif()
    except Exception:
        return
    software = exif.get(ExifTags.Base.Software) if exif else None
    tool = _editing_tool(software)
    if tool:
        result.add("Image metadata", f"Image was saved by editing software: '{software}'", 30)
    # PNG text chunks can also carry software info
    info_sw = img.info.get("Software") if hasattr(img, "info") else None
    if not tool and _editing_tool(info_sw):
        result.add("Image metadata", f"Image was saved by editing software: '{info_sw}'", 30)


# ---------- content checks ----------

def check_ai(ai: dict | None, result: TamperResult):
    if not ai:
        return
    if ai.get("is_cpr_certificate") is False:
        result.add("AI review", "Document does not appear to be a CPR / BLS / First-Aid certificate", 40)
    likelihood = (ai.get("tamper_likelihood") or "none").lower()
    pts = {"high": 45, "medium": 25, "low": 10}.get(likelihood, 0)
    signs = [s for s in (ai.get("visual_tamper_signs") or []) if s]
    if pts:
        result.add("AI visual review", f"AI rated tampering likelihood '{likelihood}'", pts)
    for sign in signs[:4]:
        result.add("AI visual review", sign, 5)


def check_dates(issue: date | None, expiry: date | None, inferred: bool, result: TamperResult,
                today: date | None = None, validity_years: int = 2):
    today = today or date.today()
    if issue and issue > today:
        result.add("Date sanity", f"Issue date {issue} is in the future", 30)
    if issue and expiry and not inferred:
        if expiry <= issue:
            result.add("Date sanity", f"Expiry {expiry} is not after issue date {issue}", 30)
        else:
            days = (expiry - issue).days
            expected = 365 * validity_years
            if abs(days - expected) > 62:
                result.add(
                    "Date sanity",
                    f"Validity period is {days / 365:.1f} years (CPR cards are normally {validity_years} years)",
                    15,
                )


def check_name(guard_name: str | None, holder_name: str | None, result: TamperResult, threshold: int = 80):
    if not guard_name or not holder_name:
        result.name_match = None
        return
    score = fuzz.token_set_ratio(guard_name.lower(), holder_name.lower())
    result.name_match = score >= threshold
    if not result.name_match:
        result.add("Name check", f"Name on certificate '{holder_name}' does not match submitted name '{guard_name}'", 25)


def check_duplicates(duplicates: list[dict], result: TamperResult):
    """duplicates: [{'id', 'guard_id', 'guard_name', 'match': 'file'|'cert_id'}] from OTHER guards."""
    for dup in duplicates[:3]:
        what = "identical file" if dup["match"] == "file" else f"same certificate number"
        result.add(
            "Duplicate",
            f"{what} already submitted by {dup['guard_name']} (ID {dup['guard_id']}, submission #{dup['id']})",
            40,
        )


def assess(
    data: bytes,
    mime: str,
    ai: dict | None,
    issue_date: date | None,
    expiry_date: date | None,
    expiry_inferred: bool,
    guard_name: str | None,
    holder_name: str | None,
    duplicates: list[dict] | None = None,
    today: date | None = None,
    validity_years: int = 2,
) -> TamperResult:
    result = TamperResult()
    if mime == "application/pdf":
        check_pdf(data, result)
    else:
        check_image_exif(data, result)
    check_ai(ai, result)
    check_dates(issue_date, expiry_date, expiry_inferred, result, today, validity_years)
    check_name(guard_name, holder_name, result)
    check_duplicates(duplicates or [], result)
    result.score = min(100, sum(r["points"] for r in result.reasons))
    result.level = level_for(result.score)
    return result
