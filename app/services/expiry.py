"""Certificate expiry status calculation."""
from dataclasses import dataclass
from datetime import date

from dateutil.relativedelta import relativedelta

EXPIRED = "Expired"
EXPIRING = "Expiring Soon"
VALID = "Valid"
UNKNOWN = "Unknown"

STATUSES = [EXPIRED, EXPIRING, VALID, UNKNOWN]


@dataclass
class ExpiryInfo:
    expiry_date: date | None
    inferred: bool
    status: str
    days_left: int | None


def resolve_expiry(issue_date: date | None, expiry_date: date | None, validity_years: int = 2) -> tuple[date | None, bool]:
    """Return (expiry_date, inferred). Infers expiry from issue date when missing."""
    if expiry_date:
        return expiry_date, False
    if issue_date:
        return issue_date + relativedelta(years=validity_years), True
    return None, False


def expiry_status(expiry_date: date | None, today: date | None = None, warning_months: int = 6) -> ExpiryInfo:
    today = today or date.today()
    if expiry_date is None:
        return ExpiryInfo(None, False, UNKNOWN, None)
    days_left = (expiry_date - today).days
    if expiry_date < today:
        status = EXPIRED
    elif expiry_date <= today + relativedelta(months=warning_months):
        status = EXPIRING
    else:
        status = VALID
    return ExpiryInfo(expiry_date, False, status, days_left)


def status_for(submission, today: date | None = None, warning_months: int = 6) -> ExpiryInfo:
    info = expiry_status(submission.expiry_date, today, warning_months)
    info.inferred = bool(submission.expiry_inferred)
    return info
