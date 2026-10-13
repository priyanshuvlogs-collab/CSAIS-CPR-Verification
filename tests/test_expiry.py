from datetime import date

from app.services.expiry import EXPIRED, EXPIRING, UNKNOWN, VALID, expiry_status, resolve_expiry

TODAY = date(2026, 10, 13)


def test_expired():
    assert expiry_status(date(2026, 10, 12), TODAY).status == EXPIRED


def test_expires_today_is_expiring():
    info = expiry_status(TODAY, TODAY)
    assert info.status == EXPIRING and info.days_left == 0


def test_exactly_six_months_is_expiring():
    assert expiry_status(date(2027, 4, 13), TODAY).status == EXPIRING


def test_just_over_six_months_is_valid():
    assert expiry_status(date(2027, 4, 14), TODAY).status == VALID


def test_unknown():
    assert expiry_status(None, TODAY).status == UNKNOWN


def test_infer_expiry_from_issue():
    assert resolve_expiry(date(2025, 3, 1), None) == (date(2027, 3, 1), True)
    assert resolve_expiry(date(2025, 3, 1), date(2027, 2, 28)) == (date(2027, 2, 28), False)
    assert resolve_expiry(None, None) == (None, False)
