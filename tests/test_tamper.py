from datetime import date

from app.services import tamper
from tests.conftest import TODAY, make_cert_jpeg, make_cert_pdf

GOOD_AI = {"is_cpr_certificate": True, "visual_tamper_signs": [], "tamper_likelihood": "none"}


def run(data, mime, **kw):
    args = dict(ai=GOOD_AI, issue_date=date(2025, 1, 10), expiry_date=date(2027, 1, 10), expiry_inferred=False,
                guard_name="John Smith", holder_name="John Smith", today=TODAY)
    args.update(kw)
    return tamper.assess(data, mime, **args)


def test_clean_jpeg_is_low():
    r = run(make_cert_jpeg(), "image/jpeg")
    assert r.level == "Low", r.reasons
    assert r.score == 0, r.reasons
    assert r.name_match is True


def test_photoshop_exif_flagged():
    r = run(make_cert_jpeg(exif_software="Adobe Photoshop 25.0"), "image/jpeg")
    assert any(x["signal"] == "Image metadata" for x in r.reasons)
    assert r.score >= 30


def test_clean_pdf_is_low():
    r = run(make_cert_pdf(), "application/pdf")
    assert r.score == 0, r.reasons


def test_edited_pdf_flagged_high():
    data = make_cert_pdf(producer="Adobe Photoshop", mod_date="D:20260901120000", incremental=True)
    r = run(data, "application/pdf")
    signals = [x["detail"] for x in r.reasons]
    assert any("editing tool" in s for s in signals)
    assert any("modified" in s for s in signals)
    assert any("revisions" in s for s in signals)
    assert r.level == "High"


def test_date_sanity():
    r = run(make_cert_pdf(), "application/pdf", issue_date=date(2025, 1, 10), expiry_date=date(2029, 1, 10))
    assert any("Validity period" in x["detail"] for x in r.reasons)
    r = run(make_cert_pdf(), "application/pdf", issue_date=date(2025, 1, 10), expiry_date=date(2024, 1, 10))
    assert any("not after issue" in x["detail"] for x in r.reasons)
    r = run(make_cert_pdf(), "application/pdf", issue_date=date(2027, 1, 10), expiry_date=date(2029, 1, 10))
    assert any("future" in x["detail"] for x in r.reasons)


def test_inferred_expiry_skips_validity_check():
    r = run(make_cert_pdf(), "application/pdf", expiry_date=date(2027, 1, 10), expiry_inferred=True)
    assert r.score == 0


def test_name_mismatch():
    r = run(make_cert_pdf(), "application/pdf", holder_name="Maria Gonzalez")
    assert r.name_match is False
    assert any(x["signal"] == "Name check" for x in r.reasons)


def test_name_match_tolerates_order_and_middle_name():
    r = run(make_cert_pdf(), "application/pdf", guard_name="john smith", holder_name="Smith, John A.")
    assert r.name_match is True


def test_ai_signals_and_duplicate():
    ai = {"is_cpr_certificate": True, "tamper_likelihood": "high",
          "visual_tamper_signs": ["Expiry year uses a different font"]}
    dups = [{"id": 1, "guard_id": "G-9", "guard_name": "Other Guard", "match": "file"}]
    r = run(make_cert_pdf(), "application/pdf", ai=ai, duplicates=dups)
    assert r.level == "High"
    assert any("different font" in x["detail"] for x in r.reasons)
    assert any(x["signal"] == "Duplicate" for x in r.reasons)
    assert r.score <= 100


def test_not_a_cpr_certificate():
    r = run(make_cert_pdf(), "application/pdf", ai={**GOOD_AI, "is_cpr_certificate": False})
    assert r.score >= 40
