import io
from datetime import date

import pytest
from PIL import Image, ImageDraw


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("ADMIN_PASSWORD", "test-pass")
    monkeypatch.setenv("SECRET_KEY", "test-secret")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    from app.config import get_settings

    get_settings.cache_clear()
    from app import db

    db.init_engine()
    from app import main

    main._failed_logins.clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def fake_ai(monkeypatch):
    """Replace the Claude call with a configurable fake."""
    state = {"response": {
        "is_cpr_certificate": True, "holder_name": "John Smith", "issuer": "American Heart Association",
        "cert_id": "AHA-123456", "course_type": "BLS Provider", "issue_date": "2025-01-10",
        "expiry_date": "2027-01-31", "visual_tamper_signs": [], "tamper_likelihood": "none", "confidence": 0.95,
    }}

    def fake(data, mime, client=None):
        state["last_mime"] = mime
        return dict(state["response"])

    from app.services import extract

    monkeypatch.setattr(extract, "extract_fields", fake)
    return state


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture
def admin(client):
    r = client.post("/admin/login", data={"password": "test-pass"}, follow_redirects=False)
    assert r.status_code == 303
    return client


def make_cert_jpeg(name="John Smith", exif_software=None) -> bytes:
    img = Image.new("RGB", (900, 600), "white")
    d = ImageDraw.Draw(img)
    d.rectangle((20, 20, 880, 580), outline="navy", width=6)
    d.text((300, 80), "CERTIFICATE OF COMPLETION", fill="black")
    d.text((300, 160), "CPR / AED / BLS Provider", fill="black")
    d.text((300, 260), name, fill="black")
    d.text((300, 360), "Issued 2025-01-10   Renew by 2027-01-31", fill="black")
    buf = io.BytesIO()
    exif = Image.Exif()
    if exif_software:
        exif[0x0131] = exif_software
    img.save(buf, "JPEG", quality=92, exif=exif)
    return buf.getvalue()


def make_cert_pdf(producer=None, mod_date=None, incremental=False) -> bytes:
    import pymupdf

    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 100), "CPR Certificate - John Smith", fontsize=18)
    page.insert_text((72, 140), "Issued 2025-01-10  Expires 2027-01-31", fontsize=12)
    meta = {"creationDate": "D:20250110120000", "modDate": mod_date or "D:20250110120000"}
    if producer:
        meta["producer"] = producer
    doc.set_metadata(meta)
    data = doc.tobytes()
    doc.close()
    if incremental:
        data = data + b"\n1 0 obj\n<<>>\nendobj\n%%EOF\n"
    return data


TODAY = date(2026, 10, 13)
