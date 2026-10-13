import io

from openpyxl import load_workbook

from app.services import extract
from tests.conftest import make_cert_jpeg, make_cert_pdf


def upload(client, data, filename="cert.jpg", name="John Smith", gid="G-1", site="Mall"):
    return client.post("/upload", data={"guard_name": name, "guard_id": gid, "site": site, "email": ""},
                       files={"certificate": (filename, data)})


def test_upload_form_renders(client):
    r = client.get("/")
    assert r.status_code == 200 and "Upload your CPR certificate" in r.text


def test_upload_and_scan_jpeg(client, fake_ai, admin):
    r = upload(client, make_cert_jpeg())
    assert r.status_code == 200 and "Thank you" in r.text
    assert fake_ai["last_mime"] == "image/jpeg"
    r = client.get("/admin")
    assert "John Smith" in r.text and "American Heart Association" in r.text


def test_pdf_sent_as_pdf_and_previewed(client, fake_ai, admin):
    upload(client, make_cert_pdf(), "cert.pdf")
    assert fake_ai["last_mime"] == "application/pdf"
    r = client.get("/admin/submissions/1/preview.png")
    assert r.status_code == 200 and r.content.startswith(b"\x89PNG")


def test_rejects_bad_file_type(client, fake_ai):
    r = upload(client, b"MZ\x90\x00 not a cert", "evil.exe")
    assert r.status_code == 400 and "Unsupported file type" in r.text


def test_rejects_disguised_extension(client, fake_ai):
    r = upload(client, b"<html><script>alert(1)</script>", "cert.jpg")
    assert r.status_code == 400


def test_rejects_oversize(client, fake_ai, monkeypatch):
    from app.config import get_settings

    monkeypatch.setattr(get_settings(), "max_upload_mb", 0)
    r = upload(client, make_cert_jpeg())
    assert r.status_code == 400 and "too large" in r.text


def test_admin_requires_login(client):
    for path in ["/admin", "/admin/submissions/1", "/admin/submissions/1/file", "/admin/reports/export.csv"]:
        r = client.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/admin/login", path


def test_wrong_password_and_lockout(client):
    for _ in range(5):
        assert client.post("/admin/login", data={"password": "nope"}).status_code == 401
    assert client.post("/admin/login", data={"password": "test-pass"}).status_code == 429


def test_default_password_disables_login(client, monkeypatch):
    from app.config import get_settings

    monkeypatch.setattr(get_settings(), "admin_password", "change-me")
    r = client.post("/admin/login", data={"password": "change-me"})
    assert r.status_code == 503


def test_without_api_key_forensics_still_run(client, admin):
    upload(client, make_cert_jpeg(exif_software="GIMP 2.10"))
    from app.db import SessionLocal
    from app.models import Submission

    with SessionLocal() as db:
        sub = db.query(Submission).one()
        assert sub.scan_status == "ai_unavailable"
        assert sub.tamper_level in ("Medium", "High")
    r = client.get("/admin")
    assert "ANTHROPIC_API_KEY is not set" in r.text


def test_ai_error_is_recorded(client, admin, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("rate limited")

    monkeypatch.setattr(extract, "extract_fields", boom)
    upload(client, make_cert_jpeg())
    from app.db import SessionLocal
    from app.models import Submission

    with SessionLocal() as db:
        sub = db.query(Submission).one()
        assert sub.scan_status == "error" and "rate limited" in sub.scan_error


def test_duplicate_file_from_other_guard(client, fake_ai, admin):
    data = make_cert_jpeg()
    upload(client, data, gid="G-1")
    upload(client, data, name="Other Person", gid="G-2")
    from app.db import SessionLocal
    from app.models import Submission

    with SessionLocal() as db:
        second = db.query(Submission).order_by(Submission.id.desc()).first()
        assert any(r["signal"] == "Duplicate" for r in second.tamper_reasons)
        assert second.tamper_level == "High"


def test_filters_and_exports(client, fake_ai, admin):
    upload(client, make_cert_jpeg(), gid="G-1")
    fake_ai["response"] = {**fake_ai["response"], "holder_name": "Jane Doe", "expiry_date": "2020-01-01",
                           "issue_date": "2018-01-01", "cert_id": "X-999"}
    upload(client, make_cert_jpeg("Jane Doe"), name="Jane Doe", gid="G-2", site="Airport")

    r = client.get("/admin", params={"status": "Expired"})
    assert "Jane Doe" in r.text and "G-1" not in r.text
    r = client.get("/admin", params={"site": "Mall"})
    assert "G-1" in r.text and "Jane Doe" not in r.text

    r = client.get("/admin/reports/export.csv")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    text = r.content.decode("utf-8-sig")
    assert "Jane Doe" in text and "Expired" in text

    r = client.get("/admin/reports/export.xlsx", params={"status": "Expired"})
    wb = load_workbook(io.BytesIO(r.content))
    rows = list(wb["CPR Certificates"].values)
    assert len(rows) == 2 and rows[1][1] == "Jane Doe"

    r = client.get("/admin/reports/export.pdf")
    assert r.status_code == 200 and r.content.startswith(b"%PDF")

    assert client.get("/admin/reports/export.exe").status_code == 404


def test_detail_update_and_csrf(client, fake_ai, admin):
    upload(client, make_cert_jpeg())
    r = client.get("/admin/submissions/1")
    assert r.status_code == 200 and "Tamper risk indicators" in r.text
    assert client.get("/admin/submissions/1/file").content[:3] == b"\xff\xd8\xff"

    # missing CSRF token rejected
    r = client.post("/admin/submissions/1/update", data={"admin_notes": "x"})
    assert r.status_code == 400

    import re
    token = re.search(r'name="csrf" value="([^"]+)"', client.get("/admin/submissions/1").text).group(1)
    r = client.post("/admin/submissions/1/update", data={
        "csrf": token, "issue_date": "2025-01-10", "expiry_date": "2026-11-01", "admin_notes": "Called AHA",
        "reviewed": "1"}, follow_redirects=False)
    assert r.status_code == 303
    from app.db import SessionLocal
    from app.models import Submission

    with SessionLocal() as db:
        sub = db.get(Submission, 1)
        assert sub.reviewed and sub.admin_notes == "Called AHA" and sub.dates_overridden
        assert str(sub.expiry_date) == "2026-11-01" and not sub.expiry_inferred

    # rescan keeps admin-overridden dates
    r = client.post("/admin/submissions/1/rescan", data={"csrf": token}, follow_redirects=False)
    assert r.status_code == 303
    with SessionLocal() as db:
        assert str(db.get(Submission, 1).expiry_date) == "2026-11-01"

    r = client.post("/admin/submissions/1/delete", data={"csrf": token}, follow_redirects=False)
    assert r.status_code == 303
    assert client.get("/admin/submissions/1").status_code == 404


def _fake_claude(captured, stop_reason="end_turn", text='{"holder_name": "A"}'):
    from types import SimpleNamespace as NS

    class Messages:
        def create(self, **kw):
            captured.update(kw)
            return NS(stop_reason=stop_reason, stop_details=NS(explanation="policy") if stop_reason == "refusal" else None,
                      content=[NS(type="text", text=text)])

    return NS(beta=NS(messages=Messages()))


def test_extract_fields_request_shape():
    """The real extractor sends the file + a JSON schema to Claude, with refusal fallbacks on."""
    captured = {}
    out = extract.extract_fields(b"%PDF-1.7", "application/pdf", client=_fake_claude(captured))
    assert out == {"holder_name": "A"}
    assert captured["model"] == "claude-opus-5-5"
    assert captured["output_config"]["format"]["type"] == "json_schema"
    assert captured["fallbacks"] == "default"
    block = captured["messages"][0]["content"][0]
    assert block["type"] == "document" and block["source"]["media_type"] == "application/pdf"

    extract.extract_fields(b"\xff\xd8\xff", "image/jpeg", client=_fake_claude(captured))
    block = captured["messages"][0]["content"][0]
    assert block["type"] == "image" and block["source"]["media_type"] == "image/jpeg"


def test_extract_fields_refusal():
    import pytest

    with pytest.raises(extract.AIRefused):
        extract.extract_fields(b"\xff\xd8\xff", "image/jpeg", client=_fake_claude({}, stop_reason="refusal"))


def test_sync_scan_mode_and_batched_rescan(client, fake_ai, admin, monkeypatch):
    import re

    from app.config import get_settings
    from app.db import SessionLocal
    from app.models import Submission, SubmissionFile

    monkeypatch.setattr(get_settings(), "scan_mode", "sync")
    calls = []
    monkeypatch.setattr("app.services.scanner.scan_by_id", lambda *a, **k: calls.append(a))
    upload(client, make_cert_jpeg(), gid="G-1")
    upload(client, make_cert_pdf(), "c.pdf", gid="G-2")
    assert calls == []  # scanned in-request, not as a background task
    with SessionLocal() as db:
        assert all(s.scan_status == "done" for s in db.query(Submission))
        assert db.query(SubmissionFile).count() == 2

    token = re.search(r'name="csrf" value="([^"]+)"', client.get("/admin").text).group(1)
    r = client.post("/admin/rescan-all", data={"csrf": token}, follow_redirects=False)
    assert r.headers["location"] == "/admin?rescanned=2&remaining=0"
    assert "Re-scanned 2 certificate(s)" in client.get(r.headers["location"]).text

    # deleting a submission removes its stored file too
    client.post("/admin/submissions/1/delete", data={"csrf": token})
    with SessionLocal() as db:
        assert db.query(SubmissionFile).count() == 1


def test_export_links_keep_only_filters(client, admin):
    r = client.get("/admin", params={"status": "Expired", "rescanned": 3})
    assert "export.csv?status=Expired&quot;" not in r.text
    assert 'href="/admin/reports/export.csv?status=Expired"' in r.text


def test_healthz(client):
    assert client.get("/healthz").json() == {"ok": True}
