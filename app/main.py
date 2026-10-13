import hashlib
import hmac
import secrets
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import date
from pathlib import Path

from fastapi import BackgroundTasks, Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from starlette.middleware.sessions import SessionMiddleware

from app.config import get_settings
from app.db import get_db, init_engine
from app.models import Submission
from app.services import pdf_utils, reports, scanner
from app.services.expiry import EXPIRED, EXPIRING, STATUSES, UNKNOWN, VALID, resolve_expiry, status_for
from app.services.extract import parse_date

BASE_DIR = Path(__file__).parent
MAGIC = {b"\xff\xd8\xff": ("image/jpeg", ".jpg"), b"\x89PNG\r\n\x1a\n": ("image/png", ".png"), b"%PDF-": ("application/pdf", ".pdf")}


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_engine()
    yield


settings = get_settings()
app = FastAPI(title="CPR Certificate Verification Portal", lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, same_site="lax", https_only=False,
                   max_age=8 * 3600)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    return response


def sniff_type(head: bytes):
    for magic, info in MAGIC.items():
        if head.startswith(magic):
            return info
    return None


# ------------------------------------------------------------------ auth

_failed_logins: dict[str, list[float]] = defaultdict(list)
MAX_FAILS, LOCK_SECONDS = 5, 15 * 60


class NotAuthenticated(Exception):
    pass


@app.exception_handler(NotAuthenticated)
async def _redirect_login(request: Request, exc: NotAuthenticated):
    return RedirectResponse("/admin/login", status_code=303)


def require_admin(request: Request):
    if not request.session.get("admin"):
        raise NotAuthenticated()
    return True


def csrf_token(request: Request) -> str:
    tok = request.session.get("csrf")
    if not tok:
        tok = request.session["csrf"] = secrets.token_urlsafe(24)
    return tok


def check_csrf(request: Request, token: str):
    if not token or not hmac.compare_digest(token, request.session.get("csrf", "")):
        raise HTTPException(status_code=400, detail="Invalid form token, please reload the page")


templates.env.globals["csrf_token"] = csrf_token


@app.get("/admin/login")
def login_form(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})


@app.post("/admin/login")
def login(request: Request, password: str = Form(...)):
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    _failed_logins[ip] = [t for t in _failed_logins[ip] if now - t < LOCK_SECONDS]
    if len(_failed_logins[ip]) >= MAX_FAILS:
        return templates.TemplateResponse(request, "login.html",
                                          {"error": "Too many failed attempts. Try again in 15 minutes."},
                                          status_code=429)
    configured = get_settings().admin_password
    if configured in ("", "change-me"):
        return templates.TemplateResponse(request, "login.html",
                                          {"error": "Admin login is disabled until ADMIN_PASSWORD is set in .env."},
                                          status_code=503)
    if hmac.compare_digest(password.encode(), configured.encode()):
        _failed_logins.pop(ip, None)
        request.session.clear()
        request.session["admin"] = True
        return RedirectResponse("/admin", status_code=303)
    _failed_logins[ip].append(now)
    return templates.TemplateResponse(request, "login.html", {"error": "Incorrect password."}, status_code=401)


@app.post("/admin/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/admin/login", status_code=303)


# ------------------------------------------------------------------ guard upload

@app.get("/")
def upload_form(request: Request):
    return templates.TemplateResponse(request, "upload.html", {"error": None, "form": {}})


@app.post("/upload")
async def upload(
    request: Request,
    background: BackgroundTasks,
    guard_name: str = Form(...),
    guard_id: str = Form(...),
    email: str = Form(""),
    site: str = Form(""),
    certificate: UploadFile = File(...),
    db=Depends(get_db),
):
    s = get_settings()
    form = {"guard_name": guard_name, "guard_id": guard_id, "email": email, "site": site}

    def fail(msg):
        return templates.TemplateResponse(request, "upload.html", {"error": msg, "form": form}, status_code=400)

    guard_name, guard_id = guard_name.strip(), guard_id.strip()
    if not guard_name or not guard_id:
        return fail("Please enter your full name and guard ID.")
    max_bytes = s.max_upload_mb * 1024 * 1024
    data = await certificate.read(max_bytes + 1)
    if not data:
        return fail("Please choose a certificate file to upload.")
    if len(data) > max_bytes:
        return fail(f"File is too large. Maximum size is {s.max_upload_mb} MB.")
    kind = sniff_type(data[:16])
    if not kind:
        return fail("Unsupported file type. Please upload a JPG, PNG or PDF.")
    mime, ext = kind

    s.upload_dir.mkdir(parents=True, exist_ok=True)
    path = s.upload_dir / f"{secrets.token_hex(16)}{ext}"
    path.write_bytes(data)

    sub = Submission(
        guard_name=guard_name[:200], guard_id=guard_id[:100], email=email.strip()[:200] or None,
        site=site.strip()[:200] or None, original_filename=(certificate.filename or "upload")[:300],
        stored_path=str(path), sha256=hashlib.sha256(data).hexdigest(), mime=mime,
    )
    db.add(sub)
    db.commit()
    background.add_task(scanner.scan_by_id, sub.id)
    return templates.TemplateResponse(request, "upload_success.html", {"sub": sub})


# ------------------------------------------------------------------ admin

def filtered(db, status: str = "", risk: str = "", site: str = "", q: str = "", reviewed: str = ""):
    s = get_settings()
    items = []
    for sub in db.scalars(select(Submission).order_by(Submission.uploaded_at.desc())):
        info = status_for(sub, warning_months=s.expiry_warning_months)
        if status and info.status != status:
            continue
        if risk and (sub.tamper_level or "") != risk:
            continue
        if site and (sub.site or "").lower() != site.lower():
            continue
        if reviewed == "yes" and not sub.reviewed or reviewed == "no" and sub.reviewed:
            continue
        if q:
            hay = " ".join(filter(None, [sub.guard_name, sub.guard_id, sub.holder_name, sub.cert_id, sub.email])).lower()
            if q.lower() not in hay:
                continue
        items.append((sub, info))
    return items


@app.get("/admin")
def dashboard(request: Request, status: str = "", risk: str = "", site: str = "", q: str = "", reviewed: str = "",
              _=Depends(require_admin), db=Depends(get_db)):
    items = filtered(db, status, risk, site, q, reviewed)
    all_rows = reports.build_rows(filtered(db))
    sites = sorted({sub.site for sub in db.scalars(select(Submission)) if sub.site})
    pending = sum(1 for sub, _i in items if sub.scan_status == "pending")
    return templates.TemplateResponse(request, "dashboard.html", {
        "items": items,
        "summary": reports.summary(all_rows),
        "filters": {"status": status, "risk": risk, "site": site, "q": q, "reviewed": reviewed},
        "query": str(request.url.query),
        "statuses": STATUSES, "sites": sites, "pending": pending,
        "EXPIRED": EXPIRED, "EXPIRING": EXPIRING, "VALID": VALID, "UNKNOWN": UNKNOWN,
        "warning_months": get_settings().expiry_warning_months,
        "ai_configured": bool(get_settings().anthropic_api_key),
    })


def get_sub(db, sub_id: int) -> Submission:
    sub = db.get(Submission, sub_id)
    if not sub:
        raise HTTPException(404, "Submission not found")
    return sub


@app.get("/admin/submissions/{sub_id}")
def detail(request: Request, sub_id: int, _=Depends(require_admin), db=Depends(get_db)):
    sub = get_sub(db, sub_id)
    info = status_for(sub, warning_months=get_settings().expiry_warning_months)
    others = db.scalars(select(Submission).where(Submission.guard_id == sub.guard_id, Submission.id != sub.id)
                        .order_by(Submission.uploaded_at.desc())).all()
    return templates.TemplateResponse(request, "detail.html", {"sub": sub, "info": info, "others": others,
                                                               "warning_months": get_settings().expiry_warning_months})


@app.get("/admin/submissions/{sub_id}/file")
def submission_file(sub_id: int, _=Depends(require_admin), db=Depends(get_db)):
    sub = get_sub(db, sub_id)
    path = Path(sub.stored_path)
    if not path.exists():
        raise HTTPException(404, "File missing")
    return FileResponse(path, media_type=sub.mime, filename=sub.original_filename, content_disposition_type="inline")


@app.get("/admin/submissions/{sub_id}/preview.png")
def submission_preview(sub_id: int, _=Depends(require_admin), db=Depends(get_db)):
    """First page of a PDF rendered as PNG (browsers, especially mobile, can't always show PDFs inline)."""
    sub = get_sub(db, sub_id)
    path = Path(sub.stored_path)
    if sub.mime != "application/pdf" or not path.exists():
        raise HTTPException(404, "No preview")
    try:
        png = pdf_utils.render_first_page_png(path.read_bytes(), zoom=1.5)
    except Exception:
        raise HTTPException(422, "PDF could not be rendered")
    return Response(png, media_type="image/png")


@app.post("/admin/submissions/{sub_id}/rescan")
def rescan(request: Request, sub_id: int, csrf: str = Form(""), _=Depends(require_admin), db=Depends(get_db)):
    check_csrf(request, csrf)
    scanner.scan_submission(db, get_sub(db, sub_id))
    return RedirectResponse(f"/admin/submissions/{sub_id}", status_code=303)


@app.post("/admin/rescan-all")
def rescan_all(request: Request, background: BackgroundTasks, csrf: str = Form(""), only_failed: str = Form(""),
               _=Depends(require_admin), db=Depends(get_db)):
    check_csrf(request, csrf)
    q = select(Submission.id)
    if only_failed:
        q = q.where(Submission.scan_status.in_(["pending", "error", "ai_unavailable"]))
    for sub_id in db.scalars(q):
        background.add_task(scanner.scan_by_id, sub_id)
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/submissions/{sub_id}/update")
def update(request: Request, sub_id: int, csrf: str = Form(""), issue_date: str = Form(""),
           expiry_date: str = Form(""), admin_notes: str = Form(""), reviewed: str = Form(""),
           _=Depends(require_admin), db=Depends(get_db)):
    check_csrf(request, csrf)
    sub = get_sub(db, sub_id)
    new_issue, new_expiry = parse_date(issue_date), parse_date(expiry_date)
    shown_expiry = None if sub.expiry_inferred else sub.expiry_date  # form leaves inferred expiry blank
    if new_issue != sub.issue_date or new_expiry != shown_expiry:
        sub.issue_date = new_issue
        sub.expiry_date, sub.expiry_inferred = resolve_expiry(new_issue, new_expiry, get_settings().default_validity_years)
        sub.dates_overridden = True
        scanner.apply_tamper(db, sub)
    sub.admin_notes = admin_notes.strip() or None
    sub.reviewed = bool(reviewed)
    db.commit()
    return RedirectResponse(f"/admin/submissions/{sub_id}", status_code=303)


@app.post("/admin/submissions/{sub_id}/delete")
def delete(request: Request, sub_id: int, csrf: str = Form(""), _=Depends(require_admin), db=Depends(get_db)):
    check_csrf(request, csrf)
    sub = get_sub(db, sub_id)
    Path(sub.stored_path).unlink(missing_ok=True)
    db.delete(sub)
    db.commit()
    return RedirectResponse("/admin", status_code=303)


@app.get("/admin/reports/export.{fmt}")
def export(fmt: str, status: str = "", risk: str = "", site: str = "", q: str = "", reviewed: str = "",
           _=Depends(require_admin), db=Depends(get_db)):
    rows = reports.build_rows(filtered(db, status, risk, site, q, reviewed))
    stamp = date.today().isoformat()
    if fmt == "csv":
        body, media = reports.to_csv(rows), "text/csv; charset=utf-8"
    elif fmt == "xlsx":
        body, media = reports.to_xlsx(rows), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    elif fmt == "pdf":
        body, media = reports.to_pdf(rows, get_settings().expiry_warning_months,
                                     {"status": status, "risk": risk, "site": site, "search": q, "reviewed": reviewed}), "application/pdf"
    else:
        raise HTTPException(404, "Unknown format")
    return Response(body, media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="cpr-report-{stamp}.{fmt}"'})
