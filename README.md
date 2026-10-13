# CSAIS CPR Certificate Verification Portal

A web portal where security guards upload their CPR / BLS / First Aid certificates and an admin can:

- **Scan** each certificate with Claude (Anthropic API) to read the holder name, issuer, certificate number, and issue/expiry dates
- **See expiry status** for each one: **Expired**, **Expiring Soon** (within 6 months, configurable), **Valid**, or **Unknown**
- **Check for tampering** with a 0–100 risk score and a list of the specific indicators found
- **Export reports** as CSV, Excel, or PDF, using the dashboard's current filters

## Quick start

```bash
pip install -r requirements.txt
cp .env.example .env        # then add ANTHROPIC_API_KEY, ADMIN_PASSWORD, SECRET_KEY
uvicorn app.main:app --reload
```

- Guard upload form: http://localhost:8000/
- Admin dashboard: http://localhost:8000/admin

### Deploying on Vercel + Supabase

The app runs as a single Vercel Python function (`app/main.py`, see `vercel.json`) and keeps all data, including uploaded files, in Postgres. Set these environment variables in the Vercel project:

| Variable | Value |
|---|---|
| `DATABASE_URL` | Supabase pooler URL in transaction mode, `postgresql+psycopg://…:6543/postgres` |
| `DB_SCHEMA` | `cpr` |
| `SCAN_MODE` | `sync` (Vercel can't run work after the response is sent) |
| `MAX_UPLOAD_MB` | `4` (Vercel limits request bodies to 4.5 MB; large phone photos are shrunk in the browser first) |
| `ANTHROPIC_API_KEY`, `ADMIN_PASSWORD`, `SECRET_KEY` | as above |

`GET /healthz` returns `{"ok": true}` when the database is reachable.

With Docker:

```bash
docker build -t cpr-portal .
docker run -p 8000:8000 --env-file .env -v cpr-data:/data cpr-portal
```

Run in production behind HTTPS, for example with a reverse proxy such as Caddy or nginx.

## How it works

1. **Upload.** A guard enters their name, guard ID, and optionally email and site, then uploads a JPG, PNG, or PDF (max 10 MB). The file type is checked from the file's contents, not its extension. The file is saved with a random name.
2. **Scan.** The scan runs in the background right after upload. The photo or PDF is sent to Claude (`ANTHROPIC_MODEL`, default `claude-opus-5-5`), which reads PDFs directly and returns structured JSON with the certificate fields and its visual tampering observations. If Claude's safety filter declines a document, the API retries it on a fallback model automatically.
3. **Expiry.** Status is recalculated from today's date every time the dashboard loads, so a certificate moves to "Expiring Soon" or "Expired" without a re-scan. If a card only shows an issue date, expiry is set to issue date + 2 years and marked *inferred*.
4. **Tamper risk.** Independent signals each add points:

   | Signal | Example |
   |---|---|
   | AI visual review | mismatched fonts in dates, pasted or blurred areas, missing logo or seal |
   | PDF metadata | Producer or Creator is Photoshop or an online PDF editor, modified long after creation, several incremental saves |
   | Image metadata | EXIF "Software" tag is Photoshop, GIMP, Canva, … |
   | Date sanity | expiry before issue date, issue date in the future, validity period not about 2 years |
   | Name check | the name on the card doesn't match the name the guard entered (fuzzy match) |
   | Duplicates | the same file or same certificate number was submitted by a *different* guard |

   Scores of 0–29 are **Low**, 30–59 **Medium**, and 60+ **High**. These are indicators for review, not proof. Confirm flagged certificates with the issuer, for example through the AHA eCard or Red Cross certificate lookup.
5. **Review.** On the detail page the admin can view the file, correct dates, add notes, mark the certificate as reviewed, re-scan it, or delete it.

Without an `ANTHROPIC_API_KEY`, uploads still work and the file forensics still run. Use **Re-scan incomplete** on the dashboard after adding the key.

## Security notes

- Only the admin can see uploaded files and reports. The admin session cookie is signed. Login locks for 15 minutes after 5 failed attempts. Admin actions require a CSRF token.
- The Claude API key is used only on the server and is never sent to the browser.
- `data/` (the SQLite DB and uploads) and `.env` are git-ignored. Back up `data/`.

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

The tests use a fake Claude client, so they need no API key.
