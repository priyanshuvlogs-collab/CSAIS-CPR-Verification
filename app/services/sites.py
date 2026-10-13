"""Site list: case-insensitive matching so "costco", "Costco " and "COSTCO" are one site."""
from sqlalchemy import func, select

from app.models import Site


def clean(name: str | None) -> str:
    return " ".join((name or "").split())[:200]


def find(db, name: str) -> Site | None:
    return db.scalar(select(Site).where(func.lower(Site.name) == clean(name).lower()))


def get_or_create(db, name: str, added_by: str = "guard") -> Site | None:
    """Return the existing site (reactivating it) or add a new one. Caller commits."""
    name = clean(name)
    if len(name) < 2:
        return None
    site = find(db, name)
    if site is None:
        site = Site(name=name, added_by=added_by)
        db.add(site)
        db.flush()
    elif not site.active and added_by == "admin":
        site.active = True
    return site


def active_names(db) -> list[str]:
    return list(db.scalars(select(Site.name).where(Site.active.is_(True)).order_by(func.lower(Site.name))))


def bulk_add(db, text: str) -> tuple[int, int]:
    """Add one site per line (or comma/semicolon separated). Returns (added, already_there)."""
    added = existing = 0
    seen = set()
    for raw in text.replace(";", "\n").replace(",", "\n").splitlines():
        name = clean(raw)
        if len(name) < 2 or name.lower() in seen:
            continue
        seen.add(name.lower())
        if find(db, name):
            existing += 1
        else:
            get_or_create(db, name, added_by="admin")
            added += 1
    return added, existing
