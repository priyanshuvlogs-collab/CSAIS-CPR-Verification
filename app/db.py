import logging

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import NullPool

from app.config import get_settings


class Base(DeclarativeBase):
    pass


_engine = None
_SessionLocal = None


def init_engine(url: str | None = None):
    global _engine, _SessionLocal
    settings = get_settings()
    url = url or settings.db_url
    if url.startswith("sqlite"):
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        _engine = create_engine(url, connect_args={"check_same_thread": False})
    else:
        # Serverless-friendly: no client-side pool (the Supabase pooler does pooling) and no
        # server-side prepared statements (not supported in pgbouncer/Supavisor transaction mode).
        _engine = create_engine(
            url, poolclass=NullPool, connect_args={"prepare_threshold": None},
            execution_options={"schema_translate_map": {None: settings.db_schema or None}},
        )
    _SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)
    from app import models  # noqa: F401  (register tables)

    try:
        Base.metadata.create_all(_engine)
    except Exception:  # keep the app up so /healthz can report the problem
        logging.getLogger("cpr").exception("Could not create database tables")
    return _engine


def SessionLocal():
    if _SessionLocal is None:
        init_engine()
    return _SessionLocal()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
