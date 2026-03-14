from __future__ import annotations
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

def _db_url() -> str:
    url = os.getenv("DATABASE_PUBLIC_URL", "").strip().strip("\"").strip("\'") or os.getenv("DATABASE_URL_PUBLIC", "").strip().strip("\"").strip("\'") or os.getenv("DATABASE_URL", "").strip().strip("\"").strip("\'")
    # Normalize Railway internal hostname casing
    url = url.replace("Postgres.railway.internal", "postgres.railway.internal")
    if not url:
        return ""
    # Railway sometimes provides postgres:// -> SQLAlchemy prefers postgresql://
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    return url

class Base(DeclarativeBase):
    pass

def make_engine():
    url = _db_url()
    if not url:
        return None
    pool_size = int(os.getenv("DB_POOL_SIZE", "5"))
    max_overflow = int(os.getenv("DB_MAX_OVERFLOW", "10"))
    pool_timeout = int(os.getenv("DB_POOL_TIMEOUT", "30"))
    # PATCH0100_13: connect_timeout prevents startup from hanging when DB is
    # unreachable (e.g. Railway private-network DNS not yet ready).  Without
    # this, psycopg2 blocks on TCP connect indefinitely, causing uvicorn to
    # never emit "Application startup complete" and Railway to return 502.
    connect_timeout = int(os.getenv("DB_CONNECT_TIMEOUT", "5"))
    return create_engine(
        url,
        pool_pre_ping=True,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_timeout=pool_timeout,
        connect_args={"connect_timeout": connect_timeout},
    )

ENGINE = make_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=ENGINE) if ENGINE else None

def get_db():
    if SessionLocal is None:
        raise RuntimeError("DATABASE_URL not configured")
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
