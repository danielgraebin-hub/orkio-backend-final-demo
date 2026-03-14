from __future__ import annotations
import os
from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context

from app.db import Base
from app import models  # noqa: F401

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

def _db_url() -> str:
    url = os.getenv("DATABASE_PUBLIC_URL", "").strip().strip("\"").strip("\'") or os.getenv("DATABASE_URL_PUBLIC", "").strip().strip("\"").strip("\'") or os.getenv("DATABASE_URL", "").strip().strip("\"").strip("\'")
    # Normalize Railway internal hostname casing
    url = url.replace("Postgres.railway.internal", "postgres.railway.internal")
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    return url

def run_migrations_offline() -> None:
    url = _db_url()
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = _db_url()
    connectable = engine_from_config(configuration, prefix="sqlalchemy.", poolclass=pool.NullPool)

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
