"""
Alembic migration environment.

Imports our ORM Base so autogenerate can detect model changes.
"""

from logging.config import fileConfig
from pathlib import Path
import sys

from alembic import context
from sqlalchemy import engine_from_config, pool

# Ensure backend root (which contains `app/`) is on import path.
BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.models.database import Base
from app.config import get_settings

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Set the DB URL from our config (overrides alembic.ini)
#
# `database_migration_url`, not `database_sync_url`. Since 2026-10-19 the
# application connects as `tip_app`, which has DML and no DDL — so running
# migrations on the application's connection fails with "must be owner of
# table", and would fail *partway through* a migration rather than at its
# start. Migrations are the one job that needs the owning superuser, and this
# is the only place that URL is read. See scripts/db_roles.sql.
settings = get_settings()
config.set_main_option("sqlalchemy.url", settings.database_migration_url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode — generates SQL without connecting."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode — connects and applies."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
