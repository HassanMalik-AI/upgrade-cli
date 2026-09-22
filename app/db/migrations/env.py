"""
Alembic environment configured for async SQLAlchemy metadata discovery.

This module configures Alembic migrations for an async SQLAlchemy application.
It supports:
- Online migrations (connect to DB, run migrations)
- Offline migrations (generate SQL without DB)
- Async engine with asyncpg driver
- Metadata discovery from app.models
- Naming conventions from app.db.base
- Multi-environment support (dev/staging/prod)
- Type comparison (detect column type changes)
- Server default comparison (detect default changes)

Key Design Decisions:
- Uses `import app.models` to ensure ALL models are registered before
  Alembic reads `Base.metadata`. Without this, new models won't appear.
- Uses `NullPool` for migrations (never pool during DDL operations).
- Uses `async_engine_from_config` + `run_sync` for async driver compatibility.
- Escapes `%` as `%%` for ConfigParser (URLs with % in password need this).
- Supports both offline (SQL generation) and online (direct execution) modes.
"""

import asyncio
import logging
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config

# ============================================================
# CRITICAL: IMPORT ALL MODELS BEFORE READING METADATA
# ============================================================

# This import MUST come before target_metadata is used.
# It triggers loading of app/models/__init__.py, which imports
# every model module, which registers every table in Base.metadata.
# Without this, Alembic autogenerate would miss new tables.
import app.models  # noqa: F401

from app.core.config.settings import get_settings
from app.db.base import Base

# ============================================================
# ALEMBIC CONFIG
# ============================================================

# The Alembic Config object provides access to values in alembic.ini
config = context.config

# Configure Python logging from alembic.ini
# This sets up loggers like "alembic", "sqlalchemy.engine", etc.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Setup module-level logger for env.py diagnostics
logger = logging.getLogger("alembic.env")

# Load validated, cached settings
settings = get_settings()

# ============================================================
# DATABASE URL CONFIGURATION
# ============================================================

# Set the database URL in Alembic config.
# The `.replace("%", "%%")` is important: Alembic uses ConfigParser,
# which treats % as an interpolation marker. URLs with % in the
# password (like "p%ssword") would break without escaping.
config.set_main_option(
    "sqlalchemy.url",
    settings.database_url.replace("%", "%%"),
)

# ============================================================
# TARGET METADATA (For autogenerate)
# ============================================================

# Alembic uses this metadata to:
# - Detect new tables, columns, indexes, constraints
# - Compare current models vs database schema
# - Generate migration scripts
# 
# CRITICAL: This must be set AFTER all models are imported.
# Base.metadata is populated during import of model classes.
target_metadata = Base.metadata


# ============================================================
# OFFLINE MIGRATIONS (Generate SQL without DB connection)
# ============================================================

def run_migrations_offline() -> None:
    """
    Generate SQL without opening a database connection.
    
    Use cases:
    - Review SQL before applying
    - Air-gapped environments (no DB access)
    - Generate migration scripts for DBAs to review
    - CI/CD pipelines that verify migrations
    
    Commands:
        alembic upgrade head --sql > migration.sql
        alembic downgrade -1 --sql > rollback.sql
    
    Note: Offline mode cannot detect drift from actual DB.
    It only compares models vs migration history.
    """
    logger.info("Running migrations in OFFLINE mode")
    
    context.configure(
        url=settings.database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # Detect column type changes
        compare_type=True,
        # Detect server default changes
        compare_server_default=True,
        # Include schemas in comparison
        include_schemas=True,
        # Batch mode for SQLite (ignored by PostgreSQL)
        render_as_batch=True,
    )

    with context.begin_transaction():
        context.run_migrations()


# ============================================================
# ONLINE MIGRATIONS (Connect and run)
# ============================================================

def do_run_migrations(connection) -> None:
    """
    Run migrations using an existing sync connection.
    
    This function is called via `run_sync` from the async engine.
    Alembic's internal machinery is synchronous, so we need to
    hand it a sync connection.
    
    Args:
        connection: SQLAlchemy sync Connection object
    """
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # Detect column type changes (String → Text, etc.)
        compare_type=True,
        # Detect server default changes
        compare_server_default=True,
        # Include schemas in comparison
        include_schemas=True,
        # Batch mode for SQLite (helpful for column changes)
        render_as_batch=True,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """
    Run migrations through the async database driver.
    
    Uses asyncpg driver and Alembic's run_sync to bridge the
    async driver with Alembic's sync-only internals.
    
    Design Decisions:
    - NullPool: Migrations are one-shot, no need to pool connections.
      Pooling during DDL can cause issues with locks.
    - `async_engine_from_config`: Uses the same config as the app,
      ensuring consistent connection parameters.
    - `run_sync`: Bridges async connection to sync context for Alembic.
    - `dispose`: Cleanly close all connections after migration.
    """
    logger.info("Running migrations in ONLINE mode")
    
    # Get Alembic config section
    configuration = config.get_section(config.config_ini_section, {})
    
    # Create async engine with NullPool
    # NullPool = no connection reuse (safe for migrations)
    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    
    async with connectable.connect() as connection:
        # Alembic requires sync context, so we bridge via run_sync
        await connection.run_sync(do_run_migrations)
    
    # Dispose engine (release all connections)
    # Important for clean shutdown
    await connectable.dispose()


# ============================================================
# ENTRY POINT
# ============================================================

if context.is_offline_mode():
    # Offline: generate SQL without DB connection
    run_migrations_offline()
else:
    # Online: connect to DB and run migrations
    # asyncio.run() starts a new event loop for async migrations
    asyncio.run(run_migrations_online())