"""
Async SQLAlchemy engine and session factory with full production configuration.

The engine is created at import time with connection pooling for optimal
performance. Sessions are request-scoped using dependency injection,
ensuring proper cleanup after each request.

Connection pool values are configured from settings, allowing environment-
specific tuning without code changes.
"""

from typing import AsyncGenerator, Optional

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool, QueuePool
from sqlalchemy import text

from app.core.config.settings import get_settings
from app.utils.logger import logger

# ============================================================
# STEP 1: LOAD SETTINGS
# ============================================================

settings = get_settings()

logger.info(
    "Initializing database connection",
    extra={
        "event": "db_init_start",
        "pool_size": settings.database_pool_size,
        "max_overflow": settings.database_max_overflow,
        "environment": settings.environment,
    },
)

# ============================================================
# STEP 2: CREATE ASYNC ENGINE WITH PRODUCTION CONFIGURATION
# ============================================================

engine = create_async_engine(
    # Connection URL from settings
    settings.async_database_url,
    
    # Connection pool configuration
    pool_size=settings.database_pool_size,
    max_overflow=settings.database_max_overflow,
    pool_timeout=settings.database_pool_timeout,
    pool_pre_ping=True,           # Check connection before using
    pool_recycle=3600,            # Recycle after 1 hour
    
    # Logging
    echo=settings.debug and settings.is_development,
    echo_pool=settings.debug and settings.is_development,
    
    # Performance
    poolclass=QueuePool,
    connect_args={
        "timeout": 10,            # Connection timeout
        "command_timeout": 30,    # Query timeout
        "server_settings": {
            "application_name": settings.app_name,
        },
    },
)

# ============================================================
# STEP 3: CREATE SESSION FACTORY
# ============================================================

SessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,      # Objects remain usable after commit
    autocommit=False,            # Explicit commits only
    autoflush=False,             # Explicit flushes only
)


# ============================================================
# STEP 5: DATABASE HEALTH CHECK FUNCTIONS
# ============================================================

async def check_db_connection() -> bool:
    """
    Check if database connection is healthy.
    
    Returns:
        True if connection is healthy, False otherwise
    """
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.warning(
            f"Database health check failed: {str(e)}",
            extra={"event": "db_health_check_failed", "error": str(e)},
        )
        return False

async def ping_db() -> bool:
    """
    Ping database to verify connection.
    
    Used during startup to ensure database is reachable.
    
    Returns:
        True if ping successful, False otherwise
    """
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        logger.info("Database ping successful")
        return True
    except Exception as e:
        logger.error(
            f"Database ping failed: {str(e)}",
            extra={"event": "db_ping_failed", "error": str(e)},
        )
        return False

# ============================================================
# STEP 6: DATABASE INITIALIZATION (Startup)
# ============================================================

async def init_db_pool() -> None:
    """
    Initialize database connection pool.
    
    Called during application startup to warm up connections.
    This ensures connections are ready before accepting traffic.
    """
    try:
        # Pre-warm connections by checking connection
        await ping_db()
        
        logger.info(
            "Database connection pool initialized",
            extra={
                "event": "db_pool_initialized",
                "pool_size": settings.database_pool_size,
                "max_overflow": settings.database_max_overflow,
            },
        )
    except Exception as e:
        logger.error(
            f"Failed to initialize database pool: {str(e)}",
            extra={"event": "db_pool_init_failed", "error": str(e)},
        )
        raise

# ============================================================
# STEP 7: DATABASE CLEANUP (Shutdown)
# ============================================================

async def close_db_connections() -> None:
    """
    Close all database connections gracefully.
    
    Called during application shutdown to release all connections.
    This ensures no connections are left open.
    """
    try:
        await engine.dispose()
        logger.info(
            "Database connections closed successfully",
            extra={"event": "db_connections_closed"},
        )
    except Exception as e:
        logger.error(
            f"Error closing database connections: {str(e)}",
            extra={"event": "db_connections_close_failed", "error": str(e)},
        )
        raise

# ============================================================
# STEP 8: TRANSACTION HELPERS
# ============================================================

async def commit_or_rollback(session: AsyncSession) -> None:
    """
    Commit session or rollback on error.
    
    This helper ensures transactions are properly handled.
    
    Args:
        session: Active database session
    """
    try:
        await session.commit()
    except Exception as e:
        await session.rollback()
        logger.error(
            f"Transaction failed, rolled back: {str(e)}",
            extra={"event": "transaction_rollback", "error": str(e)},
        )
        raise

# ============================================================
# STEP 9: DATABASE MONITORING
# ============================================================

def get_pool_status() -> dict:
    """
    Get current connection pool status.
    
    Returns:
        Dictionary with pool statistics
    """
    if hasattr(engine.pool, "size"):
        return {
            "size": engine.pool.size(),
            "checkedin": engine.pool.checkedin(),
            "overflow": engine.pool.overflow(),
            "total": engine.pool.total(),
        }
    return {"pool_type": "No pool or pool not accessible"}

# ============================================================
# STEP 10: ENGINE EXPORT (For main.py)
# ============================================================

# Export engine for direct access (used in migrations, CLI, etc.)
__all__ = [
    "engine",
    "SessionLocal",
    "check_db_connection",
    "ping_db",
    "init_db_pool",
    "close_db_connections",
    "commit_or_rollback",
    "get_pool_status",
]

logger.info(
    "Database configuration loaded successfully",
    extra={
        "event": "db_config_loaded",
        "database": settings.database_url.split("@")[-1] if "@" in settings.database_url else "local",
        "pool_size": settings.database_pool_size,
    },
)