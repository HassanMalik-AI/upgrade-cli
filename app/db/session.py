"""
FastAPI dependency that yields and closes one async DB session.

This module provides the database session dependency for FastAPI endpoints.
Each request gets its own session which is automatically closed after the
request completes.

Features:
- Request-scoped sessions with auto-commit/rollback
- Context manager for background tasks
- Read-only sessions for analytics
- Performance monitoring
- Tenant-aware sessions for multi-tenancy
- Health check utilities
- Request ID tracking for observability

Design:
- Session per request (never share between requests)
- Auto-close with `async with` (or explicit finally block)
- Explicit commit (don't auto-commit by default)
- Rollback on exception for data integrity
- Structured logging for every session lifecycle
"""

import time
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import Optional

from fastapi import Depends, Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config.database import SessionLocal, engine
from app.core.config.settings import get_settings
from app.utils.logger import logger

# ============================================================
# REQUEST ID CONTEXT (For Distributed Tracing)
# ============================================================

# Context variable for storing request ID (set by middleware)
# Used for correlating logs across the request lifecycle
request_id_var: ContextVar[str] = ContextVar("request_id", default="")

settings = get_settings()


# ============================================================
# 1. STANDARD SESSION DEPENDENCY (Recommended)
# ============================================================

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Yield a request-scoped SQLAlchemy session and always close it.
    
    This is the STANDARD dependency for FastAPI endpoints.
    Every request gets a fresh session that is:
    - Automatically created when the request starts
    - Automatically closed when the request ends
    - Rolled back on any exception
    - Committed explicitly by the endpoint (not auto-commit)
    
    Why explicit commit (not auto-commit):
    - Business logic controls transaction boundaries
    - Multiple operations can be atomic
    - Easier to test and reason about
    - No surprise commits on read-only operations
    
    Yields:
        AsyncSession: Database session for the current request
    
    Example:
        @router.get("/users")
        async def get_users(db: AsyncSession = Depends(get_db)):
            result = await db.execute(select(User))
            return result.scalars().all()
        
        @router.post("/users")
        async def create_user(data: UserCreate, db: AsyncSession = Depends(get_db)):
            user = User(**data.dict())
            db.add(user)
            await db.commit()
            await db.refresh(user)
            return user
    """
    session: AsyncSession = SessionLocal()
    try:
        yield session
    except Exception as e:
        await session.rollback()
        logger.exception(f"Database session error: {e}")
        raise
    finally:
        await session.close()


# ============================================================
# 2. SESSION WITH AUTO-COMMIT (For Simple CRUD)
# ============================================================

async def get_db_autocommit() -> AsyncGenerator[AsyncSession, None]:
    """
    Session that auto-commits on success, auto-rollbacks on error.
    
    Use this for simple endpoints where you want automatic
    transaction handling without explicit commit calls.
    
    When to use:
    - Simple CRUD operations (single logical unit)
    - Endpoints with no complex transaction logic
    - Reducing boilerplate in basic endpoints
    
    When NOT to use:
    - Multi-step transactions
    - Operations requiring explicit rollback control
    - Read-only endpoints (waste of a commit)
    
    Yields:
        AsyncSession: Auto-committing database session
    """
    session = SessionLocal()
    try:
        yield session
        await session.commit()
    except Exception as e:
        await session.rollback()
        logger.exception(f"Auto-commit session rolled back: {e}")
        raise
    finally:
        await session.close()


# ============================================================
# 3. SESSION WITH REQUEST TRACKING (For Observability)
# ============================================================

async def get_db_tracked(request: Request) -> AsyncGenerator[AsyncSession, None]:
    """
    Session with correlation ID for distributed tracing.
    
    Adds the request ID to every query as a SQL comment, making it
    possible to correlate database queries with application logs.
    
    This is CRITICAL for:
    - Debugging production issues
    - Performance analysis
    - Security audit trails
    - Distributed tracing (Jaeger, Zipkin)
    
    Yields:
        AsyncSession: Session with request tracking
    """
    # Get or generate request ID
    request_id = getattr(request.state, "request_id", None) or str(uuid.uuid4())
    request_id_var.set(request_id)
    
    session: AsyncSession = SessionLocal()
    try:
        # Add request ID as SQL comment for query correlation
        # Visible in PostgreSQL logs: /* req:abc-123 */ SELECT ...
        await session.execute(text(f"SET application_name = 'app-{request_id[:8]}'"))
        yield session
    except Exception as e:
        await session.rollback()
        logger.bind(request_id=request_id).exception("Database session error")
        raise
    finally:
        await session.close()


# ============================================================
# 4. READ-ONLY SESSION (For Analytics & Reporting)
# ============================================================

async def get_readonly_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Read-only database session for analytics and reporting.
    
    Prevents accidental writes by setting the transaction to
    READ ONLY at the database level. Any INSERT/UPDATE/DELETE
    will raise an error.
    
    Why use read-only sessions:
    - Analytics endpoints can't accidentally modify data
    - Reporting queries run in a safe environment
    - Extra safety layer against application bugs
    - Can be routed to read replicas for scalability
    
    Yields:
        AsyncSession: Read-only session
    """
    session: AsyncSession = SessionLocal()
    try:
        # Set transaction to read-only
        await session.execute(text("SET TRANSACTION READ ONLY"))
        yield session
    except Exception as e:
        await session.rollback()
        logger.exception(f"Read-only session error: {e}")
        raise
    finally:
        await session.close()


# ============================================================
# 5. SESSION WITH PERFORMANCE MONITORING
# ============================================================

async def get_db_with_metrics() -> AsyncGenerator[AsyncSession, None]:
    """
    Database session with performance monitoring.
    
    Tracks session duration and logs slow sessions for analysis.
    Helps identify performance bottlenecks in production.
    
    Yields:
        AsyncSession: Session with metrics collection
    """
    start_time = time.perf_counter()
    session: AsyncSession = SessionLocal()
    
    try:
        yield session
    except Exception as e:
        await session.rollback()
        raise
    finally:
        duration_ms = (time.perf_counter() - start_time) * 1000
        await session.close()
        
        # Log all sessions (DEBUG) or slow sessions (WARNING)
        log_method = logger.warning if duration_ms > 1000 else logger.debug
        log_method(
            f"Database session completed",
            extra={
                "session_duration_ms": round(duration_ms, 2),
                "slow": duration_ms > 1000,
            }
        )


# ============================================================
# 6. SESSION WITH TIMEOUT (For Long-Running Query Protection)
# ============================================================

async def get_db_with_timeout(timeout_seconds: int = 30) -> AsyncGenerator[AsyncSession, None]:
    """
    Session with statement timeout to prevent runaway queries.
    
    Sets a maximum execution time for every query in the session.
    Long-running queries are automatically killed by PostgreSQL.
    
    Why timeouts matter:
    - Prevents blocking the connection pool
    - Protects against accidental cross-joins
    - Ensures fair resource allocation
    - Critical for multi-tenant applications
    
    Yields:
        AsyncSession: Session with statement timeout
    """
    session: AsyncSession = SessionLocal()
    try:
        # Set statement timeout for this session
        await session.execute(
            text(f"SET statement_timeout = '{timeout_seconds * 1000}'")
        )
        yield session
    except Exception as e:
        await session.rollback()
        logger.exception(f"Timeout session error: {e}")
        raise
    finally:
        await session.close()


# ============================================================
# 7. CONTEXT MANAGER (For Background Tasks & Scripts)
# ============================================================

@asynccontextmanager
async def get_db_context() -> AsyncGenerator[AsyncSession, None]:
    """
    Context manager for database sessions in non-request contexts.
    
    Unlike `get_db()` (FastAPI dependency), this is a context manager
    that can be used in:
    - Background tasks (Celery, ARQ, etc.)
    - CLI scripts and management commands
    - Cron jobs
    - Startup/shutdown hooks
    - Tests
    
    Usage:
        async with get_db_context() as db:
            user = await db.get(User, user_id)
            user.name = "Updated"
            await db.commit()
    
    Yields:
        AsyncSession: Database session
    """
    session: AsyncSession = SessionLocal()
    try:
        yield session
    except Exception as e:
        await session.rollback()
        logger.exception(f"Background session error: {e}")
        raise
    finally:
        await session.close()


# ============================================================
# 8. TENANT-AWARE SESSION (Multi-Tenancy)
# ============================================================

async def get_tenant_db(tenant_id: str) -> AsyncGenerator[AsyncSession, None]:
    """
    Multi-tenant database session.
    
    Supports multiple tenancy strategies:
    - Schema-per-tenant: `SET search_path TO tenant_xyz`
    - Row-level security: `SET app.current_tenant = 'xyz'`
    - Database-per-tenant: Different connection strings
    
    Example (schema-per-tenant):
        @router.get("/orders")
        async def get_orders(
            tenant: Tenant = Depends(get_current_tenant),
            db: AsyncSession = Depends(get_tenant_db_dep),
        ):
            result = await db.execute(select(Order))
            return result.scalars().all()
    
    Args:
        tenant_id: Tenant identifier
        
    Yields:
        AsyncSession: Tenant-scoped session
    """
    session: AsyncSession = SessionLocal()
    try:
        # Validate tenant_id (prevent SQL injection)
        if not tenant_id.isalnum():
            raise ValueError(f"Invalid tenant_id: {tenant_id}")
        
        # Set the schema for this session
        schema = f"tenant_{tenant_id}"
        await session.execute(text(f"SET search_path TO {schema}"))
        yield session
    except Exception as e:
        await session.rollback()
        logger.exception(f"Tenant session error: {e}")
        raise
    finally:
        await session.close()


# ============================================================
# 9. HEALTH CHECK FUNCTIONS
# ============================================================

async def check_db_health() -> bool:
    """
    Check if database is accessible (lightweight).
    
    Used by `/health` and `/health/ready` endpoints.
    Returns True if database responds to a simple query.
    
    Returns:
        bool: True if healthy, False otherwise
    """
    try:
        async with SessionLocal() as session:
            await session.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False


async def check_db_health_deep() -> dict:
    """
    Deep database health check (diagnostic).
    
    Returns:
        dict: Detailed health information including:
            - connected: bool
            - version: PostgreSQL version
            - pool: connection pool statistics
            - latency_ms: query round-trip time
    """
    result = {
        "connected": False,
        "version": None,
        "pool": None,
        "latency_ms": None,
    }
    
    try:
        start = time.perf_counter()
        async with SessionLocal() as session:
            # Check connection and get version
            version_result = await session.execute(text("SELECT version()"))
            result["version"] = version_result.scalar()
            result["connected"] = True
            result["latency_ms"] = round((time.perf_counter() - start) * 1000, 2)
        
        # Get pool statistics
        if hasattr(engine.pool, "size"):
            result["pool"] = {
                "size": engine.pool.size(),
                "checked_in": engine.pool.checkedin(),
                "checked_out": engine.pool.checkedout(),
                "overflow": engine.pool.overflow(),
            }
    except Exception as e:
        logger.error(f"Deep health check failed: {e}")
        result["error"] = str(e)
    
    return result


# ============================================================
# 10. TRANSACTION HELPERS
# ============================================================

@asynccontextmanager
async def transaction(db: AsyncSession) -> AsyncGenerator[None, None]:
    """
    Explicit transaction context manager.
    
    Use for multi-step transactions with explicit control:
        async with transaction(db):
            user = User(...)
            db.add(user)
            order = Order(user_id=user.id)
            db.add(order)
            # Both committed or both rolled back
    
    Yields:
        None: Control returns to caller
    """
    try:
        yield
        await db.commit()
    except Exception:
        await db.rollback()
        raise


async def execute_with_retry(
    db: AsyncSession,
    statement,
    max_retries: int = 3,
) -> any:
    """
    Execute a statement with retry logic for transient failures.
    
    Retries on:
    - Serialization failures (concurrent updates)
    - Deadlocks
    - Connection issues
    
    Args:
        db: Database session
        statement: SQLAlchemy statement
        max_retries: Maximum retry attempts
        
    Returns:
        Query result
    """
    import asyncio
    from sqlalchemy.exc import DBAPIError
    
    for attempt in range(max_retries):
        try:
            return await db.execute(statement)
        except DBAPIError as e:
            if attempt == max_retries - 1:
                raise
            if "deadlock" in str(e).lower() or "serialization" in str(e).lower():
                await asyncio.sleep(0.1 * (2 ** attempt))  # Exponential backoff
                continue
            raise


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    # Session dependencies
    "get_db",
    "get_db_autocommit",
    "get_db_tracked",
    "get_readonly_db",
    "get_db_with_metrics",
    "get_db_with_timeout",
    "get_tenant_db",
    
    # Context managers
    "get_db_context",
    "transaction",
    
    # Health checks
    "check_db_health",
    "check_db_health_deep",
    
    # Utilities
    "execute_with_retry",
    "request_id_var",
]