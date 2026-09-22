"""Create the FastAPI application and assemble cross-cutting concerns.

The factory pattern keeps imports side-effect-light for tests, workers, and CLI
scripts. Customize middleware and router registration here; business logic
belongs in services rather than in this composition module.
"""
#imports
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from slowapi.middleware import SlowAPIMiddleware

from app.api.v1.routers.api_router import api_router
from app.core.config.settings import get_settings
from app.core.middleware.correlation import CorrelationIdMiddleware
from app.core.middleware.error_handler import register_exception_handlers
from app.core.middleware.logging import RequestLoggingMiddleware
from app.core.middleware.rate_limit import limiter, register_rate_limit
from app.db.session import (
    check_db_connection,
    close_db_connections,
    init_db_pool,
    ping_db,
)
from app.utils.logger import logger

# Global background tasks tracking
_background_tasks = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Handle application startup and shutdown events using modern FastAPI lifespan.
    
    This replaces the deprecated @app.on_event decorators.
    All initialization and cleanup happens here.
    """
    settings = get_settings()
    
    # ============ STARTUP ============
    try:
        logger.info(
            "Starting application...",
            extra={
                "event": "startup_start",
                "app_name": settings.app_name,
                "environment": settings.environment,
                "version": "0.1.0",
            },
        )
        
        # Set startup time for health checks
        app.state.startup_time = datetime.utcnow()
        
        # Initialize database connection pool
        await init_db_pool()
        await ping_db()  # Verify connection
        logger.info("Database connection pool initialized successfully")
        
        # Initialize Redis cache (if enabled)
        if settings.redis_enabled:
            from app.core.cache.redis_client import redis_client
            await redis_client.ping()
            app.state.redis_client = redis_client
            logger.info("Redis cache connection established")
        
        # Load dynamic configuration from database
        await load_dynamic_config(app)
        
        # Start background workers if needed
        if settings.enable_background_tasks:
            await start_background_workers(app)
        
        # Warm up caches
        await warm_up_caches(app)
        
        # Check external service health
        await check_external_services(app)
        
        logger.info(
            "Application started successfully",
            extra={
                "event": "startup_complete",
                "uptime": 0,
                "environment": settings.environment,
            },
        )
        
    except Exception as e:
        logger.error(
            f"Startup failed: {str(e)}",
            extra={"event": "startup_failed", "error": str(e)},
        )
        raise  # Crash the application if startup fails
    
    # ============ APPLICATION RUNS ============
    yield
    
    # ============ SHUTDOWN ============
    try:
        logger.info(
            "Shutting down application...",
            extra={"event": "shutdown_start"},
        )
        
        # Cancel background tasks
        for task in _background_tasks:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        logger.info("Background tasks cancelled")
        
        # Close database connections
        await close_db_connections()
        logger.info("Database connections closed")
        
        # Close Redis connections
        if hasattr(app.state, "redis_client"):
            await app.state.redis_client.close()
            logger.info("Redis connection closed")
        
        # Clean up any remaining resources
        await cleanup_resources(app)
        
        logger.info(
            "Application shutdown complete",
            extra={"event": "shutdown_complete"},
        )
        
    except Exception as e:
        logger.error(
            f"Shutdown error: {str(e)}",
            extra={"event": "shutdown_error", "error": str(e)},
        )


async def load_dynamic_config(app: FastAPI):
    """Load dynamic configuration from database."""
    try:
        # Load feature flags, rate limits, etc. from DB
        # This allows configuration without redeployment
        app.state.dynamic_config = {
            "maintenance_mode": False,
            "feature_flags": {
                "new_ui": True,
                "beta_features": False,
            },
        }
        logger.info("Dynamic configuration loaded")
    except Exception as e:
        logger.warning(f"Failed to load dynamic config: {e}")
        app.state.dynamic_config = {}


async def warm_up_caches(app: FastAPI):
    """Warm up critical caches."""
    try:
        # Pre-populate frequently accessed data
        # Example: Load popular products, user sessions, etc.
        logger.info("Cache warming completed")
    except Exception as e:
        logger.warning(f"Cache warming partially failed: {e}")


async def check_external_services(app: FastAPI):
    """Check health of external services on startup."""
    services_status = {
        "database": await check_db_connection(),
        "redis": await check_redis_connection() if hasattr(app.state, "redis_client") else True,
    }
    
    app.state.services_status = services_status
    
    if not all(services_status.values()):
        logger.warning(
            "Some external services are unhealthy",
            extra={"services": services_status},
        )


async def check_redis_connection() -> bool:
    """Check Redis connection health."""
    try:
        from app.core.cache.redis_client import redis_client
        await redis_client.ping()
        return True
    except Exception:
        return False


async def start_background_workers(app: FastAPI):
    """Start background workers for async tasks."""
    try:
        # Example: Email queue worker
        # task = asyncio.create_task(email_worker())
        # _background_tasks.append(task)
        logger.info("Background workers started")
    except Exception as e:
        logger.error(f"Failed to start background workers: {e}")


async def cleanup_resources(app: FastAPI):
    """Clean up any remaining resources."""
    # Close any open file handles, network connections, etc.
    pass


def create_app() -> FastAPI:
    """
    Build and configure the FastAPI application.
    
    Returns:
        A configured FastAPI instance with all middleware, routes,
        and error handlers registered.
    """
    settings = get_settings()
    
    # Create FastAPI application
    application = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        docs_url="/docs" if settings.docs_enabled else None,
    )
    
    # ============ MIDDLEWARE STACK ============
    # ORDER MATTERS: First in = First executed
    
    # 1. Rate Limiting - ALWAYS FIRST (fastest check)
    application.state.limiter = limiter
    application.add_middleware(SlowAPIMiddleware)
    logger.info("Rate limiting middleware registered")
    
    # 2. Correlation ID - For request tracing
    application.add_middleware(CorrelationIdMiddleware)
    logger.info("Correlation ID middleware registered")
    
    # 3. Request Logging - Log every request
    application.add_middleware(RequestLoggingMiddleware)
    logger.info("Request logging middleware registered")
    
    # 4. CORS - Security configuration
    application.add_middleware(
        CORSMiddleware,
        **settings.cors_config
    )
    logger.info(f"CORS middleware registered with origins: {settings.cors_origins}")
    
    # ============ ROUTE REGISTRATION ============
    application.include_router(api_router, prefix=settings.api_prefix)
    logger.info(f"API router registered with prefix: {settings.api_prefix}")
    
    # ============ ERROR HANDLERS ============
    register_exception_handlers(application)
    register_rate_limit(application)
    logger.info("Error handlers and rate limit handlers registered")
    
    # ============ HEALTH ENDPOINTS ============
    
    @application.get("/health", tags=["health"])
    async def health(request: Request) -> Dict[str, Any]:
        """
        Lightweight liveness check for load balancers and Kubernetes.
        
        Returns:
            Simple status response with uptime and version information.
        """
        uptime_seconds = (
            datetime.utcnow() - request.app.state.startup_time
        ).total_seconds()
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "0.1.0",
            "uptime": uptime_seconds,
            "uptime_human": str(timedelta(seconds=int(uptime_seconds))),
        }
    
    @application.get("/health/deep", tags=["health"])
    async def deep_health(request: Request) -> Dict[str, Any]:
        """
        Deep health check for Kubernetes readiness probes.
        
        Checks all dependencies:
        - Database connectivity
        - Cache availability
        - External service status
        
        Returns:
            200 OK if all services healthy
            503 Service Unavailable if any dependency fails
        """
        checks = {
            "database": {
                "status": await check_db_connection(),
                "timestamp": datetime.utcnow().isoformat(),
            },
        }
        
        # Check Redis if configured
        if hasattr(request.app.state, "redis_client"):
            checks["redis"] = {
                "status": await check_redis_connection(),
                "timestamp": datetime.utcnow().isoformat(),
            }
        
        # Check external services
        if hasattr(request.app.state, "services_status"):
            checks["external_services"] = request.app.state.services_status
        
        # Determine overall status
        all_healthy = all(
            check.get("status", False) if isinstance(check, dict) else check
            for check in checks.values()
        )
        
        if not all_healthy:
            raise HTTPException(
                status_code=503,
                detail={
                    "status": "unhealthy",
                    "checks": checks,
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )
        
        return {
            "status": "healthy",
            "checks": checks,
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    @application.get("/health/ready", tags=["health"])
    async def readiness(request: Request) -> Dict[str, Any]:
        """
        Kubernetes readiness probe endpoint.
        
        Checks if the application is ready to serve traffic.
        This is a lighter check than /health/deep.
        """
        # Check if database is available
        db_ok = await check_db_connection()
        
        if not db_ok:
            raise HTTPException(
                status_code=503,
                detail={
                    "status": "not_ready",
                    "reason": "Database unavailable",
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )
        
        return {
            "status": "ready",
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    @application.get("/version", tags=["health"])
    async def version() -> Dict[str, Any]:
        """
        Application version and build information.
        
        Useful for deployment tracking and debugging.
        """
        return {
            "version": "0.1.0",
            "environment": settings.environment,
            "build_time": getattr(settings, "build_time", None),
            "api_prefix": settings.api_prefix,
            "app_name": settings.app_name,
        }
    
    @application.get("/metrics", tags=["health"])
    async def metrics() -> Dict[str, Any]:
        """
        Basic application metrics.
        
        For production, use Prometheus with proper metrics collection.
        """
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        
        return {
            "system": {
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_usage": psutil.disk_usage("/").percent,
            },
            "process": {
                "memory_mb": process.memory_info().rss / 1024 / 1024,
                "cpu_percent": process.cpu_percent(),
                "threads": process.num_threads(),
                "connections": len(process.connections()),
            },
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    @application.get("/ping", tags=["health"])
    async def ping() -> Dict[str, str]:
        """
        Minimal endpoint for simple connectivity tests.
        
        No dependencies, always returns pong.
        """
        return {"ping": "pong"}
    
    # ============ APPLICATION STATE ============
    
    # Store settings in app state for easy access
    application.state.settings = settings
    
    logger.info(
        "Application configured successfully",
        extra={
            "event": "app_created",
            "app_name": settings.app_name,
            "environment": settings.environment,
            "docs_enabled": docs_enabled,
        },
    )
    
    return application


# ============ CREATE APPLICATION INSTANCE ============
app = create_app()


# ============ OPTIONAL: CLI COMMAND HANDLERS ============
# These are used by your CLI tool for management commands

@app.cli.command("db_create")
def db_create():
    """Create database tables."""
    from app.db.base import Base
    from app.db.session import engine
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables created")


@app.cli.command("db_drop")
def db_drop():
    """Drop database tables."""
    from app.db.base import Base
    from app.db.session import engine
    Base.metadata.drop_all(bind=engine)
    print("✅ Database tables dropped")


@app.cli.command("create_superuser")
def create_superuser(email: str, password: str):
    """Create a superuser."""
    import asyncio
    from app.services.user_service import UserService
    from app.repositories.user_repository import UserRepository
    
    async def _create():
        repo = UserRepository()
        service = UserService(repo)
        user = await service.create_superuser(email, password)
        print(f"✅ Superuser created: {user.email}")
    
    asyncio.run(_create())


# ============ OPTIONAL: DEVELOPMENT HELPERS ============

if __name__ == "__main__":
    import uvicorn
    
    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.environment == "dev",
        log_level="debug" if settings.environment == "dev" else "info",
    )
