"""Central Loguru configuration with rotation and retention.

Applications may replace the sink in one place to integrate with a managed
logging platform. Never log passwords, bearer tokens, or reset links.
"""
from app.core.config.settings import get_settings
from loguru import logger

logger.remove()
logger.add("logs/app.log", rotation="10 MB", retention="30 days", serialize=True, enqueue=True)
logger.add(lambda message: print(message, end=""), level="INFO")


# ============================================
# STEP 1: Remove default handler
# ============================================

logger.remove()

# ============================================
# STEP 2: Log configuration with DEBUG level for development
# ============================================
settings = get_settings()

logger.add(
    "logs/debug.log",
    rotation="10 MB",             # Rotate every 10 MB
    retention="7 days",           # Keep logs for 7 days
    level="DEBUG",                # Show DEBUG and above (includes INFO, WARNING, ERROR)
    enqueue=True,                 # Asynchronous logging (better performance)
    serialize=True,               # JSON format
    backtrace=True,
    diagnose=True,
)

# ============================================
# STEP 3: Production-ready JSON logging
# ============================================
logger.add(
    "logs/production.log",
    rotation="50 MB",             # Larger rotation for production
    retention="30 days",          # Longer retention
    level="INFO",                 # Production level (no DEBUG)
    enqueue=True,
    serialize=True,
    backtrace=True,
    diagnose=True,
)

# ============================================
# STEP 4: Console logging for development only
# ============================================
if settings.debug:
    logger.add(
        lambda msg: print(msg, end=""),
        level="DEBUG",
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | {level: <8} | {name}:{function}:{line} - <level>{message}</level>"
    )

logger.info("Logger configured successfully")
