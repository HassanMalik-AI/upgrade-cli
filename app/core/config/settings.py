"""
Validated environment configuration for every runtime component.

Pydantic Settings reads environment variables and an optional ``.env`` file,
making deployments twelve-factor friendly. Change defaults here only for safe
local development; production secrets must come from a secret manager.
"""

from functools import lru_cache
from typing import Any, Dict, List, Optional, Union
import json
import os

from pydantic import (
    AliasChoices,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with validation and conservative security defaults."""

    # ============================================================
    # YOUR EXISTING FIELDS (PRESERVED AS-IS)
    # ============================================================

    app_name: str = Field(
        default="Hinbert FastAPI",
        validation_alias=AliasChoices("APP_NAME", "HINBERT_APP_NAME")
    )
    api_prefix: str = "/api/v1"
    environment: str = Field(
        default="development",
        validation_alias=AliasChoices("ENVIRONMENT", "HINBERT_ENVIRONMENT")
    )
    database_url: str = Field(
        default="postgresql+asyncpg://postgres:postgres@localhost:5432/app",
        validation_alias=AliasChoices("DATABASE_URL", "HINBERT_DATABASE_URL"),
    )
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        validation_alias=AliasChoices("REDIS_URL", "HINBERT_REDIS_URL")
    )
    debug: bool = Field(
        default=False,
        validation_alias=AliasChoices("DEBUG", "HINBERT_DEBUG")
    )
    jwt_secret_key: SecretStr = Field(
        default=SecretStr("change-me-in-production"),
        validation_alias=AliasChoices("SECRET_KEY", "HINBERT_JWT_SECRET_KEY"),
    )
    jwt_algorithm: str = Field(
        default="HS256",
        validation_alias=AliasChoices("ALGORITHM", "HINBERT_JWT_ALGORITHM")
    )
    access_token_minutes: int = Field(
        default=15,
        validation_alias=AliasChoices("ACCESS_TOKEN_EXPIRE_MINUTES", "HINBERT_ACCESS_TOKEN_MINUTES")
    )
    refresh_token_days: int = Field(
        default=30,
        validation_alias=AliasChoices("REFRESH_TOKEN_EXPIRE_DAYS", "HINBERT_REFRESH_TOKEN_DAYS")
    )
    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:3000"],
        validation_alias=AliasChoices("BACKEND_CORS_ORIGINS", "HINBERT_CORS_ORIGINS"),
    )
    smtp_host: str = Field(
        default="localhost",
        validation_alias=AliasChoices("SMTP_HOST", "HINBERT_SMTP_HOST")
    )
    smtp_port: int = Field(
        default=587,
        validation_alias=AliasChoices("SMTP_PORT", "HINBERT_SMTP_PORT")
    )
    smtp_username: str = Field(
        default="",
        validation_alias=AliasChoices("SMTP_USER", "HINBERT_SMTP_USERNAME")
    )
    smtp_password: SecretStr = Field(
        default=SecretStr(""),
        validation_alias=AliasChoices("SMTP_PASSWORD", "HINBERT_SMTP_PASSWORD")
    )
    smtp_from: str = Field(
        default="no-reply@example.com",
        validation_alias=AliasChoices("EMAIL_FROM", "HINBERT_SMTP_FROM")
    )
    google_client_id: str = Field(
        default="",
        validation_alias=AliasChoices("GOOGLE_CLIENT_ID", "HINBERT_GOOGLE_CLIENT_ID")
    )
    google_client_secret: SecretStr = Field(
        default=SecretStr(""),
        validation_alias=AliasChoices("GOOGLE_CLIENT_SECRET", "HINBERT_GOOGLE_CLIENT_SECRET")
    )
    facebook_client_id: str = Field(
        default="",
        validation_alias=AliasChoices("FACEBOOK_CLIENT_ID", "HINBERT_FACEBOOK_CLIENT_ID")
    )
    facebook_client_secret: SecretStr = Field(
        default=SecretStr(""),
        validation_alias=AliasChoices("FACEBOOK_CLIENT_SECRET", "HINBERT_FACEBOOK_CLIENT_SECRET")
    )
    rate_limit: str = Field(
        default="100/minute",
        validation_alias=AliasChoices("RATE_LIMIT_PER_MINUTE", "HINBERT_RATE_LIMIT")
    )

    # ============================================================
    # ADDITIONAL PROFESSIONAL FIELDS (Optional)
    # ============================================================

    app_version: str = Field(
        default="0.1.0",
        description="Application version",
        validation_alias=AliasChoices("APP_VERSION", "HINBERT_APP_VERSION"),
    )

    base_url: str = Field(
        default="http://localhost:8000",
        description="Public-facing application URL",
        validation_alias=AliasChoices("BASE_URL", "HINBERT_BASE_URL"),
    )

    database_pool_size: int = Field(
        default=10,
        description="Database connection pool size",
        validation_alias=AliasChoices("DB_POOL_SIZE", "HINBERT_DB_POOL_SIZE"),
    )

    database_max_overflow: int = Field(
        default=20,
        description="Max overflow connections",
        validation_alias=AliasChoices("DB_MAX_OVERFLOW", "HINBERT_DB_MAX_OVERFLOW"),
    )

    database_pool_timeout: int = Field(
        default=30,
        description="Connection pool timeout in seconds",
        validation_alias=AliasChoices("DB_POOL_TIMEOUT", "HINBERT_DB_POOL_TIMEOUT"),
    )

    redis_cache_ttl: int = Field(
        default=3600,
        description="Default cache TTL in seconds",
        validation_alias=AliasChoices("REDIS_CACHE_TTL", "HINBERT_REDIS_CACHE_TTL"),
    )

    redis_session_ttl: int = Field(
        default=86400,
        description="Session TTL in seconds (24 hours)",
        validation_alias=AliasChoices("REDIS_SESSION_TTL", "HINBERT_REDIS_SESSION_TTL"),
    )

    log_level: str = Field(
        default="INFO",
        description="Logging level",
        validation_alias=AliasChoices("LOG_LEVEL", "HINBERT_LOG_LEVEL"),
    )

    log_json: bool = Field(
        default=False,
        description="Enable JSON structured logging",
        validation_alias=AliasChoices("LOG_JSON", "HINBERT_LOG_JSON"),
    )

    sentry_dsn: Optional[str] = Field(
        default=None,
        description="Sentry DSN for error tracking",
        validation_alias=AliasChoices("SENTRY_DSN", "HINBERT_SENTRY_DSN"),
    )

    enable_2fa: bool = Field(
        default=True,
        description="Enable 2FA/TOTP",
        validation_alias=AliasChoices("ENABLE_2FA", "HINBERT_ENABLE_2FA"),
    )

    enable_email_verification: bool = Field(
        default=True,
        description="Enable email verification",
        validation_alias=AliasChoices("ENABLE_EMAIL_VERIFICATION", "HINBERT_ENABLE_EMAIL_VERIFICATION"),
    )

    default_page_size: int = Field(
        default=20,
        description="Default items per page",
        validation_alias=AliasChoices("DEFAULT_PAGE_SIZE", "HINBERT_DEFAULT_PAGE_SIZE"),
    )

    max_page_size: int = Field(
        default=100,
        description="Maximum items per page",
        validation_alias=AliasChoices("MAX_PAGE_SIZE", "HINBERT_MAX_PAGE_SIZE"),
    )

    # ============================================================
    # PYDANTIC MODEL CONFIGURATION (PRESERVED)
    # ============================================================

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="",
        extra="ignore",
        env_file_encoding="utf-8",
        case_sensitive=False,
        validate_default=True,
    )

    # ============================================================
    # YOUR EXISTING VALIDATORS (PRESERVED)
    # ============================================================

    @field_validator("jwt_secret_key")
    @classmethod
    def reject_weak_production_secret(cls, value: SecretStr) -> SecretStr:
        """Prevent the documented development secret from reaching production."""
        secret = value.get_secret_value()
        if secret == "change-me-in-production" or len(secret) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters and must not use the default value")
        return value

    # ============================================================
    # ADDITIONAL PROFESSIONAL VALIDATORS
    # ============================================================

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, value: str) -> str:
        """Validate environment is one of allowed values."""
        allowed = {"development", "staging", "production", "test"}
        if value.lower() not in allowed:
            raise ValueError(
                f"Environment must be one of: {', '.join(allowed)}"
            )
        return value.lower()

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, value: str) -> str:
        """Validate database URL uses supported dialect."""
        supported = ["postgresql", "mysql", "sqlite"]
        if not any(value.startswith(f"{dialect}+") or value.startswith(f"{dialect}://") 
                   for dialect in supported):
            raise ValueError(
                f"Database URL must use supported dialect: {', '.join(supported)}"
            )
        return value

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        """Validate log level is one of allowed values."""
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if value.upper() not in allowed:
            raise ValueError(
                f"LOG_LEVEL must be one of: {', '.join(allowed)}"
            )
        return value.upper()

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, value: Union[str, List[str]]) -> List[str]:
        """
        Parse CORS origins from string or list.
        
        Supports:
        - JSON array: '["http://localhost:3000"]'
        - Comma-separated: 'http://localhost:3000,https://example.com'
        - Already list: ['http://localhost:3000']
        """
        if isinstance(value, str):
            # Try JSON parsing first
            try:
                parsed = json.loads(value)
                if isinstance(parsed, list):
                    return parsed
            except json.JSONDecodeError:
                pass
            
            # Fallback to comma-separated
            if "," in value:
                return [item.strip() for item in value.split(",") if item.strip()]
            
            # Single value
            return [value.strip()]
        
        return value or []

    # ============================================================
    # CROSS-FIELD VALIDATORS
    # ============================================================

    @model_validator(mode="after")
    def validate_environment_consistency(self) -> "Settings":
        """Ensure consistent configuration for the current environment."""
        if self.is_production and self.debug:
            raise ValueError(
                "DEBUG mode cannot be enabled in production environment"
            )
        return self

    @model_validator(mode="after")
    def validate_oauth_config(self) -> "Settings":
        """Validate OAuth configuration if enabled."""
        if self.google_client_id and not self.google_client_secret.get_secret_value():
            raise ValueError(
                "GOOGLE_CLIENT_SECRET must be set when GOOGLE_CLIENT_ID is provided"
            )
        if self.facebook_client_id and not self.facebook_client_secret.get_secret_value():
            raise ValueError(
                "FACEBOOK_CLIENT_SECRET must be set when FACEBOOK_CLIENT_ID is provided"
            )
        return self

    # ============================================================
    # COMPUTED PROPERTIES - FOR CLEANER main.py INTEGRATION
    # ============================================================

    @property
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.environment.lower() == "development"

    @property
    def is_staging(self) -> bool:
        """Check if running in staging environment."""
        return self.environment.lower() == "staging"

    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment.lower() == "production"

    @property
    def is_test(self) -> bool:
        """Check if running in test environment."""
        return self.environment.lower() == "test"

    @property
    def docs_enabled(self) -> bool:
        """Check if API documentation should be available."""
        return not self.is_production

    @property
    def async_database_url(self) -> str:
        """Get async database URL with correct driver."""
        if "postgresql://" in self.database_url and "+asyncpg" not in self.database_url:
            return self.database_url.replace("postgresql://", "postgresql+asyncpg://")
        return self.database_url

    @property
    def sync_database_url(self) -> str:
        """Get sync database URL without async driver."""
        if "+asyncpg" in self.database_url:
            return self.database_url.replace("+asyncpg", "")
        return self.database_url

    @property
    def is_debug(self) -> bool:
        """Check if debug mode is enabled."""
        return self.debug and self.is_development

    # ============================================================
    # CONFIGURATION DICTIONARIES - FOR CLEANER main.py INTEGRATION
    # ============================================================

    @property
    def cors_config(self) -> Dict[str, Any]:
        """Get CORS configuration dictionary."""
        return {
            "allow_origins": self.cors_origins,
            "allow_credentials": True,
            "allow_methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            "allow_headers": [
                "Authorization",
                "Content-Type",
                "X-Correlation-ID",
            ],
            "expose_headers": ["X-Correlation-ID"],
            "max_age": 3600,
        }

    @property
    def db_connection_options(self) -> Dict[str, Any]:
        """Get database connection options."""
        return {
            "pool_size": self.database_pool_size,
            "max_overflow": self.database_max_overflow,
            "pool_timeout": self.database_pool_timeout,
            "echo": self.debug and self.is_development,
            "pool_pre_ping": True,  # Check connection before using
        }

    @property
    def jwt_config(self) -> Dict[str, Any]:
        """Get JWT configuration dictionary."""
        return {
            "secret_key": self.jwt_secret_key,
            "algorithm": self.jwt_algorithm,
            "access_token_expire_minutes": self.access_token_minutes,
            "refresh_token_expire_days": self.refresh_token_days,
        }

    @property
    def redis_config(self) -> Dict[str, Any]:
        """Get Redis configuration dictionary."""
        return {
            "url": self.redis_url,
            "cache_ttl": self.redis_cache_ttl,
            "session_ttl": self.redis_session_ttl,
        }

    @property
    def feature_flags(self) -> Dict[str, bool]:
        """Get all feature flags as a dictionary."""
        return {
            "2fa": self.enable_2fa,
            "email_verification": self.enable_email_verification,
        }

    @property
    def rate_limits(self) -> Dict[str, str]:
        """Get rate limit configurations."""
        return {
            "default": self.rate_limit,
            "auth": "5/minute",  # Can be made configurable
            "api": "1000/minute",  # Can be made configurable
        }

    # ============================================================
    # UTILITY METHODS
    # ============================================================

    def is_feature_enabled(self, feature: str) -> bool:
        """Check if a specific feature is enabled."""
        return self.feature_flags.get(feature, False)

    def get_rate_limit(self, endpoint_type: str = "default") -> str:
        """Get rate limit for a specific endpoint type."""
        return self.rate_limits.get(endpoint_type, self.rate_limit)

    def model_dump(self, **kwargs) -> Dict[str, Any]:
        """
        Override model_dump to hide secrets by default.
        
        This prevents accidentally logging sensitive information.
        """
        if "exclude" not in kwargs:
            kwargs["exclude"] = {
                "jwt_secret_key": True,
                "smtp_password": True,
                "google_client_secret": True,
                "facebook_client_secret": True,
            }
        return super().model_dump(**kwargs)

    def get_secret(self, key: str) -> Optional[str]:
        """
        Get a secret value from the environment.
        
        Args:
            key: The secret key to retrieve
            
        Returns:
            The secret value as a string, or None if not found
        """
        value = getattr(self, key, None)
        if isinstance(value, SecretStr):
            return value.get_secret_value()
        return value


# ============================================================
# SETTINGS CACHE (PRESERVED)
# ============================================================

@lru_cache
def get_settings() -> Settings:
    """Return one cached, validated settings object per process."""
    return Settings()


# ============================================================
# DEVELOPMENT HELPER (Optional)
# ============================================================

if __name__ == "__main__":
    """Print settings for debugging when run directly."""
    settings = get_settings()
    
    print("=" * 80)
    print("APPLICATION CONFIGURATION")
    print("=" * 80)
    
    print(f"\n📦 App: {settings.app_name} v{settings.app_version}")
    print(f"🌍 Environment: {settings.environment.upper()}")
    print(f"🐞 Debug: {'✅' if settings.debug else '❌'}")
    print(f"📚 Docs: {'✅' if settings.docs_enabled else '❌'}")
    print(f"📊 Database: {settings.database_url.split('@')[-1] if '@' in settings.database_url else settings.database_url}")
    print(f"⚡ Redis: {settings.redis_url}")
    print(f"🔒 JWT Algorithm: {settings.jwt_algorithm}")
    print(f"⏱️  Access Token: {settings.access_token_minutes} minutes")
    print(f"🔁 Refresh Token: {settings.refresh_token_days} days")
    print(f"📧 Email: {settings.smtp_from} ({settings.smtp_host}:{settings.smtp_port})")
    print(f"🌐 CORS: {settings.cors_origins}")
    
    print("\n🚩 Feature Flags:")
    for flag, enabled in settings.feature_flags.items():
        print(f"   {flag}: {'✅' if enabled else '❌'}")
    
    print("\n" + "=" * 80)
    print("✅ Configuration loaded successfully")