"""
OAuth provider configuration boundary.

Provider exchange logic belongs in ``social_auth_service`` so credentials and
HTTP clients can be mocked in tests. Add provider-specific scopes and callback
URLs there without coupling the rest of the application to an SDK.

This module ONLY defines configuration. It does NOT:
- Make HTTP requests to providers
- Exchange authorization codes
- Fetch user profiles
- Handle redirects

That logic lives in ``social_auth_service`` where it can be:
- Tested in isolation
- Mocked for unit tests
- Swapped without affecting configuration
- Versioned independently

Design Principles:
- Configuration as data (no logic here)
- Provider-agnostic interface
- Secrets from settings (never hardcoded)
- Extensible for new providers
- Testable through service layer

Why separate config from service:
1. Configuration rarely changes; logic does
2. Credentials come from environment (settings)
3. Services are easier to test than modules
4. Clear separation of concerns
5. Reusable across multiple services
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from app.core.config.settings import get_settings
from app.utils.logger import logger


# ============================================================
# PROVIDER TYPES
# ============================================================

class OAuthProvider(str, Enum):
    """
    Supported OAuth providers.
    
    Using str enum means:
    - Values are strings (JSON serializable)
    - Type-safe in code
    - IDE autocomplete works
    - Can compare with strings
    """
    GOOGLE = "google"
    FACEBOOK = "facebook"
    
    @classmethod
    def is_supported(cls, provider: str) -> bool:
        """Check if a provider is supported."""
        return provider.lower() in {p.value for p in cls}
    
    @classmethod
    def all_providers(cls) -> list[str]:
        """Get list of all supported provider names."""
        return [p.value for p in cls]


# Backward compatibility with the original tuple
SUPPORTED_PROVIDERS = tuple(p.value for p in OAuthProvider)


# ============================================================
# PROVIDER CONFIGURATION (Data Classes)
# ============================================================

@dataclass(frozen=True)
class OAuthProviderConfig:
    """
    Immutable configuration for a single OAuth provider.
    
    Frozen dataclass ensures configuration cannot be accidentally
    modified at runtime. If changes are needed, create a new instance.
    
    Attributes:
        name: Provider identifier (google, facebook, etc.)
        client_id: Public identifier for OAuth app
        client_secret: Private secret (from settings)
        authorize_url: URL where user is redirected to authorize
        token_url: URL to exchange code for access token
        userinfo_url: URL to fetch user profile
        scopes: Required scopes for authentication
        redirect_uri: Where provider sends user after auth
        is_enabled: Whether this provider is configured and usable
    """
    
    # Required fields
    name: str
    client_id: str
    client_secret: str
    authorize_url: str
    token_url: str
    userinfo_url: str
    scopes: list[str]
    redirect_uri: str
    
    # Optional fields with defaults
    is_enabled: bool = False
    
    # Additional provider-specific configuration
    extra_params: dict = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        if not self.name:
            raise ValueError("Provider name is required")
        if not self.authorize_url:
            raise ValueError(f"{self.name}: authorize_url is required")
        if not self.token_url:
            raise ValueError(f"{self.name}: token_url is required")
        if not self.userinfo_url:
            raise ValueError(f"{self.name}: userinfo_url is required")
    
    @property
    def is_configured(self) -> bool:
        """Check if provider has required credentials."""
        return bool(
            self.client_id 
            and self.client_secret 
            and self.redirect_uri
        )
    
    def to_dict(self, include_secrets: bool = False) -> dict:
        """
        Convert to dictionary (safe for logging).
        
        Args:
            include_secrets: Include client_secret (never True in prod)
        """
        data = {
            "name": self.name,
            "client_id": self.client_id[:8] + "..." if self.client_id else None,
            "authorize_url": self.authorize_url,
            "token_url": self.token_url,
            "userinfo_url": self.userinfo_url,
            "scopes": self.scopes,
            "redirect_uri": self.redirect_uri,
            "is_enabled": self.is_enabled,
            "is_configured": self.is_configured,
        }
        if include_secrets:
            data["client_secret"] = self.client_secret
        return data


# ============================================================
# PROVIDER REGISTRY
# ============================================================

class OAuthRegistry:
    """
    Registry of OAuth provider configurations.
    
    Loads configuration from settings and provides:
    - Access to provider configs
    - Enable/disable based on credentials
    - Type-safe provider access
    - Testing support (can be reset)
    
    Usage:
        registry = OAuthRegistry()
        
        # Get provider config
        google = registry.get("google")
        
        # Check if enabled
        if registry.is_enabled("google"):
            ...
        
        # List all enabled providers
        providers = registry.enabled_providers()
    """
    
    def __init__(self):
        """Initialize registry by loading settings."""
        self._settings = get_settings()
        self._providers: dict[str, OAuthProviderConfig] = {}
        self._load_providers()
    
    def _load_providers(self) -> None:
        """Load all provider configurations from settings."""
        # Load Google
        self._providers[OAuthProvider.GOOGLE.value] = OAuthProviderConfig(
            name=OAuthProvider.GOOGLE.value,
            client_id=self._settings.google_client_id,
            client_secret=self._settings.google_client_secret.get_secret_value(),
            authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token",
            userinfo_url="https://www.googleapis.com/oauth2/v2/userinfo",
            scopes=[
                "openid",
                "email",
                "profile",
            ],
            redirect_uri=f"{self._settings.base_url}{self._settings.api_prefix}/auth/google/callback",
            is_enabled=bool(self._settings.google_client_id),
            extra_params={
                "access_type": "offline",  # For refresh token
                "prompt": "consent",       # Force consent for refresh
            },
        )
        
        # Load Facebook
        self._providers[OAuthProvider.FACEBOOK.value] = OAuthProviderConfig(
            name=OAuthProvider.FACEBOOK.value,
            client_id=self._settings.facebook_client_id,
            client_secret=self._settings.facebook_client_secret.get_secret_value(),
            authorize_url="https://www.facebook.com/v18.0/dialog/oauth",
            token_url="https://graph.facebook.com/v18.0/oauth/access_token",
            userinfo_url="https://graph.facebook.com/me",
            scopes=[
                "email",
                "public_profile",
            ],
            redirect_uri=f"{self._settings.base_url}{self._settings.api_prefix}/auth/facebook/callback",
            is_enabled=bool(self._settings.facebook_client_id),
            extra_params={
                "fields": "id,name,email,picture",  # Fields to fetch
            },
        )
        
        # Log loaded providers
        enabled = [p.name for p in self._providers.values() if p.is_enabled]
        logger.info(
            f"OAuth registry loaded",
            extra={
                "event": "oauth_registry_loaded",
                "providers": list(self._providers.keys()),
                "enabled": enabled,
            }
        )
    
    def get(self, provider: str) -> OAuthProviderConfig:
        """
        Get configuration for a specific provider.
        
        Args:
            provider: Provider name (google, facebook)
            
        Returns:
            Provider configuration
            
        Raises:
            ValueError: If provider is not supported
        """
        provider_lower = provider.lower()
        if provider_lower not in self._providers:
            raise ValueError(
                f"Unsupported provider: {provider}. "
                f"Supported: {list(self._providers.keys())}"
            )
        return self._providers[provider_lower]
    
    def is_enabled(self, provider: str) -> bool:
        """Check if provider is enabled and configured."""
        try:
            config = self.get(provider)
            return config.is_enabled and config.is_configured
        except ValueError:
            return False
    
    def enabled_providers(self) -> list[str]:
        """Get list of enabled provider names."""
        return [
            name for name, config in self._providers.items()
            if config.is_enabled and config.is_configured
        ]
    
    def all_providers(self) -> list[str]:
        """Get list of all registered provider names."""
        return list(self._providers.keys())
    
    def reset(self) -> None:
        """Reset registry (for testing)."""
        self._providers.clear()
        self._load_providers()


# ============================================================
# SINGLETON REGISTRY
# ============================================================

_registry: Optional[OAuthRegistry] = None


def get_oauth_registry() -> OAuthRegistry:
    """
    Get the singleton OAuth registry.
    
    Creates on first call, reuses on subsequent calls.
    This ensures configuration is loaded only once.
    
    Returns:
        OAuthRegistry instance
    """
    global _registry
    if _registry is None:
        _registry = OAuthRegistry()
    return _registry


# ============================================================
# CONVENIENCE FUNCTIONS
# ============================================================

def get_provider_config(provider: str) -> OAuthProviderConfig:
    """
    Get configuration for a provider.
    
    Convenience function that uses the singleton registry.
    
    Args:
        provider: Provider name
        
    Returns:
        Provider configuration
    """
    return get_oauth_registry().get(provider)


def is_provider_enabled(provider: str) -> bool:
    """Check if a provider is enabled and configured."""
    return get_oauth_registry().is_enabled(provider)


def get_enabled_providers() -> list[str]:
    """Get list of enabled provider names."""
    return get_oauth_registry().enabled_providers()


def is_provider_supported(provider: str) -> bool:
    """Check if a provider is supported (regardless of configuration)."""
    return OAuthProvider.is_supported(provider)


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    # Types
    "OAuthProvider",
    "OAuthProviderConfig",
    
    # Registry
    "OAuthRegistry",
    "get_oauth_registry",
    
    # Convenience functions
    "get_provider_config",
    "is_provider_enabled",
    "get_enabled_providers",
    "is_provider_supported",
    
    # Backward compatibility
    "SUPPORTED_PROVIDERS",
]