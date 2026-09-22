"""
Social-login provider adapters for Google and Facebook.

This module provides the SocialAuthService class, which handles OAuth2
authentication flows for external identity providers. It normalizes
provider-specific user data into a common format.

Design Pattern: Adapter Pattern + Service Layer
    - Adapts provider-specific APIs to unified interface
    - Handles OAuth2 code exchange
    - Fetches user profile from provider
    - Normalizes provider data into common format
    - Creates/links local user accounts

Note:
    This file handles the business logic and HTTP exchange for social auth.
    For configuration and settings only, see `app/core/security/oauth.py`.
    They are separated to keep business logic distinct from configuration.

Responsibilities:
    - Exchange authorization codes for access tokens
    - Fetch user profiles from providers
    - Normalize provider-specific data
    - Handle provider-specific quirks (Facebook email, Google fields)
    - Validate required fields (email)
    - Create/link local user accounts
    - Handle account linking (existing email)
    - Error handling per provider

Design Principles:
    - Single Responsibility: OAuth exchange + profile fetch
    - Provider Adapters: Each provider has own adapter logic
    - Normalization: Common output format
    - Error Handling: Specific to each provider
    - Security: HTTPS, timeouts, validation

Security Notes:
    - Client secrets loaded from settings (never hardcoded)
    - Timeouts on all HTTP requests (prevent hangs)
    - HTTPS required for all provider communications
    - Email required (prevents account takeover)
    - Account linking validated (existing emails)
    - State parameter validation (CSRF) - handled in endpoints
    - Code exchange is one-time-use (per OAuth2 spec)

Architecture:
    Endpoint /auth/{provider}/callback
            ↓
    SocialAuthService.exchange_provider_code()
            ↓
    httpx.AsyncClient → Provider API
            ↓
    Normalized {email, full_name}
            ↓
    UserService.create_or_link_user()
            ↓
    Local User Account
"""

from dataclasses import dataclass
from typing import Optional

import httpx

from app.core.config.settings import get_settings
from app.utils.logger import logger


# ============================================================
# CONSTANTS
# ============================================================

# Supported providers
SUPPORTED_PROVIDERS = frozenset({"google", "facebook"})

# HTTP timeout (seconds)
DEFAULT_TIMEOUT = 10.0

# Provider URLs
GOOGLE_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"

FACEBOOK_AUTHORIZE_URL = "https://www.facebook.com/v19.0/dialog/oauth"
FACEBOOK_TOKEN_URL = "https://graph.facebook.com/v19.0/oauth/access_token"
FACEBOOK_USERINFO_URL = "https://graph.facebook.com/me"

# Default name for providers that don't return one
DEFAULT_FULL_NAME = "OAuth User"


# ============================================================
# DATA CLASSES
# ============================================================

@dataclass(frozen=True)
class OAuthUserInfo:
    """
    Normalized OAuth user information.
    
    All providers return different field names. This class
    provides a consistent interface regardless of source.
    
    Attributes:
        email: User's email address (required)
        full_name: User's display name (fallback if missing)
        provider: Which provider this came from
        provider_user_id: User's ID in the provider's system
        avatar_url: Optional avatar/profile picture URL
        email_verified: Whether provider confirms email (if available)
    """
    email: str
    full_name: str
    provider: str
    provider_user_id: Optional[str] = None
    avatar_url: Optional[str] = None
    email_verified: bool = False


# ============================================================
# SOCIAL AUTH SERVICE
# ============================================================

class SocialAuthService:
    """
    Service for social login (OAuth2) flows.
    
    This service handles:
    - OAuth2 authorization code exchange
    - User profile fetching from providers
    - Data normalization across providers
    - Error handling per provider
    
    Example:
        service = SocialAuthService()
        
        # Exchange code for user info
        user_info = await service.exchange_provider_code(
            provider="google",
            code="authorization_code",
        )
        # user_info = OAuthUserInfo(
        #     email="user@example.com",
        #     full_name="John Doe",
        #     provider="google",
        #     provider_user_id="1234567890",
        # )
    """
    
    def __init__(self, timeout: float = DEFAULT_TIMEOUT):
        """
        Initialize social auth service.
        
        Args:
            timeout: HTTP request timeout in seconds
        """
        self.settings = get_settings()
        self.timeout = timeout
    
    # ============================================================
    # MAIN ENTRY POINT
    # ============================================================
    
    async def exchange_provider_code(
        self,
        provider: str,
        code: str,
        redirect_uri: Optional[str] = None,
    ) -> OAuthUserInfo:
        """
        Exchange an authorization code for normalized provider user information.
        
        This is the main method for OAuth2 flow. It:
        1. Validates provider
        2. Exchanges code for access token
        3. Fetches user profile
        4. Normalizes response
        
        Args:
            provider: Provider name ("google" or "facebook")
            code: Authorization code from provider
            redirect_uri: Optional redirect URI (must match provider config)
            
        Returns:
            Normalized OAuthUserInfo
            
        Raises:
            ValueError: If provider unsupported or response invalid
            httpx.HTTPError: If HTTP request fails
            httpx.TimeoutException: If request times out
            
        Example:
            # In OAuth callback endpoint:
            try:
                user_info = await service.exchange_provider_code(
                    provider="google",
                    code=request.query_params["code"],
                )
                user = await user_service.find_or_create_oauth_user(user_info)
            except httpx.TimeoutException:
                raise HTTPException(504, "Provider timeout")
            except ValueError as e:
                raise HTTPException(400, str(e))
        """
        # Validate provider
        provider = provider.lower().strip()
        if provider not in SUPPORTED_PROVIDERS:
            raise ValueError(
                f"Unsupported provider: {provider}. "
                f"Supported: {', '.join(SUPPORTED_PROVIDERS)}"
            )
        
        if not code:
            raise ValueError("Authorization code is required")
        
        logger.info(
            "OAuth exchange started",
            extra={
                "event": "oauth_exchange_started",
                "provider": provider,
            }
        )
        
        # Dispatch to provider-specific handler
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=False,
            ) as client:
                if provider == "google":
                    user_info = await self._exchange_google(
                        client, code, redirect_uri
                    )
                elif provider == "facebook":
                    user_info = await self._exchange_facebook(
                        client, code, redirect_uri
                    )
                else:
                    # Should not reach here (validated above)
                    raise ValueError(f"Unsupported provider: {provider}")
        except httpx.TimeoutException:
            logger.warning(
                "OAuth exchange timeout",
                extra={
                    "event": "oauth_timeout",
                    "provider": provider,
                }
            )
            raise
        except httpx.HTTPStatusError as e:
            logger.error(
                "OAuth HTTP error",
                extra={
                    "event": "oauth_http_error",
                    "provider": provider,
                    "status_code": e.response.status_code,
                }
            )
            raise ValueError(
                f"OAuth provider error: {e.response.status_code}"
            ) from e
        except httpx.RequestError as e:
            logger.error(
                "OAuth request error",
                extra={
                    "event": "oauth_request_error",
                    "provider": provider,
                    "error_type": type(e).__name__,
                }
            )
            raise ValueError("OAuth provider unreachable") from e
        
        logger.info(
            "OAuth exchange completed",
            extra={
                "event": "oauth_exchange_completed",
                "provider": provider,
                "has_email": bool(user_info.email),
            }
        )
        
        return user_info
    
    # ============================================================
    # GOOGLE ADAPTER
    # ============================================================
    
    async def _exchange_google(
        self,
        client: httpx.AsyncClient,
        code: str,
        redirect_uri: Optional[str],
    ) -> OAuthUserInfo:
        """
        Exchange Google authorization code for user info.
        
        Flow:
        1. POST to token endpoint with code + credentials
        2. GET user info with Bearer access token
        3. Normalize response
        """
        # Step 1: Exchange code for access token
        token_data = {
            "code": code,
            "client_id": self.settings.google_client_id,
            "client_secret": self.settings.google_client_secret.get_secret_value(),
            "grant_type": "authorization_code",
        }
        
        if redirect_uri:
            token_data["redirect_uri"] = redirect_uri
        
        token_response = await client.post(GOOGLE_TOKEN_URL, data=token_data)
        token_response.raise_for_status()
        tokens = token_response.json()
        
        access_token = tokens.get("access_token")
        if not access_token:
            raise ValueError("Google did not return an access token")
        
        # Step 2: Fetch user info
        profile_response = await client.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        profile_response.raise_for_status()
        profile = profile_response.json()
        
        # Step 3: Normalize
        email = profile.get("email")
        if not email:
            raise ValueError("Google did not return an email address")
        
        return OAuthUserInfo(
            email=str(email).lower().strip(),
            full_name=(
                profile.get("name")
                or profile.get("given_name")
                or DEFAULT_FULL_NAME
            ).strip(),
            provider="google",
            provider_user_id=profile.get("sub"),
            avatar_url=profile.get("picture"),
            email_verified=bool(profile.get("email_verified", False)),
        )
    
    # ============================================================
    # FACEBOOK ADAPTER
    # ============================================================
    
    async def _exchange_facebook(
        self,
        client: httpx.AsyncClient,
        code: str,
        redirect_uri: Optional[str],
    ) -> OAuthUserInfo:
        """
        Exchange Facebook authorization code for user info.
        
        Flow:
        1. GET token endpoint with code + credentials
        2. GET user info with access token
        3. Normalize response
        """
        # Step 1: Exchange code for access token
        token_params = {
            "client_id": self.settings.facebook_client_id,
            "client_secret": self.settings.facebook_client_secret.get_secret_value(),
            "code": code,
        }
        
        if redirect_uri:
            token_params["redirect_uri"] = redirect_uri
        
        token_response = await client.get(
            FACEBOOK_TOKEN_URL,
            params=token_params,
        )
        token_response.raise_for_status()
        tokens = token_response.json()
        
        access_token = tokens.get("access_token")
        if not access_token:
            raise ValueError("Facebook did not return an access token")
        
        # Step 2: Fetch user info
        profile_response = await client.get(
            FACEBOOK_USERINFO_URL,
            params={
                "fields": "id,name,email,picture",
                "access_token": access_token,
            },
        )
        profile_response.raise_for_status()
        profile = profile_response.json()
        
        # Step 3: Normalize
        email = profile.get("email")
        if not email:
            # Facebook might not return email if:
            # - User denied email permission
            # - Email not confirmed on Facebook
            # - App not approved for email scope
            raise ValueError(
                "Facebook did not return an email address. "
                "Please ensure your Facebook account has a verified email "
                "and grant email permission during sign-in."
            )
        
        # Extract picture URL (nested object)
        avatar_url = None
        if profile.get("picture", {}).get("data", {}).get("url"):
            avatar_url = profile["picture"]["data"]["url"]
        
        return OAuthUserInfo(
            email=str(email).lower().strip(),
            full_name=(
                profile.get("name")
                or DEFAULT_FULL_NAME
            ).strip(),
            provider="facebook",
            provider_user_id=profile.get("id"),
            avatar_url=avatar_url,
            email_verified=False,  # Facebook doesn't expose this reliably
        )
    
    # ============================================================
    # AUTHORIZATION URL HELPERS
    # ============================================================
    
    def build_authorization_url(
        self,
        provider: str,
        state: str,
        redirect_uri: Optional[str] = None,
        scopes: Optional[list[str]] = None,
    ) -> str:
        """
        Build OAuth2 authorization URL for a provider.
        
        Used by endpoints to redirect users to the provider's
        authorization page.
        
        Args:
            provider: Provider name ("google" or "facebook")
            state: CSRF state parameter (must be verified on callback)
            redirect_uri: Callback URL (must match provider config)
            scopes: Optional custom scopes
            
        Returns:
            Full authorization URL
            
        Example:
            url = service.build_authorization_url(
                provider="google",
                state=csrf_token,
                redirect_uri="https://myapp.com/auth/google/callback",
            )
            return RedirectResponse(url)
        """
        provider = provider.lower().strip()
        if provider not in SUPPORTED_PROVIDERS:
            raise ValueError(f"Unsupported provider: {provider}")
        
        if provider == "google":
            params = {
                "client_id": self.settings.google_client_id,
                "response_type": "code",
                "scope": " ".join(scopes or ["openid", "email", "profile"]),
                "state": state,
                "access_type": "offline",
                "prompt": "consent",
            }
            if redirect_uri:
                params["redirect_uri"] = redirect_uri
            
            query = "&".join(f"{k}={v}" for k, v in params.items())
            return f"{GOOGLE_AUTHORIZE_URL}?{query}"
        
        elif provider == "facebook":
            params = {
                "client_id": self.settings.facebook_client_id,
                "response_type": "code",
                "scope": ",".join(scopes or ["email", "public_profile"]),
                "state": state,
            }
            if redirect_uri:
                params["redirect_uri"] = redirect_uri
            
            query = "&".join(f"{k}={v}" for k, v in params.items())
            return f"{FACEBOOK_AUTHORIZE_URL}?{query}"
        
        raise ValueError(f"Unsupported provider: {provider}")


# ============================================================
# MODULE-LEVEL FUNCTION (Backward Compatible)
# ============================================================

async def exchange_provider_code(
    provider: str,
    code: str,
) -> dict[str, str]:
    """
    Exchange an authorization code for normalized provider user information.
    
    NOTE: This is a backward-compatible function wrapper.
    New code should use SocialAuthService.exchange_provider_code().
    
    Returns:
        Dict with keys: email, full_name
    """
    service = SocialAuthService()
    user_info = await service.exchange_provider_code(provider, code)
    
    return {
        "email": user_info.email,
        "full_name": user_info.full_name,
    }


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    # Service class
    "SocialAuthService",
    
    # Data class
    "OAuthUserInfo",
    
    # Functions
    "exchange_provider_code",
    
    # Constants
    "SUPPORTED_PROVIDERS",
]