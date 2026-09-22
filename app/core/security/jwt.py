"""
JWT access-token creation and validation.

Access tokens are short-lived and carry only a subject and token type. Refresh
tokens are generated separately and must be hashed before database persistence.

Security Design:
- Access tokens: Short-lived (15 min default), carry subject + type
- Refresh tokens: Long-lived (30 days), stored as SHA-256 hash in DB
- Signed with HS256 (HMAC-SHA256) by default
- Include standard claims: sub, type, iat, exp, jti, nbf
- Custom claims support for roles, permissions, etc.
- Comprehensive validation: signature, expiration, type, audience, issuer
- Token rotation support (refresh with rotation)
- Revocation via JTI blacklist (Redis or DB)

JWT Structure:
    Header.Payload.Signature
    eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.xyz

Standard Claims:
    sub: Subject (user ID)
    type: Token type (access, refresh, reset, verify)
    iat: Issued at (timestamp)
    exp: Expiration (timestamp)
    nbf: Not before (timestamp)
    jti: JWT ID (unique identifier for revocation)
    iss: Issuer (who created the token)
    aud: Audience (intended recipient)
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Optional, Literal

from jose import JWTError, jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError

from app.core.config.settings import get_settings
from app.utils.logger import logger


# ============================================================
# CONSTANTS
# ============================================================

# Token types for clear identification
TokenType = Literal["access", "refresh", "reset", "verify", "2fa"]

# Standard token durations
ACCESS_TOKEN_DEFAULT_MINUTES = 15
REFRESH_TOKEN_DEFAULT_DAYS = 30
RESET_TOKEN_DEFAULT_MINUTES = 15
VERIFY_TOKEN_DEFAULT_HOURS = 24
TWO_FA_TOKEN_DEFAULT_MINUTES = 5


# ============================================================
# 1. TOKEN CREATION
# ============================================================

def create_token(
    subject: UUID | str,
    token_type: TokenType = "access",
    expires_delta: Optional[timedelta] = None,
    additional_claims: Optional[dict[str, Any]] = None,
    issuer: Optional[str] = None,
    audience: Optional[str] = None,
) -> str:
    """
    Create a signed JWT for a subject and explicit token type.
    
    Args:
        subject: User ID or unique identifier (UUID or string)
        token_type: Type of token (access, refresh, reset, verify, 2fa)
        expires_delta: Custom expiration (defaults per token_type)
        additional_claims: Extra claims to include (roles, permissions)
        issuer: Token issuer (defaults from settings)
        audience: Intended recipient (defaults from settings)
        
    Returns:
        Signed JWT string
        
    Raises:
        ValueError: If token_type is invalid or subject is empty
        
    Example:
        # Access token (15 min)
        token = create_token(user_id, "access")
        
        # Refresh token (30 days)
        refresh = create_token(user_id, "refresh")
        
        # Custom expiration
        token = create_token(
            user_id,
            "access",
            expires_delta=timedelta(minutes=5)
        )
        
        # With additional claims
        token = create_token(
            user_id,
            "access",
            additional_claims={"role": "admin", "scopes": ["read", "write"]}
        )
    
    Security Notes:
        - Subject is always converted to string
        - Unique JTI added for revocation support
        - iat and nbf set to now (prevents future tokens)
        - exp set based on token_type or expires_delta
    """
    if not subject:
        raise ValueError("Subject cannot be empty")
    
    settings = get_settings()
    now = datetime.now(UTC)
    
    # Determine expiration based on token type
    if expires_delta is None:
        expires_delta = _get_default_expiry(token_type)
    
    # Build standard payload
    payload: dict[str, Any] = {
        # Standard claims (RFC 7519)
        "sub": str(subject),                    # Subject
        "iat": int(now.timestamp()),            # Issued At
        "nbf": int(now.timestamp()),            # Not Before
        "exp": int((now + expires_delta).timestamp()),  # Expiration
        "jti": str(uuid.uuid4()),               # JWT ID (for revocation)
        
        # Custom claims
        "type": token_type,                     # Token type
    }
    
    # Add issuer if configured
    if issuer or settings.jwt_issuer:
        payload["iss"] = issuer or settings.jwt_issuer
    
    # Add audience if configured
    if audience or settings.jwt_audience:
        payload["aud"] = audience or settings.jwt_audience
    
    # Add custom claims (roles, scopes, etc.)
    if additional_claims:
        # Prevent overwriting standard claims
        protected_claims = {"sub", "iat", "exp", "nbf", "jti", "type", "iss", "aud"}
        for key, value in additional_claims.items():
            if key in protected_claims:
                raise ValueError(f"Cannot override protected claim: {key}")
            payload[key] = value
    
    # Sign the token
    token = jwt.encode(
        payload,
        settings.jwt_secret_key.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )
    
    logger.debug(
        f"Created {token_type} token",
        extra={
            "event": "token_created",
            "token_type": token_type,
            "subject": str(subject)[:8] + "...",  # Partial for privacy
            "expires_in_seconds": int(expires_delta.total_seconds()),
        }
    )
    
    return token


def create_access_token(
    subject: UUID | str,
    additional_claims: Optional[dict[str, Any]] = None,
) -> str:
    """
    Convenience function for creating access tokens.
    
    Args:
        subject: User ID
        additional_claims: Extra claims (roles, permissions)
        
    Returns:
        Signed access token
    """
    return create_token(subject, "access", additional_claims=additional_claims)


def create_refresh_token(subject: UUID | str) -> str:
    """
    Convenience function for creating refresh tokens.
    
    IMPORTANT: The returned token must be hashed (SHA-256) before
    storing in the database. Never store raw refresh tokens.
    
    Args:
        subject: User ID
        
    Returns:
        Signed refresh token (raw, must be hashed before storage)
    """
    return create_token(subject, "refresh")


def create_reset_token(subject: UUID | str) -> str:
    """Create a password reset token (15 min expiry)."""
    return create_token(subject, "reset")


def create_verify_token(subject: UUID | str) -> str:
    """Create an email verification token (24 hours expiry)."""
    return create_token(subject, "verify")


def create_2fa_token(subject: UUID | str) -> str:
    """Create a 2FA pending token (5 min expiry)."""
    return create_token(subject, "2fa")


# ============================================================
# 2. TOKEN DECODING & VALIDATION
# ============================================================

def decode_token(
    token: str,
    expected_type: Optional[TokenType] = "access",
    verify_expiration: bool = True,
    verify_audience: bool = True,
    verify_issuer: bool = True,
) -> dict[str, Any]:
    """
    Decode and validate a JWT.
    
    Performs comprehensive validation:
    - Signature verification (ensures not tampered)
    - Expiration check (rejects expired tokens)
    - Not Before check (rejects future tokens)
    - Type verification (ensures correct token type)
    - Audience check (ensures intended recipient)
    - Issuer check (ensures correct source)
    
    Args:
        token: JWT string to decode
        expected_type: Expected token type (None = skip type check)
        verify_expiration: Check if token is expired
        verify_audience: Verify audience claim
        verify_issuer: Verify issuer claim
        
    Returns:
        Decoded payload with all claims
        
    Raises:
        ValueError: For any validation failure (with specific message)
        
    Example:
        try:
            payload = decode_token(token, "access")
            user_id = UUID(payload["sub"])
        except ValueError as e:
            raise HTTPException(401, str(e))
    
    Security Notes:
        - All validation failures return generic messages
          (prevent information leakage)
        - Detailed logs help debugging without exposing to client
    """
    if not token:
        raise ValueError("Token is required")
    
    settings = get_settings()
    
    try:
        # Decode and verify signature
        payload = jwt.decode(
            token,
            settings.jwt_secret_key.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
            options={
                "verify_exp": verify_expiration,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_aud": verify_audience,
                "verify_iss": verify_issuer,
                "require": ["sub", "exp", "iat"],  # Required claims
            },
            audience=settings.jwt_audience if verify_audience else None,
            issuer=settings.jwt_issuer if verify_issuer else None,
        )
        
    except ExpiredSignatureError:
        logger.debug("Token expired", extra={"event": "token_expired"})
        raise ValueError("Token has expired")
    
    except JWTClaimsError as e:
        logger.debug(f"JWT claims error: {e}", extra={"event": "claims_error"})
        raise ValueError("Invalid token claims")
    
    except JWTError as e:
        logger.warning(f"JWT validation failed: {e}", extra={"event": "jwt_error"})
        raise ValueError("Invalid token")
    
    # Additional validations
    if expected_type is not None:
        token_type = payload.get("type")
        if token_type != expected_type:
            logger.warning(
                f"Token type mismatch",
                extra={
                    "event": "token_type_mismatch",
                    "expected": expected_type,
                    "actual": token_type,
                }
            )
            raise ValueError(f"Invalid token type")
    
    if not payload.get("sub"):
        raise ValueError("Missing subject in token")
    
    return payload


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and validate an access token."""
    return decode_token(token, expected_type="access")


def decode_refresh_token(token: str) -> dict[str, Any]:
    """Decode and validate a refresh token."""
    return decode_token(token, expected_type="refresh")


def decode_reset_token(token: str) -> dict[str, Any]:
    """Decode and validate a password reset token."""
    return decode_token(token, expected_type="reset")


def decode_verify_token(token: str) -> dict[str, Any]:
    """Decode and validate an email verification token."""
    return decode_token(token, expected_type="verify")


# ============================================================
# 3. TOKEN INSPECTION (Without validation)
# ============================================================

def inspect_token(token: str) -> Optional[dict[str, Any]]:
    """
    Decode a token WITHOUT signature verification.
    
    DANGER: Use only for debugging/logging. NEVER for authentication.
    
    Args:
        token: JWT string
        
    Returns:
        Decoded payload or None if malformed
    """
    try:
        return jwt.decode(
            token,
            options={"verify_signature": False, "verify_exp": False},
            algorithms=["HS256", "RS256"],  # Accept common algorithms
        )
    except JWTError:
        return None


def get_token_expiry(token: str) -> Optional[datetime]:
    """
    Extract expiration timestamp from token.
    
    Args:
        token: JWT string
        
    Returns:
        Expiration datetime or None if not found
    """
    payload = inspect_token(token)
    if not payload or "exp" not in payload:
        return None
    return datetime.fromtimestamp(payload["exp"], tz=UTC)


def get_token_remaining_seconds(token: str) -> Optional[float]:
    """
    Get seconds until token expires.
    
    Args:
        token: JWT string
        
    Returns:
        Seconds until expiry, or None if no expiry
    """
    exp = get_token_expiry(token)
    if not exp:
        return None
    return (exp - datetime.now(UTC)).total_seconds()


def is_token_expired(token: str) -> bool:
    """
    Check if token is expired (without raising).
    
    Args:
        token: JWT string
        
    Returns:
        True if expired, False otherwise
    """
    remaining = get_token_remaining_seconds(token)
    return remaining is not None and remaining <= 0


# ============================================================
# 4. TOKEN ROTATION
# ============================================================

def rotate_tokens(
    refresh_token: str,
) -> tuple[str, str]:
    """
    Rotate access and refresh tokens.
    
    Token rotation improves security by:
    - Limiting the lifetime of any single refresh token
    - Detecting token theft (used token used again)
    - Enabling session invalidation
    
    Args:
        refresh_token: Valid refresh token to rotate
        
    Returns:
        Tuple of (new_access_token, new_refresh_token)
        
    Raises:
        ValueError: If refresh token is invalid
        
    Example:
        # On refresh endpoint:
        new_access, new_refresh = rotate_tokens(refresh_token)
        # Store hash of new_refresh in DB
        # Return new_access to client
    """
    # Decode and validate refresh token
    payload = decode_refresh_token(refresh_token)
    subject = payload["sub"]
    
    # Create new tokens
    new_access = create_access_token(subject)
    new_refresh = create_refresh_token(subject)
    
    logger.info(
        "Tokens rotated",
        extra={
            "event": "token_rotation",
            "subject": subject[:8] + "...",
        }
    )
    
    return new_access, new_refresh


# ============================================================
# 5. HELPER FUNCTIONS
# ============================================================

def _get_default_expiry(token_type: TokenType) -> timedelta:
    """
    Get default expiration for a token type.
    
    Args:
        token_type: Type of token
        
    Returns:
        Default timedelta for that token type
    """
    settings = get_settings()
    
    defaults = {
        "access": timedelta(minutes=settings.access_token_minutes),
        "refresh": timedelta(days=settings.refresh_token_days),
        "reset": timedelta(minutes=RESET_TOKEN_DEFAULT_MINUTES),
        "verify": timedelta(hours=VERIFY_TOKEN_DEFAULT_HOURS),
        "2fa": timedelta(minutes=TWO_FA_TOKEN_DEFAULT_MINUTES),
    }
    
    return defaults.get(token_type, timedelta(minutes=ACCESS_TOKEN_DEFAULT_MINUTES))


def extract_subject(token: str) -> Optional[UUID]:
    """
    Extract subject (user ID) from token without raising.
    
    Args:
        token: JWT string
        
    Returns:
        UUID of subject or None if not found
    """
    payload = inspect_token(token)
    if not payload or "sub" not in payload:
        return None
    
    try:
        return UUID(payload["sub"])
    except (ValueError, TypeError):
        return None


def extract_jti(token: str) -> Optional[str]:
    """
    Extract JWT ID (jti) for revocation.
    
    Args:
        token: JWT string
        
    Returns:
        JTI string or None
    """
    payload = inspect_token(token)
    if not payload:
        return None
    return payload.get("jti")


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    # Creation
    "create_token",
    "create_access_token",
    "create_refresh_token",
    "create_reset_token",
    "create_verify_token",
    "create_2fa_token",
    
    # Decoding
    "decode_token",
    "decode_access_token",
    "decode_refresh_token",
    "decode_reset_token",
    "decode_verify_token",
    
    # Inspection
    "inspect_token",
    "get_token_expiry",
    "get_token_remaining_seconds",
    "is_token_expired",
    "extract_subject",
    "extract_jti",
    
    # Rotation
    "rotate_tokens",
]