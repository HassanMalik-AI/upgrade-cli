"""
Small authentication primitives shared by services and dependencies.

This module provides a thin abstraction layer over the underlying
authentication mechanisms (JWT, password hashing). It serves as:

- **Facade**: Simplifies access to complex security modules
- **Boundary**: Decouples services from specific implementations
- **Testability**: Easy to mock in unit tests
- **Migration path**: Swap implementations without changing callers
- **Composition**: Combines multiple security primitives

Why this module exists:
- Services shouldn't know about JWT details, bcrypt, etc.
- Changing from JWT to sessions → only modify this file
- Changing from bcrypt to argon2 → only modify password.py
- Test files can mock auth.py instead of deep imports

Architecture Position:
    Services/Dependencies
            ↓
        auth.py  (this file - facade)
            ↓
    ┌───────┴───────┐
    ↓               ↓
  jwt.py        password.py
    ↓               ↓
  jose          bcrypt
"""

from datetime import timedelta
from typing import Any, Optional
from uuid import UUID

from app.core.config.settings import get_settings
from app.core.security.password import (
    hash_password,
    needs_rehash,
    validate_password_strength,
    verify_password,
)
from app.utils.logger import logger


# ============================================================
# TOKEN OPERATIONS
# ============================================================

def create_token(
    subject: UUID | str,
    token_type: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Create a token through the selected authentication boundary.
    
    This function delegates to the JWT implementation. The indirection
    allows swapping token creation strategies without changing callers.
    
    Args:
        subject: User ID (UUID or string)
        token_type: Type of token (access, refresh, reset, verify, 2fa)
        expires_delta: Optional custom expiration
        
    Returns:
        Signed token string
        
    Example:
        token = create_token(user_id, "access")
        refresh = create_token(user_id, "refresh", expires_delta=timedelta(days=30))
    """
    from app.core.security.jwt import create_token as jwt_create_token
    
    return jwt_create_token(subject, token_type, expires_delta)


def decode_token(
    token: str,
    expected_type: Optional[str] = "access",
) -> dict[str, Any]:
    """
    Decode and validate a token through the authentication boundary.
    
    Args:
        token: JWT string
        expected_type: Expected token type (None to skip check)
        
    Returns:
        Decoded payload
        
    Raises:
        ValueError: If token is invalid
    """
    from app.core.security.jwt import decode_token as jwt_decode_token
    
    return jwt_decode_token(token, expected_type)


def extract_subject(token: str) -> Optional[UUID]:
    """
    Extract user ID from token without full validation.
    
    Use only for logging/metrics, never for authentication.
    
    Args:
        token: JWT string
        
    Returns:
        UUID of subject or None
    """
    from app.core.security.jwt import extract_subject as jwt_extract_subject
    
    return jwt_extract_subject(token)


# ============================================================
# PASSWORD OPERATIONS
# ============================================================

def authenticate_password(password: str, password_hash: str) -> bool:
    """
    Return whether credentials match without exposing password details.
    
    This is the ONLY function that should be used for password
    verification. It wraps the underlying implementation to:
    - Provide consistent logging
    - Enable easy mocking in tests
    - Decouple from specific hashing algorithm
    
    Args:
        password: Plaintext password to verify
        password_hash: Stored password hash
        
    Returns:
        True if password matches, False otherwise
        
    Example:
        if authenticate_password(data.password, user.password_hash):
            return create_tokens(user)
        raise HTTPException(401, "Invalid credentials")
    """
    return verify_password(password, password_hash)


def hash_new_password(password: str) -> str:
    """
    Hash a new password through the authentication boundary.
    
    Use this when:
    - User registers
    - User changes password
    - Admin resets password
    
    Args:
        password: Plaintext password
        
    Returns:
        Bcrypt hash suitable for storage
    """
    return hash_password(password)


def should_rehash(password_hash: str) -> bool:
    """
    Check if a password hash should be rehashed.
    
    Called after successful login to upgrade password hashes
    when the cost factor has changed.
    
    Args:
        password_hash: Stored password hash
        
    Returns:
        True if hash should be rehashed
    """
    return needs_rehash(password_hash)


def validate_password(password: str) -> tuple[bool, list[str]]:
    """
    Validate password strength through the authentication boundary.
    
    Args:
        password: Password to validate
        
    Returns:
        Tuple of (is_valid, errors)
    """
    return validate_password_strength(password)


# ============================================================
# HIGH-LEVEL AUTHENTICATION FLOWS
# ============================================================

def authenticate_user(
    password: str,
    password_hash: str,
    user_id: Optional[UUID] = None,
) -> bool:
    """
    Authenticate a user with comprehensive logging.
    
    This is the high-level function for authentication. It:
    - Verifies the password
    - Logs success/failure (without leaking details)
    - Can be extended for rate limiting
    
    Args:
        password: Plaintext password
        password_hash: Stored hash
        user_id: Optional user ID for logging
        
    Returns:
        True if authentication succeeds
    """
    is_valid = verify_password(password, password_hash)
    
    if is_valid:
        logger.info(
            "User authentication successful",
            extra={
                "event": "auth_success",
                "user_id": str(user_id) if user_id else None,
            }
        )
    else:
        logger.warning(
            "User authentication failed",
            extra={
                "event": "auth_failure",
                "user_id": str(user_id) if user_id else None,
            }
        )
    
    return is_valid


def create_token_pair(
    user_id: UUID | str,
    additional_claims: Optional[dict[str, Any]] = None,
) -> tuple[str, str]:
    """
    Create an access token and refresh token pair.
    
    Args:
        user_id: User identifier
        additional_claims: Extra claims for access token (roles, etc.)
        
    Returns:
        Tuple of (access_token, refresh_token)
        
    Example:
        access, refresh = create_token_pair(user.id)
        # Store hash of refresh in DB
        # Return access to client
    """
    from app.core.security.jwt import (
        create_access_token,
        create_refresh_token,
    )
    
    access_token = create_access_token(user_id, additional_claims)
    refresh_token = create_refresh_token(user_id)
    
    logger.debug(
        "Token pair created",
        extra={
            "event": "token_pair_created",
            "user_id": str(user_id)[:8] + "...",
        }
    )
    
    return access_token, refresh_token


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    # Token operations
    "create_token",
    "decode_token",
    "extract_subject",
    "create_token_pair",
    
    # Password operations
    "authenticate_password",
    "hash_new_password",
    "should_rehash",
    "validate_password",
    "authenticate_user",
]