"""
Security primitives for token generation and hashing.

This module provides pure functions for creating and hashing opaque tokens
such as refresh tokens. These are security primitives and do not contain
business logic.

Security Notes:
- Raw refresh tokens are never stored in the database.
- We use SHA-256 to hash refresh tokens before persistence.
- Random token generation uses the OS-level CSPRNG.
"""

import hashlib
import secrets

# Constants for token generation
TOKEN_ENTROPY_BYTES = 48
TOKEN_HASH_ALGORITHM = "sha256"


def hash_refresh_token(token: str) -> str:
    """
    Return the SHA-256 digest persisted for a raw refresh bearer token.
    
    Raw refresh tokens are NEVER stored in the database. Only their
    SHA-256 hashes are persisted. This means:
    - If DB leaks, tokens are useless
    - Lookup by hash, not raw token
    - Hash is irreversible (preimage resistance)
    
    Args:
        token: Raw refresh token (URL-safe base64)
        
    Returns:
        64-character hex digest of SHA-256
        
    Example:
        raw = "abc123..."
        digest = hash_refresh_token(raw)
        # digest = "e3b0c44298fc1c14..." (64 chars)
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_raw_refresh_token() -> str:
    """
    Generate a cryptographically secure raw refresh token.
    
    Uses secrets.token_urlsafe which:
    - Uses OS-level CSPRNG (os.urandom)
    - Returns URL-safe base64 (no encoding issues)
    - 48 bytes = 384 bits of entropy
    
    Returns:
        URL-safe base64 string (about 64 characters)
        
    Why 48 bytes:
        - 32 bytes (256 bits): minimum modern standard
        - 48 bytes (384 bits): extra margin
        - 64 bytes (512 bits): overkill, longer strings
        
        48 bytes balances security and storage.
    """
    return secrets.token_urlsafe(TOKEN_ENTROPY_BYTES)


__all__ = [
    "hash_refresh_token",
    "generate_raw_refresh_token",
    "TOKEN_ENTROPY_BYTES",
]
