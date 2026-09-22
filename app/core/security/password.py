"""
Password hashing using bcrypt through Passlib.

Only password hashes are persisted; plaintext passwords are never logged or
returned. Replace the scheme configuration here if an enterprise KMS policy
requires a different approved password verifier.

Security Design:
- bcrypt with configurable cost factor (work factor)
- Automatic salt generation (unique per password)
- Constant-time verification (prevents timing attacks)
- Password strength validation (enterprise policy enforcement)
- Password rehashing support (upgrade cost factor without re-login)
- Never logs or returns plaintext passwords

Why bcrypt:
- Adaptive cost factor (increases with hardware)
- Built-in salting (no rainbow table attacks)
- Slow by design (prevents brute force)
- Industry standard (OWASP, NIST approved)
- Well-tested (20+ years in production)
"""

import hmac
import logging
import re
from datetime import datetime, UTC
from typing import Optional, List, Tuple

import bcrypt

from app.core.config.settings import get_settings

logger = logging.getLogger(__name__)


# ============================================================
# CONFIGURATION
# ============================================================

# bcrypt cost factor (work factor)
# Each increment DOUBLES the time to hash
# 12 = ~250ms on modern hardware (recommended 2024)
# 10 = ~65ms  (minimum acceptable)
# 14 = ~1s    (high security, high latency)
BCRYPT_ROUNDS = 12

# bcrypt has a 72-byte limit for passwords
# Passwords longer than this are truncated (security risk!)
# We handle this by pre-hashing or rejecting
MAX_PASSWORD_BYTES = 72

# Password policy defaults (can be overridden by settings)
DEFAULT_MIN_LENGTH = 8
DEFAULT_MAX_LENGTH = 128
DEFAULT_REQUIRE_UPPERCASE = True
DEFAULT_REQUIRE_LOWERCASE = True
DEFAULT_REQUIRE_DIGIT = True
DEFAULT_REQUIRE_SPECIAL = True


# ============================================================
# 1. CORE HASHING FUNCTIONS
# ============================================================

def hash_password(password: str) -> str:
    """
    Hash a password with bcrypt and return the encoded hash.
    
    Generates a unique salt for each password. The same password
    will produce different hashes each time (due to random salt).
    
    Args:
        password: Plaintext password to hash
        
    Returns:
        Encoded bcrypt hash (60 characters, includes salt + cost)
        
    Raises:
        ValueError: If password is empty or too long
        
    Example:
        >>> hash_password("my-secret-password")
        '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewKyNiAYMyzJ/I2K'
    
    Security Notes:
        - Salt is unique per password (no rainbow tables)
        - Cost factor makes brute force slow
        - Hash includes algorithm identifier ($2b$)
        - Hash includes cost factor (12)
    """
    if not password:
        raise ValueError("Password cannot be empty")
    
    # bcrypt has 72-byte limit
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > MAX_PASSWORD_BYTES:
        raise ValueError(
            f"Password too long: {len(password_bytes)} bytes. "
            f"Maximum is {MAX_PASSWORD_BYTES} bytes."
        )
    
    # Generate salt and hash
    # gensalt() uses default cost factor (12)
    # hashpw() does the actual bcrypt hashing
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    password_hash = bcrypt.hashpw(password_bytes, salt)
    
    return password_hash.decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """
    Constant-time verify a candidate password against its stored hash.
    
    Uses bcrypt's checkpw which is constant-time, preventing timing
    attacks where an attacker could guess the hash bit-by-bit.
    
    Args:
        password: Plaintext password to verify
        password_hash: Stored bcrypt hash to compare against
        
    Returns:
        True if password matches, False otherwise
        
    Example:
        >>> stored_hash = hash_password("my-password")
        >>> verify_password("my-password", stored_hash)
        True
        >>> verify_password("wrong-password", stored_hash)
        False
    
    Security Notes:
        - Constant-time comparison (no timing leaks)
        - Returns False instead of raising on invalid hash
        - Never logs the password or hash
    """
    if not password or not password_hash:
        return False
    
    try:
        password_bytes = password.encode("utf-8")
        hash_bytes = password_hash.encode("utf-8")
        return bcrypt.checkpw(password_bytes, hash_bytes)
    except (ValueError, TypeError) as e:
        # Invalid hash format - log warning (not the hash itself)
        logger.warning(f"Password verification failed: invalid hash format")
        return False


# ============================================================
# 2. PASSWORD STRENGTH VALIDATION
# ============================================================

class PasswordPolicyError(ValueError):
    """Raised when password doesn't meet policy requirements."""
    pass


def validate_password_strength(
    password: str,
    min_length: int = DEFAULT_MIN_LENGTH,
    max_length: int = DEFAULT_MAX_LENGTH,
    require_uppercase: bool = DEFAULT_REQUIRE_UPPERCASE,
    require_lowercase: bool = DEFAULT_REQUIRE_LOWERCASE,
    require_digit: bool = DEFAULT_REQUIRE_DIGIT,
    require_special: bool = DEFAULT_REQUIRE_SPECIAL,
) -> Tuple[bool, List[str]]:
    """
    Validate password against configurable strength policy.
    
    Returns both success status and list of specific failures,
    allowing user-friendly error messages.
    
    Args:
        password: Password to validate
        min_length: Minimum password length
        max_length: Maximum password length
        require_uppercase: Require at least one uppercase letter
        require_lowercase: Require at least one lowercase letter
        require_digit: Require at least one digit
        require_special: Require at least one special character
        
    Returns:
        Tuple of (is_valid, list_of_errors)
        
    Example:
        >>> is_valid, errors = validate_password_strength("weak")
        >>> print(is_valid, errors)
        False, ['Password must be at least 8 characters', ...]
        
        >>> is_valid, errors = validate_password_strength("StrongP@ss123")
        >>> print(is_valid, errors)
        True, []
    """
    errors: List[str] = []
    
    # Length checks
    if len(password) < min_length:
        errors.append(f"Password must be at least {min_length} characters")
    
    if len(password) > max_length:
        errors.append(f"Password must be at most {max_length} characters")
    
    # bcrypt byte limit
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        errors.append(
            f"Password too long (max {MAX_PASSWORD_BYTES} bytes when encoded)"
        )
    
    # Character class checks
    if require_uppercase and not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter")
    
    if require_lowercase and not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter")
    
    if require_digit and not re.search(r"\d", password):
        errors.append("Password must contain at least one digit")
    
    if require_special and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        errors.append("Password must contain at least one special character")
    
    # Common password check (minimal list - expand for production)
    common_passwords = {
        "password", "12345678", "qwerty", "abc123", "letmein",
        "welcome", "monkey", "dragon", "master", "admin",
    }
    if password.lower() in common_passwords:
        errors.append("Password is too common")
    
    # Sequential characters check
    if re.search(r"(012|123|234|345|456|567|678|789|890)", password):
        errors.append("Password contains sequential digits")
    
    if re.search(r"(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|"
                 r"mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)", password.lower()):
        errors.append("Password contains sequential letters")
    
    return len(errors) == 0, errors


def validate_and_raise(password: str) -> None:
    """
    Validate password and raise PasswordPolicyError if invalid.
    
    Convenience wrapper for use in services where exceptions
    are preferred over tuple returns.
    
    Args:
        password: Password to validate
        
    Raises:
        PasswordPolicyError: If password doesn't meet policy
    """
    is_valid, errors = validate_password_strength(password)
    if not is_valid:
        raise PasswordPolicyError("; ".join(errors))


# ============================================================
# 3. HASH MAINTENANCE FUNCTIONS
# ============================================================

def needs_rehash(password_hash: str) -> bool:
    """
    Check if a hash needs to be rehashed (cost factor changed).
    
    When you increase BCRYPT_ROUNDS, existing hashes still use
    the old cost. This function detects that and tells you to
    rehash on next login.
    
    Args:
        password_hash: Stored bcrypt hash
        
    Returns:
        True if hash should be rehashed with current cost factor
        
    Example:
        # During login:
        if verify_password(password, user.password_hash):
            if needs_rehash(user.password_hash):
                user.password_hash = hash_password(password)
                await db.commit()
    """
    try:
        # Extract cost factor from hash
        # bcrypt format: $2b$12$... where 12 is the cost
        parts = password_hash.split("$")
        if len(parts) < 4:
            return True  # Invalid format
        
        current_cost = int(parts[2])
        return current_cost < BCRYPT_ROUNDS
    except (ValueError, IndexError):
        return True  # Invalid format, rehash


def rehash_password(password: str) -> str:
    """
    Rehash password with current cost factor.
    
    Alias for hash_password() - provided for semantic clarity
    when you intend to rehash an existing password.
    
    Args:
        password: Plaintext password
        
    Returns:
        New hash with current cost factor
    """
    return hash_password(password)


# ============================================================
# 4. CONSTANT-TIME COMPARISON (For tokens, not passwords)
# ============================================================

def constant_time_compare(a: str, b: str) -> bool:
    """
    Constant-time comparison for tokens, API keys, etc.
    
    This is for comparing short-lived tokens (reset tokens, API keys),
    NOT for password verification (use verify_password for that).
    
    Args:
        a: First string
        b: Second string
        
    Returns:
        True if strings are equal
        
    Security Notes:
        - Uses HMAC comparison to prevent timing attacks
        - Strings must be encoded identically
    """
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# ============================================================
# 5. EXPORTS
# ============================================================

__all__ = [
    # Core functions
    "hash_password",
    "verify_password",
    
    # Validation
    "validate_password_strength",
    "validate_and_raise",
    "PasswordPolicyError",
    
    # Maintenance
    "needs_rehash",
    "rehash_password",
    
    # Utilities
    "constant_time_compare",
]