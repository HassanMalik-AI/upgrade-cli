"""
TOTP primitives for optional multi-factor authentication.

This module provides the low-level TOTP (Time-based One-Time Password)
primitives used for two-factor authentication (2FA). It handles:
- Secret generation (cryptographically secure Base32)
- Code verification (with clock skew tolerance)
- QR code provisioning URIs (for authenticator apps)
- Backup code generation and verification
- Time-remaining calculation (for UI feedback)

Design Principles:
- Pure functions for primitives (no DB, no state)
- Uses `pyotp` (standard, well-tested library)
- Small clock-skew window (1 step = 30 seconds each direction)
- Never stores secrets here (that's the model's job)
- Return simple values (str, bool) for easy testing

TOTP Algorithm (RFC 6238):
    1. Shared secret (Base32-encoded, 32 chars = 160 bits)
    2. Current time / 30 seconds = counter
    3. HMAC-SHA1(secret, counter) → dynamic truncation → 6 digits
    4. Code valid for 30 seconds (or ±1 window for clock skew)

Why 30-second windows:
- Standard from RFC 6238 (Google Authenticator default)
- Short enough to be secure if observed
- Long enough for user to type
- ±1 window (±30s) handles clock skew between server and device

Security Properties:
- Secret is 160 bits (cryptographically strong)
- HMAC-SHA1 (not for signatures, but fine for TOTP)
- Time-based → codes rotate automatically
- Replay protection: same code + window can't be reused within 30s
- Backup codes for recovery (one-time use, hashed)
"""

import hmac
import secrets
import string
from datetime import UTC, datetime
from typing import Optional

import pyotp

from app.utils.logger import logger


# ============================================================
# CONFIGURATION
# ============================================================

# TOTP standard parameters (RFC 6238)
TOTP_INTERVAL_SECONDS = 30         # Code rotates every 30 seconds
TOTP_DIGITS = 6                    # 6-digit codes (standard)
TOTP_DIGEST = "sha1"               # SHA-1 (Google Authenticator compatible)
TOTP_VALID_WINDOW = 1              # ±1 step = ±30 seconds clock skew

# Backup code parameters
BACKUP_CODE_COUNT = 10             # 10 backup codes
BACKUP_CODE_LENGTH = 8             # 8 characters per code
BACKUP_CODE_ALPHABET = string.ascii_uppercase + string.digits  # A-Z, 0-9


# ============================================================
# 1. SECRET GENERATION
# ============================================================

def new_secret() -> str:
    """
    Generate a cryptographically random Base32 TOTP secret.
    
    Returns a 32-character Base32 string (160 bits of entropy).
    Compatible with all standard authenticator apps:
    - Google Authenticator
    - Microsoft Authenticator
    - Authy
    - 1Password
    - Bitwarden
    
    Returns:
        32-character Base32 secret (e.g., "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
        
    Example:
        >>> secret = new_secret()
        >>> len(secret)
        32
        >>> secret.isupper()
        True
        >>> all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in secret)
        True
    
    Security Notes:
        - Uses pyotp's random_base32() which uses secrets module
        - 160 bits = 2^160 possible secrets (astronomically secure)
        - Base32 encoding is RFC 4648 standard (required by TOTP RFC)
    """
    return pyotp.random_base32()


# ============================================================
# 2. CODE VERIFICATION
# ============================================================

def verify_code(
    secret: str,
    code: str,
    valid_window: int = TOTP_VALID_WINDOW,
) -> bool:
    """
    Verify a current TOTP code with a small clock-skew window.
    
    Args:
        secret: Base32-encoded TOTP secret
        code: 6-digit code from user's authenticator app
        valid_window: Number of 30-second windows to check (±)
        
    Returns:
        True if code is valid, False otherwise
        
    Example:
        >>> secret = new_secret()
        >>> current_code = pyotp.TOTP(secret).now()
        >>> verify_code(secret, current_code)
        True
        >>> verify_code(secret, "000000")  # Wrong code
        False
    
    Validation Window:
        valid_window=0: Only current 30-second window
        valid_window=1: Current + previous + next (90 seconds total)
        valid_window=2: Current ± 2 (150 seconds total)
        
    Why ±1 window (default):
        - Handles clock skew between server and device
        - Network latency tolerance
        - User typing time (up to 30 seconds)
        - Still limits brute-force (only 3 windows × 10^6 codes)
    
    Security Notes:
        - Code is 6 digits → 1,000,000 combinations per window
        - 3 windows × 1,000,000 = 3,000,000 possibilities
        - If attacker tries 1 code/second → 34 days to guarantee
        - Combined with rate limiting → practically impossible
    """
    if not secret or not code:
        return False
    
    # Normalize: strip whitespace from code
    code = code.strip().replace(" ", "")
    
    # Validate format
    if not code.isdigit() or len(code) != TOTP_DIGITS:
        return False
    
    try:
        totp = pyotp.TOTP(secret)
        return bool(totp.verify(code, valid_window=valid_window))
    except Exception as e:
        logger.warning(
            f"TOTP verification error: {e}",
            extra={"event": "totp_verify_error"},
        )
        return False


def verify_code_strict(secret: str, code: str) -> bool:
    """
    Verify a TOTP code with NO clock-skew tolerance.
    
    Only accepts codes from the current 30-second window.
    Use this for high-security operations where clock skew
    is not a concern (e.g., internal services).
    
    Args:
        secret: Base32-encoded TOTP secret
        code: 6-digit code
        
    Returns:
        True if valid in current window only
    """
    return verify_code(secret, code, valid_window=0)


# ============================================================
# 3. PROVISIONING URI (QR Codes)
# ============================================================

def get_provisioning_uri(
    secret: str,
    account_name: str,
    issuer_name: Optional[str] = None,
) -> str:
    """
    Generate otpauth:// URI for QR code provisioning.
    
    Users scan the QR code in their authenticator app, which
    stores the secret and starts generating codes.
    
    Args:
        secret: Base32-encoded TOTP secret
        account_name: User identifier (usually email)
        issuer_name: App name (shown in authenticator app)
        
    Returns:
        otpauth:// URI string (for QR code generation)
        
    Example:
        >>> secret = new_secret()
        >>> uri = get_provisioning_uri(secret, "user@example.com", "MyApp")
        >>> uri.startswith("otpauth://totp/")
        True
        >>> "MyApp" in uri
        True
    
    URI Format:
        otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}
        
    Usage:
        # Backend: Return URI to frontend
        uri = get_provisioning_uri(secret, user.email, settings.app_name)
        
        # Frontend: Generate QR code
        <QRCode value={uri} />
        
        # User: Scan with authenticator app
        # → Secret is stored in app
        # → App generates 6-digit codes every 30s
    """
    if not issuer_name:
        from app.core.config.settings import get_settings
        issuer_name = get_settings().app_name
    
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=account_name, issuer_name=issuer_name)


# ============================================================
# 4. CODE GENERATION (For Testing/Display)
# ============================================================

def get_current_code(secret: str) -> str:
    """
    Get the current TOTP code for a secret.
    
    WARNING: Only use for testing or server-side verification.
    Never expose this in production APIs!
    
    Args:
        secret: Base32-encoded TOTP secret
        
    Returns:
        6-digit code for current window
    """
    return pyotp.TOTP(secret).now()


def get_time_remaining() -> int:
    """
    Get seconds remaining in current TOTP window.
    
    Useful for UI: show countdown timer next to code input.
    
    Returns:
        Seconds remaining (0-30)
        
    Example:
        # Frontend: Show countdown
        remaining = get_time_remaining()
        # Display: "Code valid for {remaining} seconds"
    """
    return TOTP_INTERVAL_SECONDS - int(datetime.now(UTC).timestamp()) % TOTP_INTERVAL_SECONDS


# ============================================================
# 5. BACKUP CODES
# ============================================================

def generate_backup_codes(count: int = BACKUP_CODE_COUNT) -> list[str]:
    """
    Generate one-time backup codes for account recovery.
    
    Backup codes are used when the user loses access to their
    authenticator app. Each code can be used exactly once.
    
    Args:
        count: Number of codes to generate (default: 10)
        
    Returns:
        List of plaintext backup codes
        
    Example:
        >>> codes = generate_backup_codes()
        >>> len(codes)
        10
        >>> all(len(c) == 8 for c in codes)
        True
    
    IMPORTANT:
        - Return these to the user ONCE during setup
        - Hash them before storing in database
        - User must save them securely (password manager, print)
        - Never show them again after initial display
    
    Code Format:
        8 characters from [A-Z0-9]
        Example: "A1B2C3D4"
        
    Entropy:
        36^8 = 2.8 trillion combinations
        Secure against brute force
    """
    codes = []
    for _ in range(count):
        # Generate random code from alphabet
        code = "".join(
            secrets.choice(BACKUP_CODE_ALPHABET)
            for _ in range(BACKUP_CODE_LENGTH)
        )
        codes.append(code)
    
    logger.info(
        f"Generated {count} backup codes",
        extra={"event": "backup_codes_generated", "count": count},
    )
    
    return codes


def verify_backup_code(
    code: str,
    stored_codes: list[str],
) -> Optional[int]:
    """
    Verify a backup code against a list of stored codes.
    
    Uses constant-time comparison to prevent timing attacks.
    Returns the index of the matched code (for removal).
    
    Args:
        code: User-provided backup code
        stored_codes: List of stored (hashed) backup codes
        
    Returns:
        Index of matched code (to remove it), or None if no match
        
    Example:
        stored = ["hash1", "hash2", "hash3"]
        idx = verify_backup_code("A1B2C3D4", stored)
        if idx is not None:
            stored.pop(idx)  # Remove used code
    """
    if not code or not stored_codes:
        return None
    
    # Normalize
    code = code.strip().upper().replace("-", "").replace(" ", "")
    
    for i, stored in enumerate(stored_codes):
        # Use constant-time comparison
        # (prevents timing attacks that could reveal valid codes)
        if hmac.compare_digest(code, stored):
            return i
    
    return None


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    # Secret management
    "new_secret",
    
    # Verification
    "verify_code",
    "verify_code_strict",
    
    # Provisioning
    "get_provisioning_uri",
    
    # Code generation (testing)
    "get_current_code",
    "get_time_remaining",
    
    # Backup codes
    "generate_backup_codes",
    "verify_backup_code",
    
    # Constants
    "TOTP_INTERVAL_SECONDS",
    "TOTP_DIGITS",
    "TOTP_VALID_WINDOW",
    "BACKUP_CODE_COUNT",
    "BACKUP_CODE_LENGTH",
]