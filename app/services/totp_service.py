"""
Two-factor orchestration kept separate from HTTP handlers.

This module provides the TotpService class, which orchestrates all
two-factor authentication (2FA) operations. It coordinates between
the low-level TOTP primitives, the repository layer, and business
rules specific to 2FA setup and verification.

Design Pattern: Service Layer + Orchestration
    - Uses low-level TOTP primitives (core.security.totp)
    - Coordinates TotpSecretRepository for persistence
    - Enforces business rules (lockout, verification)
    - Handles backup codes generation and validation
    - Emits events for audit and notifications

Responsibilities:
    - Generate TOTP secrets for user setup
    - Create QR code provisioning URIs
    - Generate and manage backup codes
    - Verify TOTP codes during authentication
    - Track failed attempts and lockouts
    - Enable/disable 2FA with proper state transitions
    - Handle 2FA recovery workflows

Design Principles:
    - Single Responsibility: 2FA operations
    - Dependency Injection: Session + repositories
    - Security First: Lockout, backup codes, encryption
    - Observable: Comprehensive logging
    - Reusable: Used by auth_service during login

Security Design:
    - Secrets are generated with cryptographic randomness
    - Encryption at rest handled by model
    - Failed attempts tracked for brute-force prevention
    - Backup codes are one-time use, hashed storage
    - Lockout after threshold failures
    - Small clock skew tolerance (±30 seconds)

Architecture:
    Endpoints → TotpService (this) → TotpSecretRepository → TotpSecret Model → DB
                     ↓
              core.security.totp (primitives)
                     ↓
              pyotp library
"""

import json
import secrets
import string
from datetime import UTC, datetime, timedelta
from typing import Any, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security.totp import (
    BACKUP_CODE_ALPHABET,
    BACKUP_CODE_COUNT,
    BACKUP_CODE_LENGTH,
    TOTP_INTERVAL_SECONDS,
    generate_backup_codes,
    get_provisioning_uri,
    get_time_remaining,
    new_secret,
    verify_backup_code as verify_backup_code_primitive,
    verify_code,
    verify_code_strict,
)
from app.core.security.password import hash_password, verify_password
from app.models.domain.totp_secret import TotpSecret
from app.repositories.totp_secret_repository import TotpSecretRepository
from app.repositories.user_repository import UserRepository
from app.services.base.base_service import BaseService
from app.utils.logger import logger


# ============================================================
# BUSINESS RULES CONSTANTS
# ============================================================

MAX_SETUP_VERIFICATION_ATTEMPTS = 3    # Setup: 3 wrong codes → new secret
MAX_LOGIN_ATTEMPTS = 5                 # Login: 5 wrong codes → lockout
LOCKOUT_DURATION_MINUTES = 15          # Lockout duration


# ============================================================
# TOTP SERVICE
# ============================================================

class TotpService(BaseService[TotpSecret]):
    """
    Service for two-factor authentication orchestration.
    
    This service encapsulates all 2FA business logic. It coordinates:
    - TotpSecretRepository (persistence)
    - UserRepository (user validation)
    - core.security.totp (primitives)
    - Password verification (for enabling/disabling)
    
    Example:
        service = TotpService(session)
        
        # Setup flow
        setup_data = await service.begin_setup(user.id)
        # User scans QR, enters code
        success = await service.complete_setup(user.id, code)
        
        # Login flow (called by auth_service)
        success = await service.verify_login(user.id, code)
        
        # Disable flow
        await service.disable(user, password)
    """
    
    def __init__(self, session: AsyncSession):
        """
        Initialize TOTP service.
        
        Args:
            session: Async database session
        """
        super().__init__(TotpSecret, session)
        self.session = session
        self.totp_repo = TotpSecretRepository(session)
        self.user_repo = UserRepository(session)
    
    # ============================================================
    # SETUP FLOW
    # ============================================================
    
    async def begin_setup(
        self,
        user_id: UUID,
    ) -> dict[str, Any]:
        """
        Begin 2FA setup for a user.
        
        Business Rules:
            - User must exist and be active
            - If setup already started, replace existing secret
            - Generate backup codes for recovery
            - Return QR URI + backup codes (shown once!)
        
        The user must:
        1. Scan the QR code in their authenticator app
        2. Call complete_setup() with a valid code
        3. Save the backup codes securely
        
        Args:
            user_id: User setting up 2FA
            
        Returns:
            Dict with setup data:
            - secret: Base32 secret (for manual entry)
            - provisioning_uri: otpauth:// URI for QR code
            - backup_codes: List of one-time recovery codes
            - time_remaining: Seconds until code refreshes
            
        Raises:
            ValueError: If user not found or inactive
            
        Example:
            setup = await service.begin_setup(user.id)
            # Return to user:
            # - QR code (rendered from setup["provisioning_uri"])
            # - setup["backup_codes"] (user must save these)
        """
        # Verify user exists and is active
        user = await self.user_repo.get(user_id)
        if user is None:
            raise ValueError(f"User not found: {user_id}")
        if not user.is_active:
            raise ValueError("Cannot set up 2FA for inactive user")
        
        # Check if 2FA already active
        existing = await self.totp_repo.get_by_user_id(user_id)
        if existing and existing.is_verified:
            logger.warning(
                "2FA setup attempted when already active",
                extra={
                    "event": "totp_setup_already_active",
                    "user_id": str(user_id),
                }
            )
            raise ValueError("2FA is already enabled for this account")
        
        # Generate new secret
        secret = new_secret()
        
        # Generate backup codes
        backup_codes = generate_backup_codes()
        
        # Hash backup codes for storage
        hashed_codes = [
            hash_password(code) for code in backup_codes
        ]
        hashed_json = json.dumps(hashed_codes)
        
        # Create or replace TOTP secret record
        totp_secret = TotpSecret(user_id=user_id)
        totp_secret.secret = secret  # Encrypts via model property
        totp_secret.is_verified = False  # Must verify setup
        totp_secret.backup_codes_hash = hashed_json
        
        totp_secret = await self.totp_repo.create_or_replace(totp_secret)
        
        # Generate provisioning URI
        provisioning_uri = get_provisioning_uri(
            secret=secret,
            account_name=user.email,
            issuer_name=None,  # Uses app_name from settings
        )
        
        logger.info(
            "2FA setup initiated",
            extra={
                "event": "totp_setup_started",
                "user_id": str(user_id),
            }
        )
        
        return {
            "secret": secret,
            "provisioning_uri": provisioning_uri,
            "backup_codes": backup_codes,
            "time_remaining": get_time_remaining(),
        }
    
    async def complete_setup(
        self,
        user_id: UUID,
        code: str,
    ) -> bool:
        """
        Complete 2FA setup by verifying the first code.
        
        Business Rules:
            - User must have a pending setup
            - Code must be valid
            - On success: mark 2FA as verified
            - On failure: track attempts (max 3 → restart)
        
        Args:
            user_id: User completing setup
            code: TOTP code from authenticator app
            
        Returns:
            True if setup completed successfully
            
        Raises:
            ValueError: If no pending setup or too many attempts
            
        Example:
            success = await service.complete_setup(user.id, "123456")
            if success:
                # 2FA is now active
                ...
        """
        secret = await self.totp_repo.get_by_user_id(user_id)
        if secret is None:
            raise ValueError("No pending 2FA setup found")
        
        if secret.is_verified:
            raise ValueError("2FA already verified for this account")
        
        # Check lockout (from previous setup attempts)
        if secret.is_locked:
            remaining = secret.remaining_lockout_seconds
            raise ValueError(
                f"Setup locked. Try again in {int(remaining or 0)} seconds"
            )
        
        # Verify code
        if verify_code(secret.secret, code):
            # Mark as verified
            await self.totp_repo.enable(secret)
            
            logger.info(
                "2FA setup completed",
                extra={
                    "event": "totp_setup_completed",
                    "user_id": str(user_id),
                }
            )
            
            return True
        else:
            # Track failed attempt
            await self.totp_repo.record_failed_attempt(
                secret,
                max_attempts=MAX_SETUP_VERIFICATION_ATTEMPTS,
                lockout_minutes=5,  # Shorter for setup
            )
            
            logger.warning(
                "2FA setup verification failed",
                extra={
                    "event": "totp_setup_verification_failed",
                    "user_id": str(user_id),
                    "attempts": secret.failed_attempts,
                }
            )
            
            return False
    
    # ============================================================
    # LOGIN VERIFICATION (Called by AuthService)
    # ============================================================
    
    async def verify_login(
        self,
        user_id: UUID,
        code: str,
    ) -> bool:
        """
        Verify a TOTP code during login.
        
        Business Rules:
            - User must have active 2FA
            - Check lockout before verification
            - Track failed attempts (max 5 → 15 min lockout)
            - On success: reset failure counter
        
        Args:
            user_id: User logging in
            code: TOTP code
            
        Returns:
            True if code is valid, False otherwise
            
        Example:
            # In auth_service.login():
            if user.has_2fa:
                if not await totp_service.verify_login(user.id, code):
                    raise HTTPException(401, "Invalid 2FA code")
        """
        secret = await self.totp_repo.get_by_user_id(user_id)
        if secret is None:
            logger.warning(
                "2FA login attempt but no secret configured",
                extra={
                    "event": "totp_login_no_secret",
                    "user_id": str(user_id),
                }
            )
            return False
        
        if not secret.is_verified:
            logger.warning(
                "2FA login attempt but setup incomplete",
                extra={
                    "event": "totp_login_setup_incomplete",
                    "user_id": str(user_id),
                }
            )
            return False
        
        # Check lockout
        if secret.is_locked:
            logger.warning(
                "2FA login blocked by lockout",
                extra={
                    "event": "totp_login_locked",
                    "user_id": str(user_id),
                    "remaining_seconds": secret.remaining_lockout_seconds,
                }
            )
            return False
        
        # Verify code
        if verify_code(secret.secret, code):
            # Success: reset counters
            await self.totp_repo.record_success(secret)
            
            logger.info(
                "2FA login verified",
                extra={
                    "event": "totp_login_verified",
                    "user_id": str(user_id),
                }
            )
            
            return True
        else:
            # Failure: track and maybe lock
            await self.totp_repo.record_failed_attempt(
                secret,
                max_attempts=MAX_LOGIN_ATTEMPTS,
                lockout_minutes=LOCKOUT_DURATION_MINUTES,
            )
            
            logger.warning(
                "2FA login verification failed",
                extra={
                    "event": "totp_login_failed",
                    "user_id": str(user_id),
                    "attempts": secret.failed_attempts,
                }
            )
            
            return False
    
    # ============================================================
    # BACKUP CODES
    # ============================================================
    
    async def verify_backup_code(
        self,
        user_id: UUID,
        code: str,
    ) -> bool:
        """
        Verify a backup code (recovery flow).
        
        Business Rules:
            - User must have backup codes configured
            - Code must match one of the stored hashes
            - Used code is removed (one-time use)
            - Failed attempts tracked
        
        Args:
            user_id: User using backup code
            code: Backup code from user's saved list
            
        Returns:
            True if code is valid, False otherwise
            
        Example:
            # In auth_service recovery flow:
            if await totp_service.verify_backup_code(user.id, code):
                # Grant access, prompt to reset 2FA
                ...
        """
        secret = await self.totp_repo.get_by_user_id(user_id)
        if secret is None or not secret.backup_codes_hash:
            logger.warning(
                "Backup code attempt but no codes configured",
                extra={
                    "event": "totp_backup_no_codes",
                    "user_id": str(user_id),
                }
            )
            return False
        
        # Parse stored hashes
        try:
            hashes = json.loads(secret.backup_codes_hash)
        except (json.JSONDecodeError, TypeError):
            logger.error(
                "Backup codes JSON corrupted",
                extra={
                    "event": "totp_backup_corrupted",
                    "user_id": str(user_id),
                }
            )
            return False
        
        # Find matching hash
        matched_index = verify_backup_code_primitive(code, hashes)
        
        if matched_index is None:
            # Failed attempt tracking
            await self.totp_repo.record_failed_attempt(
                secret,
                max_attempts=MAX_LOGIN_ATTEMPTS,
                lockout_minutes=LOCKOUT_DURATION_MINUTES,
            )
            
            logger.warning(
                "Backup code verification failed",
                extra={
                    "event": "totp_backup_failed",
                    "user_id": str(user_id),
                }
            )
            
            return False
        
        # Remove used code
        hashes.pop(matched_index)
        updated_json = json.dumps(hashes)
        
        await self.totp_repo.use_backup_code(secret, updated_json)
        
        logger.info(
            "Backup code used",
            extra={
                "event": "totp_backup_used",
                "user_id": str(user_id),
                "remaining_codes": len(hashes),
            }
        )
        
        # Alert if running low
        if len(hashes) <= 2:
            logger.warning(
                "Backup codes running low",
                extra={
                    "event": "totp_backup_low",
                    "user_id": str(user_id),
                    "remaining": len(hashes),
                }
            )
        
        return True
    
    async def regenerate_backup_codes(
        self,
        user_id: UUID,
    ) -> list[str]:
        """
        Regenerate all backup codes for a user.
        
        Invalidates all previous backup codes and returns new ones.
        
        Args:
            user_id: User regenerating codes
            
        Returns:
            List of new plaintext backup codes (show to user once)
            
        Raises:
            ValueError: If user has no active 2FA
            
        Example:
            new_codes = await service.regenerate_backup_codes(user.id)
            # Display to user: "Save these codes!"
        """
        secret = await self.totp_repo.get_by_user_id(user_id)
        if secret is None or not secret.is_verified:
            raise ValueError("2FA is not active for this account")
        
        # Generate new codes
        backup_codes = generate_backup_codes()
        hashed_codes = [hash_password(code) for code in backup_codes]
        hashed_json = json.dumps(hashed_codes)
        
        # Replace
        await self.totp_repo.store_backup_codes(secret, hashed_json)
        
        logger.info(
            "Backup codes regenerated",
            extra={
                "event": "totp_backup_regenerated",
                "user_id": str(user_id),
                "count": len(backup_codes),
            }
        )
        
        return backup_codes
    
    async def has_backup_codes(self, user_id: UUID) -> bool:
        """Check if user has backup codes configured."""
        secret = await self.totp_repo.get_by_user_id(user_id)
        return secret is not None and secret.has_backup_codes
    
    async def count_remaining_backup_codes(self, user_id: UUID) -> int:
        """Count remaining backup codes."""
        secret = await self.totp_repo.get_by_user_id(user_id)
        if secret is None or not secret.backup_codes_hash:
            return 0
        
        try:
            hashes = json.loads(secret.backup_codes_hash)
            return len(hashes)
        except (json.JSONDecodeError, TypeError):
            return 0
    
    # ============================================================
    # DISABLE 2FA
    # ============================================================
    
    async def disable(
        self,
        user_id: UUID,
        password: str,
    ) -> bool:
        """
        Disable 2FA for a user.
        
        Business Rules:
            - User must have active 2FA
            - Password verification required (security)
            - Clears backup codes
            - Failed password attempt rejects
        
        Args:
            user_id: User disabling 2FA
            password: User's current password (for confirmation)
            
        Returns:
            True if disabled successfully
            
        Raises:
            ValueError: If password invalid or no 2FA active
            
        Example:
            success = await service.disable(user.id, password)
            # 2FA is now off
        """
        # Verify user
        user = await self.user_repo.get(user_id)
        if user is None:
            raise ValueError(f"User not found: {user_id}")
        
        # Verify password (security check)
        if not verify_password(password, user.password_hash):
            logger.warning(
                "2FA disable failed: invalid password",
                extra={
                    "event": "totp_disable_invalid_password",
                    "user_id": str(user_id),
                }
            )
            raise ValueError("Invalid password")
        
        # Get 2FA secret
        secret = await self.totp_repo.get_by_user_id(user_id)
        if secret is None or not secret.is_verified:
            raise ValueError("2FA is not active for this account")
        
        # Clear backup codes and disable
        await self.totp_repo.clear_backup_codes(secret)
        await self.totp_repo.disable(secret)
        
        logger.warning(
            "2FA disabled",
            extra={
                "event": "totp_disabled",
                "user_id": str(user_id),
            }
        )
        
        return True
    
    # ============================================================
    # STATUS QUERIES
    # ============================================================
    
    async def get_status(self, user_id: UUID) -> dict[str, Any]:
        """
        Get 2FA status for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            Dict with status info:
            - enabled: bool (2FA is active)
            - verified: bool (setup completed)
            - locked: bool (currently locked out)
            - has_backup_codes: bool
            - backup_codes_remaining: int
            - last_used_at: Optional[datetime]
        """
        secret = await self.totp_repo.get_by_user_id(user_id)
        
        if secret is None:
            return {
                "enabled": False,
                "verified": False,
                "locked": False,
                "has_backup_codes": False,
                "backup_codes_remaining": 0,
                "last_used_at": None,
            }
        
        backup_count = await self.count_remaining_backup_codes(user_id)
        
        return {
            "enabled": secret.is_verified,
            "verified": secret.is_verified,
            "locked": secret.is_locked,
            "has_backup_codes": secret.has_backup_codes,
            "backup_codes_remaining": backup_count,
            "last_used_at": (
                secret.last_used_at.isoformat() 
                if secret.last_used_at else None
            ),
        }
    
    async def is_enabled(self, user_id: UUID) -> bool:
        """Check if user has active 2FA."""
        secret = await self.totp_repo.get_by_user_id(user_id)
        return secret is not None and secret.is_active
    
    async def is_verified(self, user_id: UUID) -> bool:
        """Check if user has completed 2FA setup."""
        secret = await self.totp_repo.get_by_user_id(user_id)
        return secret is not None and secret.is_verified
    
    # ============================================================
    # ADMIN OPERATIONS
    # ============================================================
    
    async def admin_reset(
        self,
        user_id: UUID,
        actor_id: UUID,
        reason: Optional[str] = None,
    ) -> bool:
        """
        Admin-forced 2FA reset (user lost device).
        
        Business Rules:
            - Only called by admins
            - Deletes 2FA secret entirely
            - User must set up fresh 2FA
            - Logged with actor + reason
        
        Args:
            user_id: User whose 2FA to reset
            actor_id: Admin performing reset
            reason: Optional reason for audit
            
        Returns:
            True if reset successful
        """
        secret = await self.totp_repo.get_by_user_id(user_id)
        if secret is None:
            logger.info(
                "Admin 2FA reset but no secret found",
                extra={
                    "event": "totp_admin_reset_no_secret",
                    "user_id": str(user_id),
                    "actor_id": str(actor_id),
                }
            )
            return False
        
        await self.totp_repo.delete(secret)
        
        logger.warning(
            "2FA reset by admin",
            extra={
                "event": "totp_admin_reset",
                "user_id": str(user_id),
                "actor_id": str(actor_id),
                "reason": reason,
            }
        )
        
        return True
    
    async def admin_unlock(
        self,
        user_id: UUID,
        actor_id: UUID,
    ) -> bool:
        """
        Admin-unlock a locked 2FA.
        
        Args:
            user_id: User to unlock
            actor_id: Admin performing unlock
            
        Returns:
            True if unlocked
        """
        secret = await self.totp_repo.get_by_user_id(user_id)
        if secret is None:
            return False
        
        await self.totp_repo.unlock(secret)
        
        logger.info(
            "2FA unlocked by admin",
            extra={
                "event": "totp_admin_unlock",
                "user_id": str(user_id),
                "actor_id": str(actor_id),
            }
        )
        
        return True


# ============================================================
# SIMPLE FUNCTION-BASED API (Backward Compatible)
# ============================================================

def setup_totp() -> str:
    """
    Return a new secret to encrypt and associate with a user.
    
    NOTE: This is a low-level primitive. For full 2FA setup flow,
    use TotpService.begin_setup() which handles persistence,
    QR generation, and backup codes.
    
    Returns:
        Base32-encoded TOTP secret
    """
    return new_secret()


def verify_totp(secret: str, code: str) -> bool:
    """
    Verify a user-provided current code.
    
    NOTE: This is a low-level primitive. For login flow with
    lockout tracking, use TotpService.verify_login().
    
    Args:
        secret: Base32 TOTP secret
        code: User-provided 6-digit code
        
    Returns:
        True if code is valid
    """
    return verify_code(secret, code)


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    # Service class
    "TotpService",
    
    # Low-level functions (backward compatible)
    "setup_totp",
    "verify_totp",
    
    # Constants
    "MAX_SETUP_VERIFICATION_ATTEMPTS",
    "MAX_LOGIN_ATTEMPTS",
    "LOCKOUT_DURATION_MINUTES",
]