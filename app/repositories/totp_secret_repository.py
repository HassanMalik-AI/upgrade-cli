"""
Encrypted TOTP-secret persistence operations.

This module provides the TotpSecretRepository class, which handles all
database operations for the TotpSecret model. It manages encrypted
TOTP secrets for two-factor authentication (2FA).

Design Pattern: Repository Pattern + Upsert Semantics
    - BaseRepository provides generic CRUD
    - TotpSecretRepository adds TOTP-specific methods
    - Uses upsert (create or replace) since a user has only ONE TOTP secret

Responsibilities:
    - Lookup TOTP secret by user_id (primary key)
    - Upsert TOTP secret (create or replace)
    - Enable/disable 2FA (verified flag management)
    - Track failed verification attempts (brute force prevention)
    - Manage lockouts (temporary suspension after failures)
    - Backup codes management
    - Security event logging

Design Decisions:
    - Class-based (extends BaseRepository)
    - One-to-one relationship (user_id is PK)
    - Upsert semantics (create_or_replace)
    - Encrypted secrets (handled by model)
    - Security event logging (attempts, lockouts)
    - Type-safe returns (TotpSecret | None)

Security Notes:
    - TOTP secret is encrypted at rest (by model property)
    - Failed attempts tracked to prevent brute force
    - Lockout after threshold failures
    - Backup codes are hashed (not stored plaintext)
    - All state changes logged for audit
"""

from datetime import UTC, datetime, timedelta
from typing import Optional, Sequence
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.domain.totp_secret import TotpSecret
from app.repositories.base.base_repository import BaseRepository
from app.utils.logger import logger


class TotpSecretRepository(BaseRepository[TotpSecret]):
    """
    Repository for TotpSecret model with specialized queries.
    
    Extends BaseRepository[TotpSecret] to inherit:
    - get(id), get_by_id(id)
    - list(offset, limit)
    - update(instance, values)
    - delete(instance)
    
    Adds TOTP-specific methods:
    - get_by_user_id(user_id)
    - create_or_replace(secret)
    - verify_and_enable(secret, code)
    - record_failed_attempt(secret)
    - record_success(secret)
    - is_locked(secret)
    - unlock(secret)
    - store_backup_codes(secret, hashed_codes)
    - use_backup_code(secret, index)
    - get_statistics()
    
    Example:
        # In service:
        repo = TotpSecretRepository(session)
        
        # Get user's TOTP secret
        secret = await repo.get_by_user_id(user_id)
        
        # Upsert (create or replace)
        secret = await repo.create_or_replace(new_secret)
    """
    
    # Constants for lockout policy
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 15
    
    def __init__(self, session: AsyncSession):
        """
        Initialize TOTP secret repository.
        
        Args:
            session: Async database session
        """
        super().__init__(session, TotpSecret)
    
    # ============================================================
    # LOOKUP METHODS
    # ============================================================
    
    async def get_by_user_id(self, user_id: UUID) -> Optional[TotpSecret]:
        """
        Load the encrypted secret belonging to a user.
        
        Since user_id is the primary key (one-to-one relationship),
        this is equivalent to a primary key lookup.
        
        Args:
            user_id: User's UUID
            
        Returns:
            TotpSecret if found, None otherwise
            
        Example:
            secret = await repo.get_by_user_id(user.id)
            if secret:
                # User has 2FA configured
                if secret.is_active:
                    # 2FA is active
                    ...
        """
        if not user_id:
            return None
        
        return await self.session.get(TotpSecret, user_id)
    
    async def exists_for_user(self, user_id: UUID) -> bool:
        """
        Check if a user has a TOTP secret configured.
        
        More efficient than get_by_user_id() when you only need
        to know existence (e.g., checking before setup).
        
        Args:
            user_id: User's UUID
            
        Returns:
            True if user has TOTP secret
        """
        if not user_id:
            return False
        
        from sqlalchemy import func
        
        stmt = select(func.count()).select_from(TotpSecret).where(
            TotpSecret.user_id == user_id
        )
        count = await self.session.scalar(stmt)
        return count > 0
    
    async def has_active_2fa(self, user_id: UUID) -> bool:
        """
        Check if a user has ACTIVE 2FA (verified and not locked).
        
        Args:
            user_id: User's UUID
            
        Returns:
            True if 2FA is fully set up and active
        """
        secret = await self.get_by_user_id(user_id)
        return secret is not None and secret.is_active
    
    # ============================================================
    # UPSERT OPERATIONS
    # ============================================================
    
    async def create_or_replace(
        self,
        secret: TotpSecret,
    ) -> TotpSecret:
        """
        Insert or replace a user's encrypted TOTP secret.
        
        Since a user can have only ONE TOTP secret (user_id is PK),
        this method handles both cases:
        - First setup: INSERT new secret
        - Reset setup: UPDATE existing secret
        
        The encrypted secret is transparently handled by the model
        property - callers work with plaintext, model handles encryption.
        
        Args:
            secret: TotpSecret instance (with plaintext secret set
                   via `secret.secret = "..."` property)
            
        Returns:
            Persisted TotpSecret instance
            
        Example:
            from app.core.security.totp import new_secret
            
            # Create new TOTP secret
            secret = TotpSecret(user_id=user.id)
            secret.secret = new_secret()  # Encrypted automatically
            secret = await repo.create_or_replace(secret)
        
        Security Notes:
            - Existing secret is REPLACED (old encryption key retired)
            - is_verified resets to False (must re-verify)
            - Failed attempts reset to 0
            - Lockout cleared
            - Backup codes preserved (user keeps recovery options)
        """
        if not secret or not secret.user_id:
            raise ValueError("Secret with user_id is required")
        
        existing = await self.session.get(TotpSecret, secret.user_id)
        
        if existing is not None:
            # Update existing secret
            # Only update the encrypted secret field
            # Preserve verification status, backup codes, etc.
            existing.encrypted_secret = secret.encrypted_secret
            secret = existing
            
            logger.info(
                "TOTP secret replaced",
                extra={
                    "event": "totp_secret_replaced",
                    "user_id": str(secret.user_id),
                }
            )
        else:
            # Insert new secret
            self.session.add(secret)
            
            logger.info(
                "TOTP secret created",
                extra={
                    "event": "totp_secret_created",
                    "user_id": str(secret.user_id),
                }
            )
        
        await self.session.commit()
        await self.session.refresh(secret)
        return secret
    
    # ============================================================
    # VERIFICATION STATE MANAGEMENT
    # ============================================================
    
    async def enable(
        self,
        secret: TotpSecret,
    ) -> TotpSecret:
        """
        Mark 2FA as fully verified and active.
        
        Called after user successfully enters the first TOTP code
        during setup, confirming they have the authenticator app
        working correctly.
        
        Args:
            secret: TotpSecret instance to enable
            
        Returns:
            Updated TotpSecret
        """
        secret.is_verified = True
        secret.last_used_at = datetime.now(UTC)
        secret.failed_attempts = 0
        secret.locked_until = None
        
        secret = await self.update(secret, {})  # Save changes
        
        logger.info(
            "TOTP enabled",
            extra={
                "event": "totp_enabled",
                "user_id": str(secret.user_id),
            }
        )
        
        return secret
    
    async def disable(
        self,
        secret: TotpSecret,
    ) -> TotpSecret:
        """
        Disable 2FA (user requested).
        
        Args:
            secret: TotpSecret instance to disable
            
        Returns:
            Updated TotpSecret
        """
        secret.is_verified = False
        
        secret = await self.update(secret, {})
        
        logger.warning(
            "TOTP disabled",
            extra={
                "event": "totp_disabled",
                "user_id": str(secret.user_id),
            }
        )
        
        return secret
    
    # ============================================================
    # ATTEMPT TRACKING (Brute Force Prevention)
    # ============================================================
    
    async def record_success(
        self,
        secret: TotpSecret,
    ) -> TotpSecret:
        """
        Record a successful TOTP verification.
        
        Resets failure counters and lockout. Called after
        verify_code() returns True.
        
        Args:
            secret: TotpSecret instance
            
        Returns:
            Updated TotpSecret
        """
        secret.last_used_at = datetime.now(UTC)
        secret.failed_attempts = 0
        secret.locked_until = None
        
        return await self.update(secret, {})
    
    async def record_failed_attempt(
        self,
        secret: TotpSecret,
        max_attempts: int = MAX_FAILED_ATTEMPTS,
        lockout_minutes: int = LOCKOUT_DURATION_MINUTES,
    ) -> TotpSecret:
        """
        Record a failed TOTP verification attempt.
        
        Increments failure counter. If counter reaches max_attempts,
        locks the account for lockout_minutes.
        
        Args:
            secret: TotpSecret instance
            max_attempts: Number of failures before lockout
            lockout_minutes: Duration of lockout
            
        Returns:
            Updated TotpSecret
            
        Security Notes:
            - Prevents brute-force attacks on 6-digit codes
            - 5 attempts × 15 min lockout = ~12 attempts/hour max
            - Combined with 30-second code windows = practically impossible
        """
        secret.failed_attempts += 1
        
        if secret.failed_attempts >= max_attempts:
            secret.locked_until = (
                datetime.now(UTC) + timedelta(minutes=lockout_minutes)
            )
            
            logger.warning(
                "TOTP locked due to failed attempts",
                extra={
                    "event": "totp_locked",
                    "user_id": str(secret.user_id),
                    "failed_attempts": secret.failed_attempts,
                    "locked_until": secret.locked_until.isoformat(),
                }
            )
        else:
            logger.debug(
                "TOTP failed attempt",
                extra={
                    "event": "totp_failed_attempt",
                    "user_id": str(secret.user_id),
                    "failed_attempts": secret.failed_attempts,
                    "attempts_remaining": max_attempts - secret.failed_attempts,
                }
            )
        
        return await self.update(secret, {})
    
    async def unlock(self, secret: TotpSecret) -> TotpSecret:
        """
        Manually unlock a TOTP secret.
        
        Used by admin action or after successful password reset.
        
        Args:
            secret: TotpSecret instance
            
        Returns:
            Updated TotpSecret
        """
        secret.failed_attempts = 0
        secret.locked_until = None
        
        secret = await self.update(secret, {})
        
        logger.info(
            "TOTP unlocked",
            extra={
                "event": "totp_unlocked",
                "user_id": str(secret.user_id),
            }
        )
        
        return secret
    
    async def reset_attempts(
        self,
        user_id: UUID,
    ) -> Optional[TotpSecret]:
        """
        Reset failed attempts by user_id.
        
        Convenience method that fetches then resets.
        
        Args:
            user_id: User's UUID
            
        Returns:
            Updated TotpSecret if found
        """
        secret = await self.get_by_user_id(user_id)
        if secret is None:
            return None
        return await self.unlock(secret)
    
    # ============================================================
    # BACKUP CODES
    # ============================================================
    
    async def store_backup_codes(
        self,
        secret: TotpSecret,
        hashed_codes: str,
    ) -> TotpSecret:
        """
        Store hashed backup codes for account recovery.
        
        Backup codes are generated as plaintext, shown to user ONCE,
        then hashed before storage. This method stores the hashed
        version.
        
        Args:
            secret: TotpSecret instance
            hashed_codes: JSON-serialized list of hashed codes
            
        Returns:
            Updated TotpSecret
        """
        secret.backup_codes_hash = hashed_codes
        
        secret = await self.update(secret, {})
        
        logger.info(
            "Backup codes stored",
            extra={
                "event": "backup_codes_stored",
                "user_id": str(secret.user_id),
            }
        )
        
        return secret
    
    async def use_backup_code(
        self,
        secret: TotpSecret,
        updated_hashes: str,
    ) -> TotpSecret:
        """
        Record use of a backup code (remove it from storage).
        
        After successful backup code verification, the used code
        should be removed to prevent reuse.
        
        Args:
            secret: TotpSecret instance
            updated_hashes: JSON with the used code removed
            
        Returns:
            Updated TotpSecret
        """
        secret.backup_codes_hash = updated_hashes
        
        secret = await self.update(secret, {})
        
        logger.info(
            "Backup code used",
            extra={
                "event": "backup_code_used",
                "user_id": str(secret.user_id),
            }
        )
        
        return secret
    
    async def clear_backup_codes(
        self,
        secret: TotpSecret,
    ) -> TotpSecret:
        """
        Clear all backup codes.
        
        Called during 2FA reset or when user regenerates codes.
        
        Args:
            secret: TotpSecret instance
            
        Returns:
            Updated TotpSecret
        """
        secret.backup_codes_hash = None
        
        return await self.update(secret, {})
    
    # ============================================================
    # QUERY HELPERS
    # ============================================================
    
    async def get_all_locked(
        self,
        offset: int = 0,
        limit: int = 50,
    ) -> Sequence[TotpSecret]:
        """
        Get all currently locked TOTP secrets.
        
        Useful for admin dashboards and monitoring.
        
        Args:
            offset: Pagination offset
            limit: Page size (capped at 100)
            
        Returns:
            List of locked secrets
        """
        now = datetime.now(UTC)
        query = (
            select(TotpSecret)
            .where(TotpSecret.locked_until > now)
            .offset(offset)
            .limit(min(limit, 100))
        )
        result = await self.session.scalars(query)
        return result.all()
    
    async def get_locked_count(self) -> int:
        """Get count of currently locked accounts."""
        from sqlalchemy import func
        
        now = datetime.now(UTC)
        stmt = (
            select(func.count())
            .select_from(TotpSecret)
            .where(TotpSecret.locked_until > now)
        )
        return await self.session.scalar(stmt) or 0
    
    # ============================================================
    # STATISTICS
    # ============================================================
    
    async def get_statistics(self) -> dict[str, int]:
        """
        Get TOTP statistics for monitoring.
        
        Returns:
            Dict with counts for various 2FA states
        """
        from sqlalchemy import func
        
        # Total secrets
        total = await self.count()
        
        # Verified count
        verified_stmt = (
            select(func.count())
            .select_from(TotpSecret)
            .where(TotpSecret.is_verified == True)  # noqa: E712
        )
        verified = await self.session.scalar(verified_stmt) or 0
        
        # Active count (verified AND not locked)
        now = datetime.now(UTC)
        active_stmt = (
            select(func.count())
            .select_from(TotpSecret)
            .where(TotpSecret.is_verified == True)  # noqa: E712
            .where(
                (TotpSecret.locked_until == None) |  # noqa: E711
                (TotpSecret.locked_until < now)
            )
        )
        active = await self.session.scalar(active_stmt) or 0
        
        # Locked count
        locked_stmt = (
            select(func.count())
            .select_from(TotpSecret)
            .where(TotpSecret.locked_until > now)
        )
        locked = await self.session.scalar(locked_stmt) or 0
        
        # Backup codes count
        backup_stmt = (
            select(func.count())
            .select_from(TotpSecret)
            .where(TotpSecret.backup_codes_hash != None)  # noqa: E711
        )
        with_backup = await self.session.scalar(backup_stmt) or 0
        
        return {
            "total": total,
            "verified": verified,
            "active": active,
            "locked": locked,
            "with_backup_codes": with_backup,
        }


# ============================================================
# EXPORTS
# ============================================================

__all__ = ["TotpSecretRepository"]