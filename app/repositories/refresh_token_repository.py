"""
Refresh-token persistence and revocation queries.

This module provides the RefreshTokenRepository class, which handles all
database operations for the RefreshToken model. It manages JWT refresh
tokens used for session continuity.

Design Pattern: Repository Pattern + Token Lifecycle Management
    - BaseRepository provides generic CRUD
    - RefreshTokenRepository adds token-specific methods
    - Handles create, verify, revoke, and cleanup operations

Responsibilities:
    - Token persistence (hashed only, never plaintext)
    - Active token lookup (not revoked, not expired)
    - Token revocation (logout, security response)
    - Expired token cleanup (housekeeping)
    - Session tracking (which devices are logged in)
    - Token rotation support (replace old with new)
    - Bulk operations (revoke all user tokens)

Design Decisions:
    - Class-based (extends BaseRepository)
    - Async methods (all DB operations)
    - Type-safe returns (RefreshToken | None, list[RefreshToken])
    - Bounded queries (prevent OOM)
    - Hash-based lookup (never lookup by raw token)
    - Batch revocation (user logout = all sessions)
    - Time-based expiration (enforced in queries)

Security Notes:
    - Raw tokens NEVER stored (only SHA-256 hashes)
    - Revocation instead of deletion (audit trail)
    - Expiration enforced at query level
    - Bulk cleanup for old tokens
    - Session tracking for user awareness
    - Cascade delete when user deleted
"""

from datetime import UTC, datetime, timedelta
from typing import Any, Optional, Sequence
from uuid import UUID

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.domain.refresh_token import RefreshToken
from app.repositories.base.base_repository import BaseRepository
from app.utils.logger import logger


class RefreshTokenRepository(BaseRepository[RefreshToken]):
    """
    Repository for RefreshToken model with specialized queries.
    
    Extends BaseRepository[RefreshToken] to inherit:
    - get(id), get_by_id(id)
    - list(offset, limit)
    - create(instance)
    - update(instance, values)
    - delete(instance)
    
    Adds token-specific methods:
    - find_active(token_hash)
    - create_token(...)
    - revoke(token)
    - revoke_all_for_user(user_id)
    - delete_expired()
    - get_active_sessions(user_id)
    - get_user_tokens(user_id)
    - count_active_by_user(user_id)
    - get_statistics()
    
    Example:
        # In service:
        repo = RefreshTokenRepository(session)
        
        # Create token
        token = await repo.create_token(
            user_id=user.id,
            token_hash=hash_token(raw_token),
            expires_at=datetime.now(UTC) + timedelta(days=30),
        )
        
        # Find active token
        token = await repo.find_active(token_hash)
        if token and token.is_valid:
            ...
    """
    
    def __init__(self, session: AsyncSession):
        """
        Initialize refresh token repository.
        
        Args:
            session: Async database session
        """
        super().__init__(session, RefreshToken)
    
    # ============================================================
    # TOKEN LOOKUP
    # ============================================================
    
    async def find_active(self, token_hash: str) -> Optional[RefreshToken]:
        """
        Find a non-revoked, non-expired hashed token.
        
        This is the primary method for token validation. It ensures:
        - Token hash exists in database
        - Token is not revoked (revoked_at IS NULL)
        - Token is not expired (expires_at > now)
        
        Args:
            token_hash: SHA-256 hash of the raw token
            
        Returns:
            RefreshToken if active, None otherwise
            
        Example:
            raw_token = "eyJhbGciOiJIUzI1NiIs..."
            token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
            
            token = await repo.find_active(token_hash)
            if token is None:
                raise HTTPException(401, "Invalid or expired refresh token")
            
            # Token is valid, continue with refresh
            new_access = create_access_token(token.user_id)
        
        Security Notes:
            - Never lookup by raw token (only hash)
            - Query enforces both revocation AND expiration
            - Returns None for security (no info leak)
        """
        if not token_hash:
            return None
        
        stmt = select(RefreshToken).where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked_at.is_(None),
            RefreshToken.expires_at > datetime.now(UTC),
        )
        
        return await self.session.scalar(stmt)
    
    async def find_by_hash(
        self,
        token_hash: str,
    ) -> Optional[RefreshToken]:
        """
        Find a token by hash regardless of status.
        
        Unlike find_active(), this includes revoked and expired tokens.
        Used for audit trails and history queries.
        
        Args:
            token_hash: SHA-256 hash of the raw token
            
        Returns:
            RefreshToken if found (any status), None otherwise
        """
        if not token_hash:
            return None
        
        stmt = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        return await self.session.scalar(stmt)
    
    async def exists(self, token_hash: str) -> bool:
        """
        Check if a token hash exists (any status).
        
        More efficient than find_by_hash() when you only need existence.
        
        Args:
            token_hash: SHA-256 hash
            
        Returns:
            True if token exists
        """
        if not token_hash:
            return False
        
        stmt = select(func.count()).select_from(RefreshToken).where(
            RefreshToken.token_hash == token_hash
        )
        count = await self.session.scalar(stmt)
        return count > 0
    
    # ============================================================
    # TOKEN CREATION
    # ============================================================
    
    async def create_token(
        self,
        user_id: UUID,
        token_hash: str,
        expires_at: datetime,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> RefreshToken:
        """
        Persist a hashed refresh token with metadata.
        
        IMPORTANT: The caller must hash the raw token before calling
        this method. Never pass the raw token here.
        
        Args:
            user_id: Owner user UUID
            token_hash: SHA-256 hash of the raw refresh token
            expires_at: When this token expires (UTC)
            user_agent: Optional device/browser info
            ip_address: Optional IP address
            
        Returns:
            Created RefreshToken instance
            
        Example:
            # In auth service:
            raw_token = create_refresh_token(user.id)
            token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
            
            token = await repo.create_token(
                user_id=user.id,
                token_hash=token_hash,
                expires_at=datetime.now(UTC) + timedelta(days=30),
                user_agent=request.headers.get("User-Agent"),
                ip_address=request.client.host,
            )
            
            # Return raw_token to client (they store it)
            # Store token_hash in DB (we store it)
        """
        if not user_id:
            raise ValueError("user_id is required")
        
        if not token_hash:
            raise ValueError("token_hash is required")
        
        if expires_at <= datetime.now(UTC):
            raise ValueError("expires_at must be in the future")
        
        # Normalize user_agent length (prevent oversized)
        if user_agent and len(user_agent) > 500:
            user_agent = user_agent[:500]
        
        # Normalize IP length
        if ip_address and len(ip_address) > 45:
            ip_address = ip_address[:45]
        
        token = RefreshToken(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        
        token = await self.create(token)
        
        logger.info(
            "Refresh token created",
            extra={
                "event": "refresh_token_created",
                "user_id": str(user_id),
                "expires_at": expires_at.isoformat(),
                "has_user_agent": bool(user_agent),
                "has_ip": bool(ip_address),
            }
        )
        
        return token
    
    # ============================================================
    # TOKEN REVOCATION
    # ============================================================
    
    async def revoke(self, token: RefreshToken) -> RefreshToken:
        """
        Revoke a refresh token without deleting it.
        
        Revocation sets revoked_at timestamp (soft invalidation).
        This preserves the audit trail while preventing token use.
        
        Args:
            token: RefreshToken instance to revoke
            
        Returns:
            Updated RefreshToken
        """
        if token.revoked_at is not None:
            # Already revoked - idempotent
            return token
        
        token.revoked_at = datetime.now(UTC)
        token = await self.update(token, {})
        
        logger.info(
            "Refresh token revoked",
            extra={
                "event": "refresh_token_revoked",
                "user_id": str(token.user_id),
                "token_id": str(token.id),
            }
        )
        
        return token
    
    async def revoke_by_hash(self, token_hash: str) -> bool:
        """
        Revoke a token by hash.
        
        Convenience method for logout flows where the token
        is provided as raw and hashed by the caller.
        
        Args:
            token_hash: SHA-256 hash of token to revoke
            
        Returns:
            True if revoked, False if not found
        """
        token = await self.find_active(token_hash)
        if token is None:
            return False
        
        await self.revoke(token)
        return True
    
    async def revoke_all_for_user(
        self,
        user_id: UUID,
        except_token_hash: Optional[str] = None,
    ) -> int:
        """
        Revoke all refresh tokens for a user.
        
        Used for:
        - User-initiated "logout everywhere"
        - Password change (security best practice)
        - Account compromise response
        - Admin-forced logout
        
        Args:
            user_id: User whose tokens to revoke
            except_token_hash: Optional token to keep (current session)
            
        Returns:
            Number of tokens revoked
            
        Example:
            # Password change flow:
            await repo.revoke_all_for_user(user.id)
            # User must re-login on all devices
            
            # Logout of all other devices:
            await repo.revoke_all_for_user(
                user.id,
                except_token_hash=current_token_hash,
            )
            # Keep current session, revoke others
        """
        if not user_id:
            return 0
        
        now = datetime.now(UTC)
        
        # Build query conditions
        conditions = [
            RefreshToken.user_id == user_id,
            RefreshToken.revoked_at.is_(None),  # Only active
            RefreshToken.expires_at > now,       # Only non-expired
        ]
        
        if except_token_hash:
            conditions.append(RefreshToken.token_hash != except_token_hash)
        
        # Bulk update
        stmt = (
            update(RefreshToken)
            .where(*conditions)
            .values(revoked_at=now)
            .returning(RefreshToken.id)
        )
        
        result = await self.session.execute(stmt)
        await self.session.commit()
        
        revoked_ids = result.scalars().all()
        count = len(revoked_ids)
        
        if count > 0:
            logger.warning(
                "All user tokens revoked",
                extra={
                    "event": "refresh_tokens_bulk_revoked",
                    "user_id": str(user_id),
                    "count": count,
                    "except_current": bool(except_token_hash),
                }
            )
        
        return count
    
    # ============================================================
    # SESSION QUERIES
    # ============================================================
    
    async def get_active_sessions(
        self,
        user_id: UUID,
    ) -> Sequence[RefreshToken]:
        """
        Get all active sessions (tokens) for a user.
        
        Used to display "active devices" in account settings.
        
        Args:
            user_id: User UUID
            
        Returns:
            List of active refresh tokens
        """
        if not user_id:
            return []
        
        now = datetime.now(UTC)
        stmt = (
            select(RefreshToken)
            .where(
                RefreshToken.user_id == user_id,
                RefreshToken.revoked_at.is_(None),
                RefreshToken.expires_at > now,
            )
            .order_by(RefreshToken.created_at.desc())
        )
        
        result = await self.session.scalars(stmt)
        return result.all()
    
    async def get_user_tokens(
        self,
        user_id: UUID,
        offset: int = 0,
        limit: int = 50,
    ) -> Sequence[RefreshToken]:
        """
        Get all tokens for a user (including revoked/expired).
        
        For audit and history views.
        
        Args:
            user_id: User UUID
            offset: Pagination offset
            limit: Page size
            
        Returns:
            List of tokens
        """
        if not user_id:
            return []
        
        stmt = (
            select(RefreshToken)
            .where(RefreshToken.user_id == user_id)
            .order_by(RefreshToken.created_at.desc())
            .offset(offset)
            .limit(min(limit, 100))
        )
        
        result = await self.session.scalars(stmt)
        return result.all()
    
    async def count_active_by_user(self, user_id: UUID) -> int:
        """
        Count active sessions for a user.
        
        Useful for enforcing "max devices" policies.
        
        Args:
            user_id: User UUID
            
        Returns:
            Number of active tokens
        """
        if not user_id:
            return 0
        
        now = datetime.now(UTC)
        stmt = (
            select(func.count())
            .select_from(RefreshToken)
            .where(
                RefreshToken.user_id == user_id,
                RefreshToken.revoked_at.is_(None),
                RefreshToken.expires_at > now,
            )
        )
        
        return await self.session.scalar(stmt) or 0
    
    async def get_by_ip(
        self,
        user_id: UUID,
        ip_address: str,
    ) -> Sequence[RefreshToken]:
        """
        Find tokens by user and IP.
        
        Useful for detecting multiple logins from same location
        or suspicious patterns.
        
        Args:
            user_id: User UUID
            ip_address: IP address
            
        Returns:
            Matching tokens
        """
        if not user_id or not ip_address:
            return []
        
        now = datetime.now(UTC)
        stmt = (
            select(RefreshToken)
            .where(
                RefreshToken.user_id == user_id,
                RefreshToken.ip_address == ip_address,
                RefreshToken.revoked_at.is_(None),
                RefreshToken.expires_at > now,
            )
        )
        
        result = await self.session.scalars(stmt)
        return result.all()
    
    # ============================================================
    # TOKEN ROTATION
    # ============================================================
    
    async def rotate(
        self,
        old_token: RefreshToken,
        new_token_hash: str,
        expires_at: datetime,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> RefreshToken:
        """
        Rotate a refresh token: revoke old, create new.
        
        Token rotation improves security by:
        - Limiting token lifetime
        - Detecting token theft
        - Enabling session invalidation
        
        Args:
            old_token: Existing token to rotate
            new_token_hash: Hash of new raw token
            expires_at: New expiration
            user_agent: Optional metadata
            ip_address: Optional metadata
            
        Returns:
            Newly created RefreshToken
        """
        # Revoke old token
        await self.revoke(old_token)
        
        # Create new token with same user
        new_token = await self.create_token(
            user_id=old_token.user_id,
            token_hash=new_token_hash,
            expires_at=expires_at,
            user_agent=user_agent or old_token.user_agent,
            ip_address=ip_address or old_token.ip_address,
        )
        
        logger.info(
            "Refresh token rotated",
            extra={
                "event": "refresh_token_rotated",
                "user_id": str(old_token.user_id),
                "old_token_id": str(old_token.id),
                "new_token_id": str(new_token.id),
            }
        )
        
        return new_token
    
    # ============================================================
    # CLEANUP OPERATIONS
    # ============================================================
    
    async def delete_expired(self, grace_period_hours: int = 24) -> int:
        """
        Delete expired refresh tokens.
        
        Called periodically (cron job) to clean up old records.
        Uses a grace period to allow for audit trail inspection.
        
        Args:
            grace_period_hours: Keep expired tokens for this long
            
        Returns:
            Number of tokens deleted
            
        Example:
            # Daily cleanup job:
            count = await repo.delete_expired()
            logger.info(f"Cleaned up {count} expired tokens")
        """
        cutoff = datetime.now(UTC) - timedelta(hours=grace_period_hours)
        
        stmt = delete(RefreshToken).where(
            RefreshToken.expires_at <= cutoff
        )
        
        result = await self.session.execute(stmt)
        await self.session.commit()
        
        count = result.rowcount or 0
        
        if count > 0:
            logger.info(
                "Expired tokens deleted",
                extra={
                    "event": "expired_tokens_deleted",
                    "count": count,
                    "cutoff": cutoff.isoformat(),
                }
            )
        
        return count
    
    async def delete_revoked(
        self,
        older_than_days: int = 30,
    ) -> int:
        """
        Delete revoked tokens older than specified days.
        
        Revoked tokens are kept for audit trail, but eventually
        need cleanup to prevent table bloat.
        
        Args:
            older_than_days: Delete revoked tokens older than this
            
        Returns:
            Number of tokens deleted
        """
        cutoff = datetime.now(UTC) - timedelta(days=older_than_days)
        
        stmt = delete(RefreshToken).where(
            RefreshToken.revoked_at.isnot(None),
            RefreshToken.revoked_at <= cutoff,
        )
        
        result = await self.session.execute(stmt)
        await self.session.commit()
        
        count = result.rowcount or 0
        
        if count > 0:
            logger.info(
                "Revoked tokens deleted",
                extra={
                    "event": "revoked_tokens_deleted",
                    "count": count,
                    "older_than_days": older_than_days,
                }
            )
        
        return count
    
    async def cleanup_old_tokens(
        self,
        expired_grace_hours: int = 24,
        revoked_grace_days: int = 30,
    ) -> dict[str, int]:
        """
        Comprehensive cleanup of old tokens.
        
        Combines multiple cleanup operations:
        - Expired tokens (after grace period)
        - Revoked tokens (after longer grace period)
        
        Args:
            expired_grace_hours: Grace for expired tokens
            revoked_grace_days: Grace for revoked tokens
            
        Returns:
            Dict with counts per cleanup type
        """
        expired = await self.delete_expired(expired_grace_hours)
        revoked = await self.delete_revoked(revoked_grace_days)
        
        total = expired + revoked
        
        if total > 0:
            logger.info(
                "Token cleanup completed",
                extra={
                    "event": "token_cleanup_completed",
                    "expired_deleted": expired,
                    "revoked_deleted": revoked,
                    "total_deleted": total,
                }
            )
        
        return {
            "expired": expired,
            "revoked": revoked,
            "total": total,
        }
    
    # ============================================================
    # STATISTICS
    # ============================================================
    
    async def get_statistics(self) -> dict[str, int]:
        """
        Get refresh token statistics.
        
        Returns:
            Dict with counts for various token states
        """
        now = datetime.now(UTC)
        
        # Total tokens
        total = await self.count()
        
        # Active tokens
        active_stmt = (
            select(func.count())
            .select_from(RefreshToken)
            .where(
                RefreshToken.revoked_at.is_(None),
                RefreshToken.expires_at > now,
            )
        )
        active = await self.session.scalar(active_stmt) or 0
        
        # Revoked tokens
        revoked_stmt = (
            select(func.count())
            .select_from(RefreshToken)
            .where(RefreshToken.revoked_at.isnot(None))
        )
        revoked = await self.session.scalar(revoked_stmt) or 0
        
        # Expired tokens
        expired_stmt = (
            select(func.count())
            .select_from(RefreshToken)
            .where(RefreshToken.expires_at <= now)
        )
        expired = await self.session.scalar(expired_stmt) or 0
        
        # Unique users with active sessions
        users_stmt = (
            select(func.count(func.distinct(RefreshToken.user_id)))
            .select_from(RefreshToken)
            .where(
                RefreshToken.revoked_at.is_(None),
                RefreshToken.expires_at > now,
            )
        )
        users = await self.session.scalar(users_stmt) or 0
        
        return {
            "total": total,
            "active": active,
            "revoked": revoked,
            "expired": expired,
            "unique_users": users,
        }
    
    async def get_top_users_by_sessions(
        self,
        limit: int = 10,
    ) -> Sequence[tuple[UUID, int]]:
        """
        Get users with most active sessions.
        
        Useful for detecting suspicious patterns (user with 100 devices).
        
        Args:
            limit: Number of top users to return
            
        Returns:
            List of (user_id, session_count) tuples
        """
        now = datetime.now(UTC)
        
        stmt = (
            select(
                RefreshToken.user_id,
                func.count(RefreshToken.id).label("session_count"),
            )
            .where(
                RefreshToken.revoked_at.is_(None),
                RefreshToken.expires_at > now,
            )
            .group_by(RefreshToken.user_id)
            .order_by(func.count(RefreshToken.id).desc())
            .limit(limit)
        )
        
        result = await self.session.execute(stmt)
        return [(row.user_id, row.session_count) for row in result.all()]


# ============================================================
# EXPORTS
# ============================================================

__all__ = ["RefreshTokenRepository"]