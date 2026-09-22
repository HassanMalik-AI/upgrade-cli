"""
User-specific query repository.

This module provides the UserRepository class, which handles all
database operations for the User model. It extends BaseRepository
with user-specific queries and inherits generic CRUD operations.

Design Pattern: Repository Pattern + Inheritance
    - BaseRepository provides generic CRUD
    - UserRepository adds user-specific methods
    - Services depend on UserRepository, not SQLAlchemy directly

Responsibilities:
    - User lookup (by ID, email)
    - User creation with validation
    - User updates (whitelist enforced)
    - User deletion (cascades to related records)
    - Admin operations (list all users, search)
    - Authentication helpers (find by email, check existence)

Design Decisions:
    - Class-based (extends BaseRepository)
    - Async methods (all DB operations)
    - Type-safe returns (User | None, list[User])
    - Bounded queries (prevent OOM)
    - Normalized emails (lowercase for consistency)
    - Whitelist updates (prevent mass assignment)
    - Logging for security events (failed logins, admin ops)
"""

from typing import Any, Optional, Sequence
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.domain.user import User
from app.repositories.base.base_repository import BaseRepository
from app.utils.logger import logger


class UserRepository(BaseRepository[User]):
    """
    Repository for User model with specialized queries.
    
    Extends BaseRepository[User] to inherit:
    - get(id), get_by_id(id)
    - list(offset, limit)
    - create(instance)
    - update(instance, values)
    - delete(instance)
    
    Adds user-specific methods:
    - get_by_email(email)
    - get_by_emails(emails)
    - get_active_users()
    - get_admin_users()
    - search_users(query)
    - exists_by_email(email)
    - get_by_verification_status()
    
    Example:
        # In service:
        repo = UserRepository(session)
        
        # Generic methods (from BaseRepository)
        user = await repo.get(user_id)
        users = await repo.list(offset=0, limit=20)
        
        # User-specific methods
        user = await repo.get_by_email("user@example.com")
        admins = await repo.get_admin_users()
    """
    
    def __init__(self, session: AsyncSession):
        """
        Initialize user repository.
        
        Args:
            session: Async database session
        """
        super().__init__(session, User)
    
    # ============================================================
    # LOOKUP METHODS
    # ============================================================
    
    async def get_by_email(self, email: str) -> Optional[User]:
        """
        Find a user by normalized email.
        
        Email normalization: lowercases the input to match the
        database constraint (email = LOWER(email)).
        
        Args:
            email: User email address
            
        Returns:
            User instance if found, None otherwise
            
        Example:
            user = await repo.get_by_email("User@Example.com")
            # Matches "user@example.com" in DB
        """
        if not email:
            return None
        
        normalized_email = email.lower().strip()
        stmt = select(User).where(User.email == normalized_email)
        return await self.session.scalar(stmt)
    
    async def get_by_emails(self, emails: Sequence[str]) -> Sequence[User]:
        """
        Find multiple users by email addresses.
        
        Args:
            emails: List of email addresses
            
        Returns:
            List of found users
            
        Example:
            users = await repo.get_by_emails([
                "alice@example.com",
                "bob@example.com"
            ])
        """
        if not emails:
            return []
        
        normalized = [e.lower().strip() for e in emails if e]
        stmt = select(User).where(User.email.in_(normalized))
        result = await self.session.scalars(stmt)
        return result.all()
    
    async def exists_by_email(self, email: str) -> bool:
        """
        Check if a user with the given email exists.
        
        More efficient than get_by_email() when you only need
        to know existence (e.g., during registration validation).
        
        Args:
            email: Email to check
            
        Returns:
            True if user exists
            
        Example:
            if await repo.exists_by_email(email):
                raise HTTPException(400, "Email already registered")
        """
        if not email:
            return False
        
        normalized_email = email.lower().strip()
        stmt = select(func.count()).select_from(User).where(
            User.email == normalized_email
        )
        count = await self.session.scalar(stmt)
        return count > 0
    
    # ============================================================
    # FILTERED QUERIES
    # ============================================================
    
    async def get_active_users(
        self,
        offset: int = 0,
        limit: int = 50,
    ) -> Sequence[User]:
        """
        Get active users (is_active=True).
        
        Args:
            offset: Pagination offset
            limit: Page size (capped at 100)
            
        Returns:
            List of active users
        """
        stmt = (
            select(User)
            .where(User.is_active == True)  # noqa: E712
            .offset(offset)
            .limit(min(limit, 100))
        )
        result = await self.session.scalars(stmt)
        return result.all()
    
    async def get_verified_users(
        self,
        offset: int = 0,
        limit: int = 50,
    ) -> Sequence[User]:
        """Get users with verified email."""
        stmt = (
            select(User)
            .where(User.is_verified == True)  # noqa: E712
            .offset(offset)
            .limit(min(limit, 100))
        )
        result = await self.session.scalars(stmt)
        return result.all()
    
    async def get_unverified_users(
        self,
        offset: int = 0,
        limit: int = 50,
    ) -> Sequence[User]:
        """
        Get users with unverified email.
        
        Useful for:
        - Sending verification reminders
        - Cleanup of stale accounts
        """
        stmt = (
            select(User)
            .where(User.is_verified == False)  # noqa: E712
            .where(User.is_active == True)  # noqa: E712
            .offset(offset)
            .limit(min(limit, 100))
        )
        result = await self.session.scalars(stmt)
        return result.all()
    
    async def get_admin_users(self) -> Sequence[User]:
        """
        Get all admin users.
        
        Returns:
            List of admin users
            
        Security: Logs admin retrieval for audit purposes.
        """
        stmt = select(User).where(User.is_admin == True)  # noqa: E712
        result = await self.session.scalars(stmt)
        admins = result.all()
        
        logger.info(
            f"Admin users retrieved",
            extra={
                "event": "admin_users_retrieved",
                "count": len(admins),
            }
        )
        
        return admins
    
    # ============================================================
    # SEARCH
    # ============================================================
    
    async def search_users(
        self,
        query: str,
        offset: int = 0,
        limit: int = 50,
    ) -> Sequence[User]:
        """
        Search users by email or full name.
        
        Case-insensitive search using ILIKE.
        
        Args:
            query: Search term
            offset: Pagination offset
            limit: Page size (capped at 100)
            
        Returns:
            Matching users
            
        Example:
            users = await repo.search_users("john")
            # Matches emails/names containing "john"
        """
        if not query or not query.strip():
            return []
        
        search_term = f"%{query.strip()}%"
        
        stmt = (
            select(User)
            .where(
                or_(
                    User.email.ilike(search_term),
                    User.full_name.ilike(search_term),
                )
            )
            .offset(offset)
            .limit(min(limit, 100))
        )
        
        result = await self.session.scalars(stmt)
        return result.all()
    
    # ============================================================
    # CREATE WITH VALIDATION
    # ============================================================
    
    async def create_user(
        self,
        email: str,
        password_hash: str,
        full_name: str,
        is_verified: bool = False,
        is_admin: bool = False,
    ) -> User:
        """
        Create a new user with validated fields.
        
        Args:
            email: User email (will be lowercased)
            password_hash: Hashed password (never plaintext!)
            full_name: User's display name
            is_verified: Whether email is verified
            is_admin: Whether user is admin
            
        Returns:
            Created user instance
            
        Raises:
            ValueError: If email already exists
            
        Example:
            user = await repo.create_user(
                email="user@example.com",
                password_hash=hash_password("secret"),
                full_name="John Doe",
            )
        """
        # Normalize email
        normalized_email = email.lower().strip()
        
        # Check for existing user
        if await self.exists_by_email(normalized_email):
            raise ValueError(f"User with email {normalized_email} already exists")
        
        # Create user instance
        user = User(
            email=normalized_email,
            password_hash=password_hash,
            full_name=full_name,
            is_active=True,
            is_verified=is_verified,
            is_admin=is_admin,
        )
        
        # Persist using base method
        user = await self.create(user)
        
        logger.info(
            f"User created",
            extra={
                "event": "user_created",
                "user_id": str(user.id),
                "is_admin": is_admin,
            }
        )
        
        return user
    
    # ============================================================
    # UPDATE WITH WHITELIST
    # ============================================================
    
    async def update_profile(
        self,
        user: User,
        full_name: Optional[str] = None,
    ) -> User:
        """
        Update user profile (safe fields only).
        
        This method ONLY updates profile fields. Sensitive fields
        like password_hash, is_admin must be updated via specific
        methods with proper authorization.
        
        Args:
            user: User instance to update
            full_name: New full name (optional)
            
        Returns:
            Updated user
            
        Example:
            user = await repo.update_profile(user, full_name="New Name")
        """
        values: dict[str, Any] = {}
        if full_name is not None:
            values["full_name"] = full_name
        
        if not values:
            return user
        
        return await self.update(user, values)
    
    async def update_email(
        self,
        user: User,
        new_email: str,
        require_verification: bool = True,
    ) -> User:
        """
        Update user email (requires re-verification).
        
        Args:
            user: User instance
            new_email: New email address
            require_verification: Reset is_verified flag
            
        Returns:
            Updated user
            
        Raises:
            ValueError: If new email already exists
        """
        normalized_email = new_email.lower().strip()
        
        # Check for conflicts
        existing = await self.get_by_email(normalized_email)
        if existing and existing.id != user.id:
            raise ValueError(f"Email {normalized_email} already in use")
        
        values: dict[str, Any] = {"email": normalized_email}
        if require_verification:
            values["is_verified"] = False
        
        user = await self.update(user, values)
        
        logger.info(
            f"User email updated",
            extra={
                "event": "user_email_updated",
                "user_id": str(user.id),
                "require_verification": require_verification,
            }
        )
        
        return user
    
    async def update_password(
        self,
        user: User,
        new_password_hash: str,
    ) -> User:
        """
        Update user password hash.
        
        Args:
            user: User instance
            new_password_hash: New hashed password
            
        Returns:
            Updated user
            
        Note: Caller must also invalidate all refresh tokens!
        """
        user = await self.update(user, {"password_hash": new_password_hash})
        
        logger.info(
            f"User password updated",
            extra={
                "event": "user_password_updated",
                "user_id": str(user.id),
            }
        )
        
        return user
    
    async def verify_email(self, user: User) -> User:
        """
        Mark user's email as verified.
        
        Args:
            user: User instance
            
        Returns:
            Updated user
        """
        user = await self.update(user, {"is_verified": True})
        
        logger.info(
            f"User email verified",
            extra={
                "event": "user_email_verified",
                "user_id": str(user.id),
            }
        )
        
        return user
    
    async def activate(self, user: User) -> User:
        """Activate user account."""
        return await self.update(user, {"is_active": True})
    
    async def deactivate(self, user: User) -> User:
        """Deactivate user account (soft suspension)."""
        user = await self.update(user, {"is_active": False})
        
        logger.warning(
            f"User deactivated",
            extra={
                "event": "user_deactivated",
                "user_id": str(user.id),
            }
        )
        
        return user
    
    async def promote_to_admin(self, user: User) -> User:
        """
        Promote user to admin.
        
        SECURITY: Should only be called by existing admin or system.
        """
        user = await self.update(user, {"is_admin": True})
        
        logger.warning(
            f"User promoted to admin",
            extra={
                "event": "user_promoted_admin",
                "user_id": str(user.id),
            }
        )
        
        return user
    
    async def demote_from_admin(self, user: User) -> User:
        """
        Demote user from admin.
        
        SECURITY: Should only be called by super admin.
        """
        user = await self.update(user, {"is_admin": False})
        
        logger.warning(
            f"User demoted from admin",
            extra={
                "event": "user_demoted_admin",
                "user_id": str(user.id),
            }
        )
        
        return user
    
    # ============================================================
    # DELETE (With Cleanup)
    # ============================================================
    
    async def delete_user(self, user: User) -> None:
        """
        Delete user and all related records.
        
        Cascade delete will automatically remove:
        - Refresh tokens
        - Email verifications
        - Password resets
        - TOTP secret
        
        Args:
            user: User instance to delete
        """
        user_id = user.id
        email = user.email
        
        await self.delete(user)
        
        logger.warning(
            f"User deleted",
            extra={
                "event": "user_deleted",
                "user_id": str(user_id),
                "email": email,
            }
        )
    
    # ============================================================
    # STATISTICS
    # ============================================================
    
    async def get_statistics(self) -> dict[str, int]:
        """
        Get user statistics.
        
        Returns:
            Dict with counts for various user states
            
        Example:
            stats = await repo.get_statistics()
            # {
            #     "total": 1000,
            #     "active": 950,
            #     "verified": 800,
            #     "admins": 5,
            # }
        """
        total = await self.count()
        
        # Count active
        active_stmt = select(func.count()).select_from(User).where(User.is_active == True)  # noqa: E712
        active = await self.session.scalar(active_stmt) or 0
        
        # Count verified
        verified_stmt = select(func.count()).select_from(User).where(User.is_verified == True)  # noqa: E712
        verified = await self.session.scalar(verified_stmt) or 0
        
        # Count admins
        admin_stmt = select(func.count()).select_from(User).where(User.is_admin == True)  # noqa: E712
        admins = await self.session.scalar(admin_stmt) or 0
        
        return {
            "total": total,
            "active": active,
            "verified": verified,
            "admins": admins,
        }


# ============================================================
# EXPORTS
# ============================================================

__all__ = ["UserRepository"]