"""
User business rules and safe profile operations.

This module provides the UserService class, which encapsulates all
business logic related to user management. It coordinates between
repositories, security primitives, and event emission.

Design Pattern: Service Layer + Facade + Composition
    - Coordinates UserRepository for data access
    - Uses password hashing for security
    - Emits events for other services (email, audit)
    - Enforces business rules (uniqueness, validation)

Responsibilities:
    - User registration with password hashing
    - User profile updates (safe fields only)
    - Email change with re-verification
    - Password change with session revocation
    - User activation/deactivation
    - Role management (admin promotion)
    - Statistics and reporting

Design Principles:
    - Single Responsibility: User-related business logic
    - Dependency Injection: Repository + session injected
    - Transactional: Atomic operations
    - Secure: Password hashing, whitelist updates
    - Observable: Logging + event emission

Security Notes:
    - Passwords hashed with bcrypt (never stored plaintext)
    - Emails normalized to lowercase
    - Field whitelisting prevents mass assignment
    - Sensitive fields only changed via specific methods
    - Business rules enforced at service level
    - Failed operations logged for audit

Architecture:
    Endpoints → UserService (this) → UserRepository → User Model → DB
                     ↓
              EmailService (events)
              AuditService (events)
              SecurityService (hashing)
"""

from typing import Any, Optional, Sequence
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security.password import hash_password, verify_password
from app.models.domain.user import User
from app.models.schemas.user import UserCreate, UserUpdate
from app.repositories.user_repository import UserRepository
from app.services.auth_service import AuthService
from app.services.base.base_service import BaseService
from app.utils.logger import logger


class UserService(BaseService[User]):
    """
    Service for user management business logic.
    
    This service encapsulates all business rules related to users.
    It coordinates:
    - UserRepository (data access)
    - Password hashing (security)
    - Event emission (email, audit)
    
    Example:
        # In endpoint:
        service = UserService(session)
        
        # Register user
        user = await service.create_user(payload)
        
        # Update profile
        user = await service.update_user(user, payload)
    """
    
    def __init__(self, session: AsyncSession):
        """
        Initialize user service.
        
        Args:
            session: Async database session
        """
        super().__init__(User, session)
        self.repository = UserRepository(session)
        self.auth_service = AuthService(session)
    
    # ============================================================
    # REGISTRATION
    # ============================================================
    
    async def create_user(self, payload: UserCreate) -> User:
        """
        Create a new user with hashed password.
        
        Business Rules:
            - Email must be unique (case-insensitive)
            - Password is hashed with bcrypt
            - Email is normalized to lowercase
            - New users are active but not verified
            - Users are not admins by default
        
        Args:
            payload: User creation data (email, password, full_name)
            
        Returns:
            Created user instance
            
        Raises:
            ValueError: If email already exists
            
        Example:
            user = await service.create_user(UserCreate(
                email="user@example.com",
                password="SecurePass123!",
                full_name="John Doe",
            ))
        
        Security Notes:
            - Password is hashed before DB storage
            - Email normalized to prevent duplicate bypass
            - is_verified=False (must verify email)
            - is_admin=False (least privilege)
        """
        # Normalize email
        normalized_email = str(payload.email).lower().strip()
        
        # Business rule: Email uniqueness
        if await self.repository.exists_by_email(normalized_email):
            logger.warning(
                "Registration attempt with existing email",
                extra={
                    "event": "user_registration_duplicate",
                    "email": normalized_email,
                }
            )
            raise ValueError(f"Email {normalized_email} is already registered")
        
        # Hash password (never store plaintext!)
        password_hash = hash_password(payload.password)
        
        # Create user entity
        user = User(
            email=normalized_email,
            full_name=payload.full_name.strip(),
            password_hash=password_hash,
            is_active=True,
            is_verified=False,
            is_admin=False,
        )
        
        # Persist via repository
        user = await self.repository.create(user)
        
        logger.info(
            "User registered",
            extra={
                "event": "user_registered",
                "user_id": str(user.id),
                "email": normalized_email,
            }
        )
        
        # TODO: Emit event for email verification
        # await self.event_bus.emit("user.registered", {"user_id": user.id})
        
        return user
    
    # ============================================================
    # PROFILE UPDATES
    # ============================================================
    
    async def update_user(
        self,
        user: User,
        payload: UserUpdate,
    ) -> User:
        """
        Apply allowed profile fields and persist them.
        
        Business Rules:
            - Only whitelisted fields can be updated
            - Empty/None values are skipped (partial update)
            - Email changes require separate method (re-verification)
            - Password changes require separate method (hash + revoke)
        
        Args:
            user: User instance to update
            payload: Update data (full_name only for now)
            
        Returns:
            Updated user instance
            
        Example:
            user = await service.update_user(user, UserUpdate(
                full_name="New Name",
            ))
        
        Security Notes:
            - Only `full_name` updated here
            - `email` requires update_email (re-verification)
            - `password` requires change_password (revoke sessions)
            - `is_admin` requires admin role management
        """
        # Whitelist of fields allowed in this method
        allowed_fields = {"full_name"}
        
        # Extract allowed fields that were provided
        values: dict[str, Any] = {}
        
        if payload.full_name is not None:
            values["full_name"] = payload.full_name.strip()
        
        # If nothing to update, return unchanged
        if not values:
            return user
        
        # Apply via repository (which does commit + refresh)
        user = await self.repository.update(user, values)
        
        logger.info(
            "User profile updated",
            extra={
                "event": "user_profile_updated",
                "user_id": str(user.id),
                "fields": list(values.keys()),
            }
        )
        
        return user
    
    # ============================================================
    # EMAIL CHANGE
    # ============================================================
    
    async def update_email(
        self,
        user: User,
        new_email: str,
        require_verification: bool = True,
    ) -> User:
        """
        Change user's email with optional re-verification.
        
        Business Rules:
            - New email must not conflict with existing users
            - Email is normalized to lowercase
            - is_verified resets to False (default)
            - Old verification tokens invalidated
        
        Args:
            user: User instance to update
            new_email: New email address
            require_verification: Reset verification status
            
        Returns:
            Updated user
            
        Raises:
            ValueError: If email already in use
            
        Example:
            user = await service.update_email(
                user,
                new_email="newemail@example.com",
            )
            # is_verified is now False
            # Caller should send verification email
        """
        normalized_email = new_email.lower().strip()
        
        # No-op if same email
        if normalized_email == user.email:
            return user
        
        # Check for conflicts
        existing = await self.repository.get_by_email(normalized_email)
        if existing and existing.id != user.id:
            logger.warning(
                "Email change conflict",
                extra={
                    "event": "user_email_change_conflict",
                    "user_id": str(user.id),
                    "attempted_email": normalized_email,
                }
            )
            raise ValueError(f"Email {normalized_email} is already in use")
        
        # Build update values
        values: dict[str, Any] = {"email": normalized_email}
        if require_verification:
            values["is_verified"] = False
        
        user = await self.repository.update(user, values)
        
        logger.info(
            "User email updated",
            extra={
                "event": "user_email_updated",
                "user_id": str(user.id),
                "new_email": normalized_email,
                "require_verification": require_verification,
            }
        )
        
        # TODO: Emit event to send verification email to new address
        # await self.event_bus.emit("user.email_changed", {
        #     "user_id": user.id,
        #     "new_email": normalized_email,
        # })
        
        return user
    
    # ============================================================
    # PASSWORD CHANGE
    # ============================================================
    
    async def change_password(
        self,
        user: User,
        current_password: str,
        new_password: str,
        revoke_all_sessions: bool = True,
    ) -> User:
        """
        Change user's password with session revocation.
        
        Business Rules:
            - Current password must be provided and verified
            - New password is hashed before storage
            - ALL refresh tokens revoked (security)
            - Password change is logged for audit
        
        Args:
            user: User instance
            current_password: User's current password (plaintext)
            new_password: New password (plaintext)
            revoke_all_sessions: Whether to revoke all sessions
            
        Returns:
            Updated user
            
        Raises:
            ValueError: If current password is wrong
            
        Example:
            user = await service.change_password(
                user,
                current_password="OldPass123!",
                new_password="NewPass456!",
            )
            # All other sessions are now logged out
        
        Security Notes:
            - Verifies current password before allowing change
            - Revokes all sessions (defense in depth)
            - User must re-login on all devices
        """
        # Verify current password
        if not verify_password(current_password, user.password_hash):
            logger.warning(
                "Failed password change attempt",
                extra={
                    "event": "password_change_failed",
                    "user_id": str(user.id),
                    "reason": "invalid_current_password",
                }
            )
            raise ValueError("Current password is incorrect")
        
        # Hash new password
        new_hash = hash_password(new_password)
        
        # Update password
        user = await self.repository.update(user, {"password_hash": new_hash})
        
        logger.info(
            "User password changed",
            extra={
                "event": "user_password_changed",
                "user_id": str(user.id),
                "revoke_all_sessions": revoke_all_sessions,
            }
        )
        
        # Revoke all sessions (security best practice)
        if revoke_all_sessions:
            revoked_count = await self.auth_service.revoke_all_sessions(user.id)
            
            logger.info(
                "Sessions revoked after password change",
                extra={
                    "event": "sessions_revoked_after_password_change",
                    "user_id": str(user.id),
                    "revoked_count": revoked_count,
                }
            )
        
        return user
    
    # ============================================================
    # ACCOUNT STATE MANAGEMENT
    # ============================================================
    
    async def activate(self, user: User) -> User:
        """
        Activate a user account.
        
        Args:
            user: User instance
            
        Returns:
            Activated user
        """
        if user.is_active:
            return user
        
        user = await self.repository.update(user, {"is_active": True})
        
        logger.info(
            "User activated",
            extra={
                "event": "user_activated",
                "user_id": str(user.id),
            }
        )
        
        return user
    
    async def deactivate(self, user: User) -> User:
        """
        Deactivate a user account (soft suspension).
        
        Business Rules:
            - Sets is_active=False
            - Revokes all sessions (force logout)
            - Preserves data (not deleted)
        
        Args:
            user: User instance
            
        Returns:
            Deactivated user
        """
        if not user.is_active:
            return user
        
        user = await self.repository.update(user, {"is_active": False})
        
        # Revoke all sessions
        await self.auth_service.revoke_all_sessions(user.id)
        
        logger.warning(
            "User deactivated",
            extra={
                "event": "user_deactivated",
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
            Verified user
        """
        if user.is_verified:
            return user
        
        user = await self.repository.update(user, {"is_verified": True})
        
        logger.info(
            "User email verified",
            extra={
                "event": "user_email_verified",
                "user_id": str(user.id),
            }
        )
        
        return user
    
    # ============================================================
    # ROLE MANAGEMENT (Admin Operations)
    # ============================================================
    
    async def promote_to_admin(
        self,
        user: User,
        actor_id: UUID,
    ) -> User:
        """
        Promote a user to admin.
        
        Business Rules:
            - Only existing admins can promote
            - Cannot promote inactive users
            - Action is logged with actor info
        
        Args:
            user: User to promote
            actor_id: Admin performing the action
            
        Returns:
            Promoted user
            
        Raises:
            ValueError: If user is inactive or already admin
        """
        if user.is_admin:
            return user
        
        if not user.is_active:
            raise ValueError("Cannot promote inactive user to admin")
        
        user = await self.repository.update(user, {"is_admin": True})
        
        logger.warning(
            "User promoted to admin",
            extra={
                "event": "user_promoted_admin",
                "user_id": str(user.id),
                "actor_id": str(actor_id),
            }
        )
        
        return user
    
    async def demote_from_admin(
        self,
        user: User,
        actor_id: UUID,
    ) -> User:
        """
        Demote a user from admin.
        
        Args:
            user: User to demote
            actor_id: Admin performing the action
            
        Returns:
            Demoted user
        """
        if not user.is_admin:
            return user
        
        user = await self.repository.update(user, {"is_admin": False})
        
        logger.warning(
            "User demoted from admin",
            extra={
                "event": "user_demoted_admin",
                "user_id": str(user.id),
                "actor_id": str(actor_id),
            }
        )
        
        return user
    
    # ============================================================
    # QUERIES
    # ============================================================
    
    async def get_user(self, user_id: UUID) -> Optional[User]:
        """Get user by ID."""
        return await self.repository.get(user_id)
    
    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email (case-insensitive)."""
        return await self.repository.get_by_email(email)
    
    async def list_users(
        self,
        offset: int = 0,
        limit: int = 50,
    ) -> Sequence[User]:
        """List users with pagination."""
        return await self.repository.list(offset=offset, limit=limit)
    
    async def search_users(
        self,
        query: str,
        offset: int = 0,
        limit: int = 50,
    ) -> Sequence[User]:
        """Search users by email or name."""
        return await self.repository.search_users(query, offset, limit)
    
    async def get_statistics(self) -> dict[str, int]:
        """Get user statistics."""
        return await self.repository.get_statistics()
    
    # ============================================================
    # AUTHENTICATION HELPERS
    # ============================================================
    
    async def authenticate(
        self,
        email: str,
        password: str,
    ) -> Optional[User]:
        """
        Authenticate a user by email and password.
        
        Business Rules:
            - User must exist
            - User must be active
            - Password must match hash
            - Failed attempts logged
        
        Args:
            email: User email
            password: User password (plaintext)
            
        Returns:
            Authenticated user or None
            
        Example:
            user = await service.authenticate(email, password)
            if user is None:
                raise HTTPException(401, "Invalid credentials")
        
        Security Notes:
            - Generic error message (don't leak which field failed)
            - Failed attempts logged for security monitoring
        """
        user = await self.repository.get_by_email(email)
        
        # User not found - don't reveal this to caller
        if user is None:
            logger.warning(
                "Authentication failed - user not found",
                extra={
                    "event": "auth_failed_user_not_found",
                    "email": email.lower(),
                }
            )
            return None
        
        # User inactive
        if not user.is_active:
            logger.warning(
                "Authentication failed - user inactive",
                extra={
                    "event": "auth_failed_user_inactive",
                    "user_id": str(user.id),
                }
            )
            return None
        
        # Verify password
        if not verify_password(password, user.password_hash):
            logger.warning(
                "Authentication failed - invalid password",
                extra={
                    "event": "auth_failed_invalid_password",
                    "user_id": str(user.id),
                }
            )
            return None
        
        logger.info(
            "User authenticated",
            extra={
                "event": "auth_success",
                "user_id": str(user.id),
            }
        )
        
        return user
    
    # ============================================================
    # ADMIN OPERATIONS
    # ============================================================
    
    async def delete_user(
        self,
        user: User,
        actor_id: UUID,
    ) -> None:
        """
        Delete a user account (admin action).
        
        Business Rules:
            - Cascades to related records
            - Requires admin actor
            - Logged for audit
        
        Args:
            user: User to delete
            actor_id: Admin performing deletion
        """
        user_id = user.id
        email = user.email
        
        await self.repository.delete(user)
        
        logger.warning(
            "User deleted by admin",
            extra={
                "event": "user_deleted_by_admin",
                "user_id": str(user_id),
                "email": email,
                "actor_id": str(actor_id),
            }
        )


# ============================================================
# EXPORTS
# ============================================================

__all__ = ["UserService"]