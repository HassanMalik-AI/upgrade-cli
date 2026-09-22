"""
Authentication orchestration and secure refresh-token rotation.

This module provides the AuthService class, which orchestrates all
authentication-related business logic:
    - User login (password + optional 2FA)
    - Token issuance (access + refresh pair)
    - Token rotation (secure refresh flow)
    - Token revocation (logout)
    - Password reset workflows
    - Session management

Design Pattern: Service Layer + Orchestration
    - Coordinates multiple repositories (User, RefreshToken, TotpSecret)
    - Uses security primitives (JWT, bcrypt, TOTP)
    - Emits domain events (audit, notifications)
    - Enforces business rules (locking, rate limits)

Responsibilities:
    - Authenticate users (email + password)
    - Issue JWT access tokens
    - Issue opaque refresh tokens (SHA-256 hashed at rest)
    - Rotate refresh tokens (revoke old, issue new)
    - Revoke tokens (single or all sessions)
    - Track sessions (device, IP, last used)
    - Enforce 2FA (if enabled)

Design Principles:
    - Single Responsibility: All auth logic here
    - Dependency Injection: Session + repositories
    - Transactional: Atomic operations
    - Secure: Hashing, rotation, revocation
    - Observable: Comprehensive logging

Security Design:
    - Refresh tokens: Random 48-byte tokens, SHA-256 hashed
    - Access tokens: Short-lived JWTs (15 min)
    - Rotation: New refresh issued on every refresh
    - Revocation: Immediate and auditable
    - Reuse detection: Old tokens marked revoked
    - Session tracking: Device, IP, timestamps

Architecture:
    Endpoints → AuthService (this) → Repositories → Models → DB
                     ↓
              Security Primitives
              (jwt, bcrypt, totp)
                     ↓
              Event Bus (audit, notifications)
"""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Optional, Tuple
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config.settings import get_settings
from app.core.security.auth import create_token
from app.core.security.jwt import (
    create_access_token,
    decode_refresh_token,
)
from app.core.security.password import hash_password, verify_password
from app.core.security.tokens import (
    hash_refresh_token,
    generate_raw_refresh_token,
)
from app.core.security.totp import verify_code
from app.models.domain.refresh_token import RefreshToken
from app.models.domain.user import User
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.repositories.user_repository import UserRepository
from app.services.totp_service import TotpService
from app.utils.logger import logger


def issue_tokens(user_id: UUID) -> Tuple[str, str, str, datetime]:
    """
    Issue short-lived access and opaque refresh credentials.
    
    The returned digest is the only refresh value suitable for persistence.
    
    Returns:
        Tuple of (access_token, raw_refresh, refresh_hash, expiry)
        
    Example:
        access, raw_refresh, refresh_hash, expiry = issue_tokens(user.id)
        
        # Return to client:
        # - access (JWT, 15 min)
        # - raw_refresh (opaque, 30 days)
        
        # Store in DB:
        # - refresh_hash (SHA-256)
        # - expiry
        # - user_id
    """
    settings = get_settings()
    
    # Generate raw refresh token (opaque, cryptographically random)
    raw_refresh = generate_raw_refresh_token()
    
    # Calculate expiration
    expiry = datetime.now(UTC) + timedelta(days=settings.refresh_token_days)
    
    # Create access token (JWT, short-lived)
    access = create_token(
        user_id,
        "access",
        timedelta(minutes=settings.access_token_minutes),
    )
    
    # Hash refresh token for storage
    refresh_hash = hash_refresh_token(raw_refresh)
    
    return access, raw_refresh, refresh_hash, expiry


def issue_password_hash(password: str) -> str:
    """
    Hash a password for reset and social-account provisioning workflows.
    
    Args:
        password: Plaintext password
        
    Returns:
        Bcrypt hash
    """
    return hash_password(password)


# ============================================================
# AUTH SERVICE
# ============================================================

class AuthService:
    """
    Service for authentication orchestration.
    
    This service coordinates:
    - UserRepository (user lookup)
    - RefreshTokenRepository (token persistence)
    - TotpSecretRepository (2FA validation)
    - Security primitives (JWT, bcrypt, TOTP)
    
    Example:
        service = AuthService(session)
        
        # Login
        user, tokens = await service.login(email, password)
        
        # Refresh
        new_tokens = await service.refresh(refresh_token)
        
        # Logout
        await service.logout(refresh_token)
    """
    
    def __init__(self, session: AsyncSession):
        """
        Initialize auth service.
        
        Args:
            session: Async database session
        """
        self.session = session
        self.users = UserRepository(session)
        self.tokens = RefreshTokenRepository(session)
        self.totp_service = TotpService(session)
        self.settings = get_settings()
    
    # ============================================================
    # LOGIN
    # ============================================================
    
    async def login(
        self,
        email: str,
        password: str,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        totp_code: Optional[str] = None,
    ) -> Tuple[User, dict[str, Any]]:
        """
        Authenticate a user and issue tokens.
        
        Flow:
        1. Find user by email
        2. Verify password
        3. Check if user is active
        4. Check if 2FA is required
        5. If 2FA: verify TOTP code
        6. Issue access + refresh tokens
        7. Store refresh token hash in DB
        8. Return user + tokens
        
        Args:
            email: User email
            password: User password (plaintext)
            user_agent: Optional device info
            ip_address: Optional IP address
            totp_code: Optional TOTP code (required if 2FA enabled)
            
        Returns:
            Tuple of (User, tokens_dict)
            
        Raises:
            ValueError: If credentials are invalid
            ValueError: If 2FA is required but not provided
            ValueError: If 2FA code is invalid
            
        Example:
            user, tokens = await service.login(
                email="user@example.com",
                password="SecurePass123!",
                user_agent="Mozilla/5.0...",
                ip_address="192.168.1.1",
            )
            # tokens = {
            #     "access_token": "...",
            #     "refresh_token": "...",
            #     "token_type": "bearer",
            #     "expires_in": 900,
            # }
        """
        # Normalize email
        normalized_email = email.lower().strip()
        
        # Find user
        user = await self.users.get_by_email(normalized_email)
        if user is None:
            logger.warning(
                "Login failed: user not found",
                extra={
                    "event": "login_failed",
                    "reason": "user_not_found",
                    "email": normalized_email,
                    "ip_address": ip_address,
                }
            )
            raise ValueError("Invalid credentials")
        
        # Check if user is active
        if not user.is_active:
            logger.warning(
                "Login failed: inactive user",
                extra={
                    "event": "login_failed",
                    "reason": "user_inactive",
                    "user_id": str(user.id),
                }
            )
            raise ValueError("Account is disabled")
        
        # Verify password
        if not verify_password(password, user.password_hash):
            logger.warning(
                "Login failed: invalid password",
                extra={
                    "event": "login_failed",
                    "reason": "invalid_password",
                    "user_id": str(user.id),
                    "ip_address": ip_address,
                }
            )
            raise ValueError("Invalid credentials")
        
        # Check 2FA
        if await self.totp_service.is_enabled(user.id):
            if not totp_code:
                logger.info(
                    "Login requires 2FA",
                    extra={
                        "event": "login_2fa_required",
                        "user_id": str(user.id),
                    }
                )
                raise ValueError("2FA code required")
            
            # verify_login handles checking lockouts and tracking attempts
            is_valid = await self.totp_service.verify_login(user.id, totp_code)
            if not is_valid:
                logger.warning(
                    "Login failed: invalid 2FA code",
                    extra={
                        "event": "login_failed",
                        "reason": "invalid_2fa",
                        "user_id": str(user.id),
                    }
                )
                raise ValueError("Invalid 2FA code")
        
        # Issue tokens
        tokens = await self._issue_and_store_tokens(
            user_id=user.id,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        
        logger.info(
            "Login successful",
            extra={
                "event": "login_success",
                "user_id": str(user.id),
                "ip_address": ip_address,
            }
        )
        
        return user, tokens
    
    # ============================================================
    # TOKEN REFRESH (Rotation)
    # ============================================================
    
    async def refresh(
        self,
        raw_refresh_token: str,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Refresh tokens with rotation.
        
        Flow:
        1. Hash provided raw token
        2. Find active token in DB
        3. If not found: reject (invalid/revoked/expired)
        4. Revoke old token
        5. Issue new access + refresh tokens
        6. Store new refresh hash
        7. Return new tokens
        
        Rotation Security:
        - Old token immediately revoked
        - New token issued
        - If old token is reused later → rejected (detects theft)
        - Attack window limited to one refresh cycle
        
        Args:
            raw_refresh_token: Raw refresh token from client
            user_agent: Optional device info
            ip_address: Optional IP address
            
        Returns:
            New tokens dict
            
        Raises:
            ValueError: If refresh token is invalid/expired/revoked
            
        Example:
            tokens = await service.refresh(
                raw_refresh_token="abc123...",
            )
            # Old token now revoked
            # New tokens returned
        """
        # Hash provided token
        token_hash = hash_refresh_token(raw_refresh_token)
        
        # Find active token
        stored_token = await self.tokens.find_active(token_hash)
        if stored_token is None:
            logger.warning(
                "Refresh failed: token not found or inactive",
                extra={
                    "event": "refresh_failed",
                    "reason": "token_not_active",
                    "ip_address": ip_address,
                }
            )
            raise ValueError("Invalid or expired refresh token")
        
        # Verify user still active
        user = await self.users.get(stored_token.user_id)
        if user is None or not user.is_active:
            logger.warning(
                "Refresh failed: user inactive or deleted",
                extra={
                    "event": "refresh_failed",
                    "reason": "user_inactive",
                    "user_id": str(stored_token.user_id),
                }
            )
            # Revoke token (defensive)
            await self.tokens.revoke(stored_token)
            raise ValueError("Account is disabled")
        
        # Revoke old token (rotation!)
        await self.tokens.revoke(stored_token)
        
        # Issue new tokens
        tokens = await self._issue_and_store_tokens(
            user_id=user.id,
            user_agent=user_agent or stored_token.user_agent,
            ip_address=ip_address or stored_token.ip_address,
        )
        
        logger.info(
            "Token refreshed with rotation",
            extra={
                "event": "token_refreshed",
                "user_id": str(user.id),
                "old_token_id": str(stored_token.id),
            }
        )
        
        return tokens
    
    # ============================================================
    # LOGOUT
    # ============================================================
    
    async def logout(self, raw_refresh_token: str) -> bool:
        """
        Revoke a single refresh token (logout from current device).
        
        Args:
            raw_refresh_token: Raw refresh token from client
            
        Returns:
            True if revoked, False if not found
            
        Example:
            success = await service.logout(raw_refresh_token)
        """
        token_hash = hash_refresh_token(raw_refresh_token)
        
        revoked = await self.tokens.revoke_by_hash(token_hash)
        
        if revoked:
            logger.info(
                "Logout successful",
                extra={
                    "event": "logout",
                }
            )
        
        return revoked
    
    async def revoke_all_sessions(
        self,
        user_id: UUID,
        except_token: Optional[str] = None,
    ) -> int:
        """
        Revoke all refresh tokens for a user.
        
        Args:
            user_id: User whose sessions to revoke
            except_token: Optional raw token to keep active
            
        Returns:
            Number of sessions revoked
            
        Example:
            # Logout from all other devices:
            count = await service.logout_all(user_id, except_token=current)
        """
        except_hash = None
        if except_token:
            except_hash = hash_refresh_token(except_token)
        
        count = await self.tokens.revoke_all_for_user(
            user_id=user_id,
            except_token_hash=except_hash,
        )
        
        logger.warning(
            "All sessions revoked",
            extra={
                "event": "logout_all",
                "user_id": str(user_id),
                "count": count,
            }
        )
        
        return count
    
    # ============================================================
    # SESSION MANAGEMENT
    # ============================================================
    
    async def get_active_sessions(
        self,
        user_id: UUID,
    ) -> list[dict[str, Any]]:
        """
        Get all active sessions for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of session info (safe for API response)
        """
        tokens = await self.tokens.get_active_sessions(user_id)
        
        return [
            {
                "id": str(token.id),
                "user_agent": token.user_agent,
                "ip_address": token.ip_address,
                "created_at": token.created_at.isoformat(),
                "last_used_at": (
                    token.last_used_at.isoformat() 
                    if token.last_used_at else None
                ),
                "expires_at": token.expires_at.isoformat(),
            }
            for token in tokens
        ]
    
    # ============================================================
    # INTERNAL: TOKEN ISSUANCE
    # ============================================================
    
    async def _issue_and_store_tokens(
        self,
        user_id: UUID,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Issue access + refresh tokens and store refresh hash.
        
        Internal method used by login and refresh flows.
        """
        # Issue tokens
        access, raw_refresh, refresh_hash, expiry = issue_tokens(user_id)
        
        # Store refresh hash in DB
        await self.tokens.create_token(
            user_id=user_id,
            token_hash=refresh_hash,
            expires_at=expiry,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        
        # Build response
        return {
            "access_token": access,
            "refresh_token": raw_refresh,
            "token_type": "bearer",
            "expires_in": self.settings.access_token_minutes * 60,
        }


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    # Service
    "AuthService",
    
    # Utilities
    "issue_tokens",
    "issue_password_hash",
]