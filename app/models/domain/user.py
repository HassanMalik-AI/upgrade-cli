"""
User table storing identity, authorization, and password state.

This module defines the User model, which is the central entity for
authentication and authorization. It stores:
- Identity: email, full_name
- Security: password_hash (never exposed)
- Authorization: is_admin, is_active, is_verified
- Relationships: refresh_tokens, email_verifications, password_resets, totp_secret

The email field is unique and indexed for fast lookups during login.
Passwords are never stored in plaintext; only bcrypt hashes are persisted.
"""

from datetime import datetime, UTC
from typing import TYPE_CHECKING, Optional
from uuid import UUID

from sqlalchemy import Boolean, String, Index, CheckConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.domain.base import TimestampedModel

if TYPE_CHECKING:
    from app.models.domain.email_verification import EmailVerification
    from app.models.domain.password_reset import PasswordReset
    from app.models.domain.refresh_token import RefreshToken
    from app.models.domain.totp_secret import TotpSecret


class User(TimestampedModel):
    """
    Application user; email is unique and password hashes are never exposed.
    
    This is the central entity for authentication and authorization.
    It stores identity, security state, and relationships to
    authentication-related tables.
    
    Attributes:
        email: Unique email address (used for login)
        full_name: User's display name
        password_hash: Bcrypt hash of password (never plaintext)
        is_active: Whether the account is enabled
        is_admin: Whether the user has admin privileges
        is_verified: Whether email has been verified
        refresh_tokens: List of refresh tokens for this user
        email_verifications: List of email verification records
        password_resets: List of password reset records
        totp_secret: Optional TOTP secret for 2FA
    """

    __tablename__ = "users"

    # ============================================================
    # IDENTITY FIELDS
    # ============================================================

    email: Mapped[str] = mapped_column(
        String(320),  # RFC 5321 max email length
        unique=True,
        index=True,
        nullable=False,
        doc="Unique email address for login and communication",
    )

    full_name: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
        doc="User's full display name",
    )

    # ============================================================
    # SECURITY FIELDS
    # ============================================================

    password_hash: Mapped[str] = mapped_column(
        String(255),  # Bcrypt hash is always 60 chars
        nullable=False,
        doc="Bcrypt hash of user's password (never plaintext)",
    )

    # ============================================================
    # AUTHORIZATION FIELDS
    # ============================================================

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        index=True,
        doc="Whether the account is enabled (False = suspended)",
    )

    is_admin: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
        doc="Whether user has admin privileges",
    )

    is_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
        doc="Whether email has been verified",
    )

    # ============================================================
    # RELATIONSHIPS
    # ============================================================

    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin",  # Eager load for performance
        doc="Refresh tokens for this user (auto-deleted with user)",
    )

    email_verifications: Mapped[list["EmailVerification"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin",
        doc="Email verification records for this user",
    )

    password_resets: Mapped[list["PasswordReset"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin",
        doc="Password reset records for this user",
    )

    totp_secret: Mapped[Optional["TotpSecret"]] = relationship(
        back_populates="user",
        uselist=False,  # One-to-one relationship
        cascade="all, delete-orphan",
        lazy="selectin",
        doc="TOTP secret for 2FA (one per user)",
    )

    # ============================================================
    # TABLE CONSTRAINTS & INDEXES
    # ============================================================

    __table_args__ = (
        # Ensure email is lowercase
        CheckConstraint("email = LOWER(email)", name="ck_users_email_lowercase"),
        # Compound index for common queries
        Index("idx_users_active_verified", "is_active", "is_verified"),
        # Index for admin queries
        Index("idx_users_admin", "is_admin", "is_active"),
    )

    # ============================================================
    # PROPERTIES
    # ============================================================

    @property
    def display_name(self) -> str:
        """Get display name (full name or email prefix)."""
        return self.full_name or self.email.split("@")[0]

    @property
    def has_2fa_enabled(self) -> bool:
        """Check if user has 2FA enabled."""
        return self.totp_secret is not None and self.totp_secret.is_verified

    @property
    def is_fully_authenticated(self) -> bool:
        """Check if user has completed all authentication steps."""
        return self.is_active and self.is_verified

    @property
    def account_age_days(self) -> int:
        """Get account age in days."""
        if self.created_at:
            return (datetime.now(UTC) - self.created_at).days
        return 0

    # ============================================================
    # UTILITY METHODS
    # ============================================================

    def to_dict(self, include_sensitive: bool = False) -> dict:
        """
        Convert user to dictionary (safe for API responses).
        
        Args:
            include_sensitive: Include sensitive fields (default: False)
            
        Returns:
            Dictionary representation of user
        """
        data = {
            "id": str(self.id),
            "email": self.email,
            "full_name": self.full_name,
            "is_active": self.is_active,
            "is_admin": self.is_admin,
            "is_verified": self.is_verified,
            "has_2fa": self.has_2fa_enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_sensitive:
            data["password_hash"] = self.password_hash
        return data

    def __repr__(self) -> str:
        """Debug representation of user."""
        return f"<User(id={self.id}, email={self.email})>"

    def __str__(self) -> str:
        """User-friendly string representation."""
        return f"User({self.email}, admin={self.is_admin}, active={self.is_active})"