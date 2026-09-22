"""
Password reset token persistence boundary.

This module defines the PasswordReset model, which manages single-use
tokens for resetting user passwords. It provides:
- Hashed token storage (SHA-256, never plaintext)
- Expiration enforcement (tokens auto-invalidate)
- Single-use enforcement (used_at marks consumption)
- User association (cascade delete with user)
- Audit trail (IP, user agent, request metadata)

Security Design:
- Raw tokens are never stored in the database
- Only SHA-256 hashes are persisted
- Tokens expire after a configurable duration (15 minutes default)
- Each token can only be used once
- Failed attempts tracked to prevent brute force
- All password reset requests are logged for audit
"""

from datetime import datetime, UTC, timedelta
from typing import TYPE_CHECKING, Optional
from uuid import UUID

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.domain.base import TimestampedModel

if TYPE_CHECKING:
    from app.models.domain.user import User


class PasswordReset(TimestampedModel):
    """
    Document the reset-token contract; use a dedicated table in migrations.
    
    This model implements the password reset flow:
    1. User requests reset → token generated → email sent
    2. User clicks link → token validated → password reset form
    3. User submits new password → token consumed → password updated
    
    Security Features:
        - SHA-256 hash storage (never plaintext)
        - Unique token hash (prevents duplicates)
        - Expiration enforcement (15 minutes default)
        - Single-use enforcement (used_at tracking)
        - Failed attempt tracking (brute force prevention)
        - Cascade delete when user is removed
        - Complete audit trail
    
    Attributes:
        user_id: UUID of the user resetting password
        token_hash: SHA-256 hash of the raw reset token
        expires_at: When this token expires (UTC)
        used_at: When this token was consumed (None if unused)
        ip_address: IP where reset was requested
        user_agent: Device/browser info
        reset_count: Number of resets requested
        failed_attempts: Failed token validation attempts
        locked_until: Temporary lockout after too many failures
    """

    __tablename__ = "password_resets"

    # ============================================================
    # CORE FIELDS
    # ============================================================

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="UUID of user resetting password",
    )

    token_hash: Mapped[str] = mapped_column(
        String(64),  # SHA-256 produces 64 hex characters
        unique=True,
        index=True,
        nullable=False,
        doc="SHA-256 hash of raw token (never plaintext)",
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        doc="Timestamp when this token expires (UTC)",
    )

    used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
        index=True,
        doc="Timestamp when token was consumed (None if unused)",
    )

    # ============================================================
    # CONTEXT FIELDS (Professional Addition)
    # ============================================================

    email: Mapped[str] = mapped_column(
        String(320),
        nullable=False,
        doc="Email address the reset was sent to",
    )

    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),  # IPv6 max length
        nullable=True,
        doc="IP address where reset was requested",
    )

    user_agent: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
        doc="Device/browser info for audit trail",
    )

    # ============================================================
    # SECURITY TRACKING
    # ============================================================

    reset_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        doc="Number of reset requests for this user (rate limiting)",
    )

    failed_attempts: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        doc="Failed token validation attempts",
    )

    locked_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        doc="Temporary lockout until this time",
    )

    # ============================================================
    # PASSWORD CHANGE TRACKING
    # ============================================================

    password_changed: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        doc="Whether password was successfully changed",
    )

    changed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="When password was actually changed",
    )

    # ============================================================
    # RELATIONSHIPS
    # ============================================================

    user: Mapped["User"] = relationship(
        back_populates="password_resets",
        lazy="selectin",
        doc="User who requested the password reset",
    )

    # ============================================================
    # TABLE CONSTRAINTS & INDEXES
    # ============================================================

    __table_args__ = (
        # Compound index for finding active resets by user
        Index("idx_password_resets_user_active", "user_id", "used_at"),
        # Compound index for cleanup queries
        Index("idx_password_resets_expires_used", "expires_at", "used_at"),
        # Index for rate limiting
        Index("idx_password_resets_created", "created_at"),
    )

    # ============================================================
    # PROPERTIES
    # ============================================================

    @property
    def is_expired(self) -> bool:
        """Check if token has expired."""
        return datetime.now(UTC) > self.expires_at

    @property
    def is_used(self) -> bool:
        """Check if token has been used."""
        return self.used_at is not None

    @property
    def is_valid(self) -> bool:
        """Check if token is valid (not expired, not used, not locked)."""
        return (
            not self.is_expired
            and not self.is_used
            and not self.is_locked
        )

    @property
    def is_locked(self) -> bool:
        """Check if reset is temporarily locked."""
        if self.locked_until is None:
            return False
        return datetime.now(UTC) < self.locked_until

    @property
    def time_until_expiry(self) -> Optional[float]:
        """Get seconds until token expires (None if already expired)."""
        if self.is_expired:
            return None
        return (self.expires_at - datetime.now(UTC)).total_seconds()

    @property
    def remaining_lockout_seconds(self) -> Optional[float]:
        """Get remaining lockout time in seconds."""
        if not self.is_locked:
            return None
        return (self.locked_until - datetime.now(UTC)).total_seconds()

    @property
    def age_seconds(self) -> Optional[float]:
        """Get age of token in seconds."""
        if self.created_at:
            return (datetime.now(UTC) - self.created_at).total_seconds()
        return None

    @property
    def was_completed(self) -> bool:
        """Check if password reset was fully completed."""
        return self.password_changed and self.changed_at is not None

    # ============================================================
    # UTILITY METHODS
    # ============================================================

    def mark_used(self) -> None:
        """Mark token as used (single-use enforcement)."""
        self.used_at = datetime.now(UTC)

    def mark_password_changed(self) -> None:
        """Mark password as successfully changed."""
        self.password_changed = True
        self.changed_at = datetime.now(UTC)
        self.mark_used()

    def mark_failed(self, max_attempts: int = 5, lockout_minutes: int = 15) -> None:
        """
        Mark a failed validation attempt.
        
        Args:
            max_attempts: Number of failures before lockout
            lockout_minutes: Duration of lockout
        """
        self.failed_attempts += 1
        if self.failed_attempts >= max_attempts:
            self.locked_until = datetime.now(UTC) + timedelta(minutes=lockout_minutes)

    def unlock(self) -> None:
        """Manually unlock (admin action)."""
        self.failed_attempts = 0
        self.locked_until = None

    def extend_expiry(self, minutes: int = 15) -> None:
        """
        Extend token expiration.
        
        Args:
            minutes: Number of minutes to extend (default: 15)
        """
        self.expires_at = datetime.now(UTC) + timedelta(minutes=minutes)

    def invalidate(self) -> None:
        """Force invalidate token (security response)."""
        self.expires_at = datetime.now(UTC)

    def to_dict(self, include_sensitive: bool = False) -> dict:
        """
        Convert token to dictionary for serialization.
        
        Args:
            include_sensitive: Include token hash (default: False)
            
        Returns:
            Dictionary representation of token
        """
        data = {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "email": self.email,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "used_at": self.used_at.isoformat() if self.used_at else None,
            "is_expired": self.is_expired,
            "is_used": self.is_used,
            "is_valid": self.is_valid,
            "is_locked": self.is_locked,
            "password_changed": self.password_changed,
            "changed_at": self.changed_at.isoformat() if self.changed_at else None,
            "reset_count": self.reset_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if include_sensitive:
            data["token_hash"] = self.token_hash
            data["ip_address"] = self.ip_address
        return data

    def __repr__(self) -> str:
        """Debug representation of token."""
        return f"<PasswordReset(id={self.id}, user_id={self.user_id}, valid={self.is_valid})>"

    def __str__(self) -> str:
        """User-friendly string representation."""
        if self.was_completed:
            status = "completed"
        elif self.is_valid:
            status = "valid"
        elif self.is_locked:
            status = "locked"
        elif self.is_expired:
            status = "expired"
        else:
            status = "used"
        return f"PasswordReset(user={self.user_id}, {status})"