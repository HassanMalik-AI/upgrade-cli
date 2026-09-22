"""
Hashed, expiring email verification tokens.

This module defines the EmailVerification model, which manages single-use
tokens for verifying user email addresses. It provides:
- Hashed token storage (SHA-256, never plaintext)
- Expiration enforcement (tokens auto-invalidate)
- Single-use enforcement (used_at marks consumption)
- User association (cascade delete with user)

Security Design:
- Raw tokens are never stored in the database
- Only SHA-256 hashes are persisted
- Tokens expire after a configurable duration
- Each token can only be used once
- Resending creates a new token (old tokens remain invalid)
"""

from datetime import datetime, UTC, timedelta
from typing import TYPE_CHECKING, Optional
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, String, Index, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.domain.base import TimestampedModel

if TYPE_CHECKING:
    from app.models.domain.user import User


class EmailVerification(TimestampedModel):
    """
    Single-use verification token linked to a user.
    
    This model implements the email verification flow:
    1. User registers → token generated → email sent
    2. User clicks link → token validated → email verified
    3. Token marked as used → cannot be reused
    
    Security Features:
        - SHA-256 hash storage (never plaintext)
        - Unique token hash (prevents duplicates)
        - Expiration enforcement (24 hours default)
        - Single-use enforcement (used_at tracking)
        - Cascade delete when user is removed
    
    Attributes:
        user_id: UUID of the user verifying email
        token_hash: SHA-256 hash of the raw verification token
        expires_at: When this token expires (UTC)
        used_at: When this token was used (None if unused)
        email: Email address being verified
        ip_address: IP where verification was requested
        user_agent: Device/browser info
    """

    __tablename__ = "email_verifications"

    # ============================================================
    # CORE FIELDS
    # ============================================================

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="UUID of user verifying email",
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
        doc="Email address being verified (may differ from user.email if changed)",
    )

    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),  # IPv6 max length
        nullable=True,
        doc="IP address where verification was requested",
    )

    user_agent: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
        doc="Device/browser info for audit trail",
    )

    # ============================================================
    # RESEND TRACKING (Professional Addition)
    # ============================================================

    resend_count: Mapped[int] = mapped_column(
        default=0,
        nullable=False,
        doc="Number of times this token was resent",
    )

    last_sent_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="When the verification email was last sent",
    )

    # ============================================================
    # RELATIONSHIPS
    # ============================================================

    user: Mapped["User"] = relationship(
        back_populates="email_verifications",
        lazy="selectin",
        doc="User who owns this verification token",
    )

    # ============================================================
    # TABLE CONSTRAINTS & INDEXES
    # ============================================================

    __table_args__ = (
        # Compound index for finding active tokens by user
        Index("idx_email_verifications_user_active", "user_id", "used_at"),
        # Compound index for cleanup queries
        Index("idx_email_verifications_expires_used", "expires_at", "used_at"),
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
        """Check if token is valid (not expired and not used)."""
        return not self.is_expired and not self.is_used

    @property
    def time_until_expiry(self) -> Optional[float]:
        """Get seconds until token expires (None if already expired)."""
        if self.is_expired:
            return None
        return (self.expires_at - datetime.now(UTC)).total_seconds()

    @property
    def age_seconds(self) -> Optional[float]:
        """Get age of token in seconds."""
        if self.created_at:
            return (datetime.now(UTC) - self.created_at).total_seconds()
        return None

    @property
    def can_resend(self) -> bool:
        """Check if token can be resent (rate limiting)."""
        if self.is_used or self.is_expired:
            return False
        if self.last_sent_at is None:
            return True
        # Minimum 60 seconds between resends
        min_interval = 60
        return (datetime.now(UTC) - self.last_sent_at).total_seconds() >= min_interval

    @property
    def resend_cooldown_seconds(self) -> Optional[float]:
        """Get seconds until token can be resent."""
        if not self.last_sent_at:
            return None
        if self.can_resend:
            return None
        elapsed = (datetime.now(UTC) - self.last_sent_at).total_seconds()
        return max(0, 60 - elapsed)

    # ============================================================
    # UTILITY METHODS
    # ============================================================

    def mark_used(self) -> None:
        """Mark token as used (single-use enforcement)."""
        self.used_at = datetime.now(UTC)

    def extend_expiry(self, hours: int = 24) -> None:
        """
        Extend token expiration.
        
        Args:
            hours: Number of hours to extend (default: 24)
        """
        self.expires_at = datetime.now(UTC) + timedelta(hours=hours)

    def record_send(self, ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> None:
        """
        Record a send/resend of the verification email.
        
        Args:
            ip_address: Optional IP address
            user_agent: Optional user agent
        """
        self.last_sent_at = datetime.now(UTC)
        self.resend_count += 1
        if ip_address:
            self.ip_address = ip_address
        if user_agent:
            self.user_agent = user_agent

    def invalidate(self) -> None:
        """
        Invalidate token by setting expires_at to now.
        
        Use this when a new token is issued to replace an old one.
        """
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
            "resend_count": self.resend_count,
            "last_sent_at": self.last_sent_at.isoformat() if self.last_sent_at else None,
            "ip_address": self.ip_address,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if include_sensitive:
            data["token_hash"] = self.token_hash
        return data

    def __repr__(self) -> str:
        """Debug representation of token."""
        return f"<EmailVerification(id={self.id}, user_id={self.user_id}, valid={self.is_valid})>"

    def __str__(self) -> str:
        """User-friendly string representation."""
        status = "valid" if self.is_valid else ("expired" if self.is_expired else "used")
        return f"EmailVerification(user={self.user_id}, {status})"