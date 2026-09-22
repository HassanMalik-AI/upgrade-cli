"""
Refresh-token allowlist storing only SHA-256 digests.

This module defines the RefreshToken model, which manages user sessions
for JWT authentication. It stores:
- Token hash (SHA-256): Never stores raw tokens
- Expiration: When the token becomes invalid
- Revocation: When the token was manually invalidated
- User relationship: Which user this token belongs to

Security features:
- Raw tokens never stored (only SHA-256 hashes)
- Unique token hash prevents duplicates
- Expiration timestamp enforces token lifetime
- Revocation timestamp enables logout
- Cascade delete when user is deleted
"""

from datetime import datetime, UTC
from typing import TYPE_CHECKING, Optional
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, String, Index, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.domain.base import TimestampedModel

if TYPE_CHECKING:
    from app.models.domain.user import User


class RefreshToken(TimestampedModel):
    """
    Revocable refresh session; raw bearer tokens never enter the database.
    
    This model implements a refresh token allowlist, which provides:
    - Token rotation support (new token issued on refresh)
    - Manual revocation (logout, security breach)
    - Expiration enforcement (automatic cleanup)
    - Session tracking (which devices are logged in)
    
    Security Design:
        - Only SHA-256 hash of token is stored (never plaintext)
        - Unique constraint prevents token reuse
        - Indexed fields for fast validation queries
        - Cascade delete when user is removed
    
    Attributes:
        user_id: UUID of the user who owns this token
        token_hash: SHA-256 hash of the raw refresh token (64 chars)
        expires_at: When this token expires (UTC)
        revoked_at: When this token was revoked (None if active)
        user_agent: Device/browser info for session tracking
        ip_address: IP address where token was issued
        last_used_at: When the token was last used
    """

    __tablename__ = "refresh_tokens"

    # ============================================================
    # CORE FIELDS
    # ============================================================

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="UUID of user who owns this refresh token",
    )

    token_hash: Mapped[str] = mapped_column(
        String(64),  # SHA-256 produces 64 hex characters
        unique=True,
        index=True,
        nullable=False,
        doc="SHA-256 hash of the raw refresh token (never plaintext)",
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        doc="Timestamp when this token expires (UTC)",
    )

    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
        index=True,
        doc="Timestamp when token was revoked (None if active)",
    )

    # ============================================================
    # SESSION TRACKING (Professional Addition)
    # ============================================================

    user_agent: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
        doc="Device/browser info for session tracking",
    )

    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),  # IPv6 max length
        nullable=True,
        doc="IP address where token was issued",
    )

    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="When this token was last used for refresh",
    )

    # ============================================================
    # RELATIONSHIPS
    # ============================================================

    user: Mapped["User"] = relationship(
        back_populates="refresh_tokens",
        lazy="selectin",
        doc="User who owns this refresh token",
    )

    # ============================================================
    # TABLE CONSTRAINTS & INDEXES
    # ============================================================

    __table_args__ = (
        # Compound index for finding active tokens by user
        Index("idx_refresh_tokens_user_active", "user_id", "revoked_at"),
        # Compound index for cleanup queries
        Index("idx_refresh_tokens_expires_revoked", "expires_at", "revoked_at"),
    )

    # ============================================================
    # PROPERTIES
    # ============================================================

    @property
    def is_expired(self) -> bool:
        """Check if token has expired."""
        return datetime.now(UTC) > self.expires_at

    @property
    def is_revoked(self) -> bool:
        """Check if token has been revoked."""
        return self.revoked_at is not None

    @property
    def is_valid(self) -> bool:
        """Check if token is valid (not expired and not revoked)."""
        return not self.is_expired and not self.is_revoked

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

    # ============================================================
    # UTILITY METHODS
    # ============================================================

    def revoke(self) -> None:
        """
        Revoke this refresh token (logout).
        
        Sets revoked_at to current time, making the token invalid
        for future refresh attempts.
        """
        self.revoked_at = datetime.now(UTC)

    def mark_used(self) -> None:
        """
        Mark token as used for session tracking.
        
        Updates last_used_at timestamp for audit purposes.
        """
        self.last_used_at = datetime.now(UTC)

    def extend_expiry(self, days: int = 30) -> None:
        """
        Extend token expiration (sliding session).
        
        Args:
            days: Number of days to extend (default: 30)
        """
        from datetime import timedelta
        self.expires_at = datetime.now(UTC) + timedelta(days=days)

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
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "is_expired": self.is_expired,
            "is_revoked": self.is_revoked,
            "is_valid": self.is_valid,
            "user_agent": self.user_agent,
            "ip_address": self.ip_address,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if include_sensitive:
            data["token_hash"] = self.token_hash
        return data

    def __repr__(self) -> str:
        """Debug representation of token."""
        return f"<RefreshToken(id={self.id}, user_id={self.user_id}, valid={self.is_valid})>"

    def __str__(self) -> str:
        """User-friendly string representation."""
        status = "valid" if self.is_valid else ("expired" if self.is_expired else "revoked")
        return f"RefreshToken(user={self.user_id}, {status})"