"""
Encrypted-at-rest TOTP secret ownership boundary.

This module defines the TotpSecret model, which stores TOTP (Time-based
One-Time Password) secrets for two-factor authentication (2FA). It provides:
- Encrypted storage of TOTP secrets (never plaintext in database)
- One-to-one relationship with User (one TOTP secret per user)
- Transparent encryption/decryption via Python properties
- Backup codes for account recovery

Security Design:
- TOTP secrets are encrypted using Fernet (AES-128 in CBC mode)
- Encryption key is derived from JWT secret key via SHA-256
- Raw secrets are only decrypted when needed for verification
- Backup codes are separately hashed for recovery
- Verification status tracks whether 2FA is fully set up
"""

from datetime import datetime, UTC
from typing import TYPE_CHECKING, Optional, List
from uuid import UUID

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.config.settings import get_settings
from app.db.base import Base

if TYPE_CHECKING:
    from app.models.domain.user import User


class TotpSecret(Base):
    """
    One TOTP secret per user; encrypted at rest.
    
    This model stores the TOTP secret used for two-factor authentication.
    The secret is encrypted using Fernet (symmetric encryption) before
    being stored in the database.
    
    Security Features:
        - Encrypted at rest (Fernet/AES-128)
        - Key derived from JWT secret (SHA-256)
        - Transparent encryption via properties
        - Backup codes for recovery
        - Verification tracking
    
    Attributes:
        user_id: UUID primary key (also foreign key to users)
        encrypted_secret: Fernet-encrypted TOTP secret
        is_verified: Whether user has confirmed 2FA setup
        backup_codes_hash: Hashed backup codes for recovery
        last_used_at: When TOTP was last successfully used
        failed_attempts: Count of failed verification attempts
        locked_until: Temporary lockout after too many failures
    """

    __tablename__ = "totp_secrets"

    # ============================================================
    # PRIMARY KEY & FOREIGN KEY
    # ============================================================

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
        doc="User who owns this TOTP secret (one-to-one)",
    )

    # ============================================================
    # ENCRYPTED SECRET
    # ============================================================

    encrypted_secret: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
        doc="Fernet-encrypted TOTP secret (never plaintext)",
    )

    # ============================================================
    # VERIFICATION & STATUS
    # ============================================================

    is_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        doc="Whether user has completed 2FA setup verification",
    )

    # ============================================================
    # BACKUP CODES (Recovery)
    # ============================================================

    backup_codes_hash: Mapped[Optional[str]] = mapped_column(
        String(2048),
        nullable=True,
        doc="JSON array of hashed backup codes for account recovery",
    )

    # ============================================================
    # SECURITY TRACKING
    # ============================================================

    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="When TOTP was last successfully used for authentication",
    )

    failed_attempts: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        doc="Consecutive failed verification attempts",
    )

    locked_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        doc="Temporary lockout until this time (after too many failures)",
    )

    # ============================================================
    # AUDIT TIMESTAMPS
    # ============================================================

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
        doc="When 2FA was first set up",
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
        doc="When 2FA settings were last modified",
    )

    # ============================================================
    # RELATIONSHIPS
    # ============================================================

    user: Mapped["User"] = relationship(
        back_populates="totp_secret",
        lazy="selectin",
        doc="User who owns this TOTP secret",
    )

    # ============================================================
    # TABLE CONSTRAINTS & INDEXES
    # ============================================================

    __table_args__ = (
        Index("idx_totp_locked_until", "locked_until"),
    )

    # ============================================================
    # SECRET PROPERTY (Encryption/Decryption)
    # ============================================================

    @property
    def secret(self) -> str:
        """
        Decrypt the secret only at the point where TOTP verification needs it.
        
        Returns:
            Decrypted TOTP secret (base32 encoded)
            
        Raises:
            ValueError: If decryption fails (corrupted or wrong key)
        """
        try:
            return Fernet(_fernet_key()).decrypt(
                self.encrypted_secret.encode()
            ).decode()
        except InvalidToken as exc:
            raise ValueError("Stored TOTP secret cannot be decrypted") from exc

    @secret.setter
    def secret(self, value: str) -> None:
        """
        Encrypt a plaintext secret before SQLAlchemy persists it.
        
        Args:
            value: Plaintext TOTP secret (base32 encoded)
        """
        self.encrypted_secret = Fernet(_fernet_key()).encrypt(
            value.encode()
        ).decode()

    # ============================================================
    # PROPERTIES
    # ============================================================

    @property
    def is_locked(self) -> bool:
        """Check if TOTP is temporarily locked."""
        if self.locked_until is None:
            return False
        return datetime.now(UTC) < self.locked_until

    @property
    def is_active(self) -> bool:
        """Check if TOTP is fully active (verified and not locked)."""
        return self.is_verified and not self.is_locked

    @property
    def remaining_lockout_seconds(self) -> Optional[float]:
        """Get remaining lockout time in seconds."""
        if not self.is_locked:
            return None
        return (self.locked_until - datetime.now(UTC)).total_seconds()

    @property
    def has_backup_codes(self) -> bool:
        """Check if backup codes are configured."""
        return self.backup_codes_hash is not None and len(self.backup_codes_hash) > 0

    # ============================================================
    # UTILITY METHODS
    # ============================================================

    def mark_used(self) -> None:
        """Mark TOTP as successfully used (reset failures)."""
        self.last_used_at = datetime.now(UTC)
        self.failed_attempts = 0
        self.locked_until = None

    def mark_failed(self, max_attempts: int = 5, lockout_minutes: int = 15) -> None:
        """
        Mark a failed verification attempt.
        
        Args:
            max_attempts: Number of failures before lockout
            lockout_minutes: Duration of lockout
        """
        from datetime import timedelta
        self.failed_attempts += 1
        if self.failed_attempts >= max_attempts:
            self.locked_until = datetime.now(UTC) + timedelta(minutes=lockout_minutes)

    def unlock(self) -> None:
        """Manually unlock TOTP (admin action)."""
        self.failed_attempts = 0
        self.locked_until = None

    def enable(self) -> None:
        """Enable 2FA after successful setup verification."""
        self.is_verified = True
        self.last_used_at = datetime.now(UTC)

    def disable(self) -> None:
        """Disable 2FA (requires password confirmation)."""
        self.is_verified = False

    def to_dict(self, include_sensitive: bool = False) -> dict:
        """Convert TOTP secret to dictionary (never exposes secret)."""
        return {
            "user_id": str(self.user_id),
            "is_verified": self.is_verified,
            "is_active": self.is_active,
            "is_locked": self.is_locked,
            "has_backup_codes": self.has_backup_codes,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        """Debug representation (never shows secret)."""
        return f"<TotpSecret(user_id={self.user_id}, verified={self.is_verified})>"

    def __str__(self) -> str:
        """User-friendly string representation."""
        status = "active" if self.is_active else ("locked" if self.is_locked else "inactive")
        return f"TotpSecret(user={self.user_id}, {status})"


def _fernet_key() -> bytes:
    """
    Return a Fernet key derived from the configured secret key.
    
    Uses SHA-256 to derive a 32-byte key from the JWT secret, then
    base64-url-safe encodes it (Fernet requirement).
    
    Returns:
        32-byte Fernet key suitable for encryption/decryption
    """
    import base64
    import hashlib

    return base64.urlsafe_b64encode(
        hashlib.sha256(
            get_settings().jwt_secret_key.get_secret_value().encode()
        ).digest()
    )