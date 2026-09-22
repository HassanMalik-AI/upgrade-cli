"""
Declarative SQLAlchemy base imported by Alembic and model modules.

This file serves as the foundation for ALL database models in the application.
Every table inherits from this Base class, ensuring:
- Consistent naming conventions
- Automatic table name generation
- Reusable mixins for common functionality
- Type-safe ORM with SQLAlchemy 2.0
- Migration support via Alembic

Design Principles:
- Single source of truth for database metadata
- Mixin composition for reusable functionality
- Explicit imports for Alembic autogenerate
- Type-safe column definitions with Mapped
- Consistent naming conventions across all tables
"""

from datetime import UTC, datetime
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import (
    DateTime,
    MetaData,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.orm import declared_attr


# ============================================================
# STEP 1: NAMING CONVENTION (Critical for Alembic)
# ============================================================

# Consistent naming for constraints and indexes.
# This ensures Alembic can reliably detect and name changes.
# Without this, constraint names can differ across migrations.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",           # Index
    "uq": "uq_%(table_name)s_%(column_0_name)s",  # Unique constraint
    "ck": "ck_%(table_name)s_%(constraint_name)s", # Check constraint
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",  # Foreign key
    "pk": "pk_%(table_name)s",                 # Primary key
}

# Custom metadata with naming convention
# This is inherited by ALL models
metadata = MetaData(naming_convention=NAMING_CONVENTION)


# ============================================================
# STEP 2: BASE CLASS
# ============================================================

class Base(DeclarativeBase):
    """
    Common parent for all database tables.
    
    Provides:
    - Metadata with naming conventions
    - Automatic table name generation (snake_case)
    - Type annotation support
    - Base for all mixins
    
    All models MUST inherit from this class (directly or via mixins).
    
    Example:
        class User(Base, UUIDMixin, TimestampMixin):
            __tablename__ = "users"
            email: Mapped[str] = mapped_column(String(255), unique=True)
    """
    
    # Abstract - no table created for Base itself
    __abstract__ = True
    
    # Metadata with naming conventions
    metadata = metadata
    
    @declared_attr.directive
    def __tablename__(cls) -> str:
        """
        Auto-generate table name from class name.
        
        Converts CamelCase to snake_case and pluralizes.
        
        Examples:
            User → users
            RefreshToken → refresh_tokens
            TOTPSecret → totp_secrets
        """
        # Convert CamelCase to snake_case
        name = cls.__name__
        snake_case = "".join(
            ["_" + c.lower() if c.isupper() else c for c in name]
        ).lstrip("_")
        
        # Pluralize (basic - can be extended)
        if not snake_case.endswith("s"):
            snake_case += "s"
        
        return snake_case


# ============================================================
# STEP 3: MIXINS (Reusable Functionality)
# ============================================================

class UUIDMixin:
    """
    Adds UUID primary key to models.
    
    Why UUID over Integer:
    - Globally unique (no collisions across systems)
    - Non-sequential (better security, no enumeration)
    - Distributed-friendly (client can generate IDs)
    - Merge-friendly (no conflicts when combining data)
    
    Example:
        class User(Base, UUIDMixin):
            __tablename__ = "users"
            # id is inherited automatically
    """
    
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        nullable=False,
        index=True,
        doc="Unique identifier (UUID v4)",
    )


class TimestampMixin:
    """
    Adds created_at and updated_at timestamps to models.
    
    Uses database-side defaults (server_default) for consistency
    across multiple application servers.
    
    Why server_default over Python default:
    - Consistent time across servers
    - Database generates time (single source of truth)
    - No timezone drift between servers
    - Works with database triggers
    
    Example:
        class User(Base, TimestampMixin):
            # created_at, updated_at inherited
    """
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
        doc="Time when record was created (UTC)",
    )
    
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
        index=True,
        doc="Time when record was last updated (UTC)",
    )


class SoftDeleteMixin:
    """
    Adds soft delete capability to models.
    
    Instead of actually deleting records, mark them as deleted.
    Preserves data for audit, recovery, and compliance.
    
    Example:
        class User(Base, SoftDeleteMixin):
            user = await get_user(id)
            user.soft_delete()  # Marks as deleted
            user.restore()      # Undoes soft delete
    """
    
    deleted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
        index=True,
        doc="Time when record was soft-deleted (None = active)",
    )
    
    @property
    def is_active(self) -> bool:
        """Check if record is active (not soft-deleted)."""
        return self.deleted_at is None
    
    @property
    def is_deleted(self) -> bool:
        """Check if record is soft-deleted."""
        return self.deleted_at is not None
    
    def soft_delete(self) -> None:
        """Mark record as deleted."""
        self.deleted_at = datetime.now(UTC)
    
    def restore(self) -> None:
        """Restore soft-deleted record."""
        self.deleted_at = None


class AuditMixin:
    """
    Adds audit trail to models.
    
    Tracks who created and who last updated the record.
    Required for compliance (GDPR, HIPAA, SOC2).
    
    Example:
        class User(Base, AuditMixin):
            user.created_by = admin.id
            user.updated_by = admin.id
    """
    
    created_by: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=True,
        doc="ID of user who created this record",
    )
    
    updated_by: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=True,
        doc="ID of user who last updated this record",
    )


class StatusMixin:
    """
    Adds status tracking to models.
    
    Common statuses: active, inactive, pending, archived, suspended.
    Enables workflow and lifecycle management.
    
    Example:
        class User(Base, StatusMixin):
            user.status = "suspended"
            if user.is_active:
                ...
    """
    
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="active",
        index=True,
        doc="Current status of the record",
    )
    
    @property
    def is_active(self) -> bool:
        """Check if record is in active status."""
        return self.status == "active"
    
    @property
    def is_pending(self) -> bool:
        """Check if record is in pending status."""
        return self.status == "pending"
    
    @property
    def is_archived(self) -> bool:
        """Check if record is archived."""
        return self.status == "archived"


# ============================================================
# STEP 4: COMPOSITE BASE MODELS
# ============================================================

class BaseModel(Base, UUIDMixin, TimestampMixin):
    """
    Complete base model with UUID and timestamps.
    
    Recommended for most application models.
    
    Provides:
    - UUID primary key
    - created_at timestamp
    - updated_at timestamp
    - to_dict() serialization
    - __repr__ debugging
    
    Example:
        class Product(BaseModel):
            __tablename__ = "products"
            name: Mapped[str] = mapped_column(String(200))
    """
    
    __abstract__ = True
    
    def dict(self) -> dict:
        """
        Convert model to dictionary (all fields).
        
        Returns:
            Dictionary of all column names and values
        """
        return {
            column.name: getattr(self, column.name)
            for column in self.__table__.columns
        }
    
    def to_dict(self, exclude: Optional[list] = None) -> dict:
        """
        Convert model to dictionary with exclusions.
        
        Args:
            exclude: List of field names to exclude
            
        Returns:
            Dictionary representation of the model
        """
        exclude = exclude or []
        return {
            column.name: getattr(self, column.name)
            for column in self.__table__.columns
            if column.name not in exclude
        }
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        return f"<{self.__class__.__name__}(id={self.id})>"
    
    def __str__(self) -> str:
        """User-friendly string representation."""
        return f"{self.__class__.__name__}(id={self.id})"


class AuditModel(Base, UUIDMixin, TimestampMixin, AuditMixin):
    """
    Base model with audit trail.
    
    Use for tables that need to track:
    - Who created the record
    - Who last updated the record
    
    Example:
        class Invoice(AuditModel):
            __tablename__ = "invoices"
            # id, created_at, updated_at, created_by, updated_by
    """
    
    __abstract__ = True
    
    def to_dict(self, exclude: Optional[list] = None) -> dict:
        """Convert to dictionary."""
        exclude = exclude or []
        return {
            column.name: getattr(self, column.name)
            for column in self.__table__.columns
            if column.name not in exclude
        }


class SoftDeleteModel(Base, UUIDMixin, TimestampMixin, SoftDeleteMixin):
    """
    Base model with soft delete capability.
    
    Use for tables where data should never be permanently deleted:
    - User accounts
    - Financial records
    - Audit logs
    - Content
    
    Example:
        class User(SoftDeleteModel):
            __tablename__ = "users"
            # Includes deleted_at field
    """
    
    __abstract__ = True
    
    def to_dict(self, exclude: Optional[list] = None) -> dict:
        """Convert to dictionary."""
        exclude = exclude or []
        return {
            column.name: getattr(self, column.name)
            for column in self.__table__.columns
            if column.name not in exclude
        }
    
    def __repr__(self) -> str:
        status = "deleted" if self.is_deleted else "active"
        return f"<{self.__class__.__name__}(id={self.id}, {status})>"


class FullModel(Base, UUIDMixin, TimestampMixin, SoftDeleteMixin, AuditMixin, StatusMixin):
    """
    Complete base model with ALL features.
    
    Use for critical tables that need:
    - UUID primary key
    - Timestamps
    - Soft delete
    - Audit trail
    - Status tracking
    
    Example:
        class User(FullModel):
            __tablename__ = "users"
            # All features included
    """
    
    __abstract__ = True


# ============================================================
# STEP 5: MODEL IMPORTS FOR ALEMBIC
# ============================================================

# IMPORTANT: Import all models here for Alembic autogenerate.
# Alembic uses Base.metadata to detect schema changes.
# Without imports, new tables won't be detected.

# Example:
# from app.models.domain.user import User
# from app.models.domain.product import Product
# from app.models.domain.refresh_token import RefreshToken
# from app.models.domain.totp_secret import TotpSecret
# from app.models.domain.email_verification import EmailVerification
# from app.models.domain.password_reset import PasswordReset

# All imported models are now in Base.metadata


# ============================================================
# STEP 6: UTILITY FUNCTIONS
# ============================================================

def get_all_table_names() -> list[str]:
    """
    Get list of all table names in metadata.
    
    Returns:
        List of table names
    """
    return list(Base.metadata.tables.keys())


def get_table_by_name(name: str):
    """
    Get a table object by name.
    
    Args:
        name: Table name
        
    Returns:
        Table object or None if not found
    """
    return Base.metadata.tables.get(name)


def reset_metadata() -> None:
    """
    Clear all metadata (useful for testing).
    
    WARNING: Only use in tests - clears all table definitions!
    """
    Base.metadata.clear()


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    # Base
    "Base",
    "metadata",
    "NAMING_CONVENTION",
    
    # Mixins
    "UUIDMixin",
    "TimestampMixin",
    "SoftDeleteMixin",
    "AuditMixin",
    "StatusMixin",
    
    # Composite Models
    "BaseModel",
    "AuditModel",
    "SoftDeleteModel",
    "FullModel",
    
    # Utilities
    "get_all_table_names",
    "get_table_by_name",
    "reset_metadata",
]