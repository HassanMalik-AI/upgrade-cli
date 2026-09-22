"""
Product table used by the example CRUD surface.

This module defines the Product model, which represents sellable items
in the catalog. It stores:
- Product information: name, description, price
- Categorization: category (indexed for filtering)
- Ownership: owner_id (foreign key to users)

Products support:
- Exact decimal pricing (no floating-point errors)
- Full-text search on name and description
- Category-based filtering
- Owner-based access control
"""

from decimal import Decimal
from typing import TYPE_CHECKING, Optional
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    Numeric,
    String,
    Text,
    Boolean,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.domain.base import TimestampedModel

if TYPE_CHECKING:
    from app.models.domain.user import User


class Product(TimestampedModel):
    """
    Sellable product with indexed name and exact numeric price.
    
    This is the primary entity for the product catalog. It supports:
    - CRUD operations via API
    - Category-based filtering
    - Owner-based access control
    - Full-text search on name and description
    
    Attributes:
        name: Product display name (indexed for search)
        description: Detailed product description
        price: Exact decimal price (12 digits, 2 decimals)
        category: Product category (indexed for filtering)
        owner_id: UUID of user who owns this product
        is_available: Whether product is available for purchase
        stock_quantity: Available stock count
        sku: Unique stock keeping unit
    """

    __tablename__ = "products"

    # ============================================================
    # CORE PRODUCT FIELDS
    # ============================================================

    name: Mapped[str] = mapped_column(
        String(200),
        index=True,
        nullable=False,
        doc="Product display name (indexed for search)",
    )

    description: Mapped[str] = mapped_column(
        Text,
        default="",
        nullable=False,
        doc="Detailed product description",
    )

    price: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        doc="Product price (exact decimal, 12 digits, 2 decimals)",
    )

    category: Mapped[str] = mapped_column(
        String(100),
        default="general",
        nullable=False,
        index=True,
        doc="Product category (indexed for filtering)",
    )

    # ============================================================
    # OWNERSHIP
    # ============================================================

    owner_id: Mapped[Optional[UUID]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        doc="UUID of user who owns this product (NULL if orphaned)",
    )

    # ============================================================
    # INVENTORY FIELDS (Professional Addition)
    # ============================================================

    is_available: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        index=True,
        doc="Whether product is available for purchase",
    )

    stock_quantity: Mapped[int] = mapped_column(
        default=0,
        nullable=False,
        doc="Available stock count",
    )

    sku: Mapped[Optional[str]] = mapped_column(
        String(50),
        unique=True,
        nullable=True,
        index=True,
        doc="Unique stock keeping unit (SKU)",
    )

    # ============================================================
    # RELATIONSHIPS
    # ============================================================

    owner: Mapped[Optional["User"]] = relationship(
        back_populates="products",
        lazy="selectin",
        doc="User who owns this product",
    )

    # ============================================================
    # TABLE CONSTRAINTS & INDEXES
    # ============================================================

    __table_args__ = (
        # Ensure price is always positive
        CheckConstraint("price >= 0", name="ck_products_price_positive"),
        # Ensure stock quantity is non-negative
        CheckConstraint("stock_quantity >= 0", name="ck_products_stock_non_negative"),
        # Compound index for category + availability queries
        Index("idx_products_category_available", "category", "is_available"),
        # Compound index for owner + availability queries
        Index("idx_products_owner_available", "owner_id", "is_available"),
        # Index for price range queries
        Index("idx_products_price", "price"),
    )

    # ============================================================
    # PROPERTIES
    # ============================================================

    @property
    def is_in_stock(self) -> bool:
        """Check if product has available stock."""
        return self.is_available and self.stock_quantity > 0

    @property
    def is_out_of_stock(self) -> bool:
        """Check if product is out of stock."""
        return self.is_available and self.stock_quantity == 0

    @property
    def price_display(self) -> str:
        """Get formatted price for display."""
        return f"${self.price:.2f}"

    @property
    def price_with_tax(self) -> Decimal:
        """Calculate price including 10% tax."""
        return (self.price * Decimal("1.10")).quantize(Decimal("0.01"))

    @property
    def discount_eligible(self) -> bool:
        """Check if product is eligible for discount."""
        return self.price >= Decimal("10.00") and self.is_in_stock

    @property
    def category_display(self) -> str:
        """Get category in title case."""
        return self.category.replace("_", " ").title()

    # ============================================================
    # UTILITY METHODS
    # ============================================================

    def apply_discount(self, percentage: float) -> Decimal:
        """
        Calculate discounted price.
        
        Args:
            percentage: Discount percentage (0-100)
            
        Returns:
            Discounted price as Decimal
            
        Raises:
            ValueError: If percentage is invalid
        """
        if not 0 <= percentage <= 100:
            raise ValueError("Discount percentage must be between 0 and 100")
        discount = self.price * Decimal(str(percentage / 100))
        return (self.price - discount).quantize(Decimal("0.01"))

    def reduce_stock(self, quantity: int) -> None:
        """
        Reduce stock quantity after sale.
        
        Args:
            quantity: Number of items sold
            
        Raises:
            ValueError: If insufficient stock
        """
        if quantity <= 0:
            raise ValueError("Quantity must be positive")
        if quantity > self.stock_quantity:
            raise ValueError(
                f"Insufficient stock: requested {quantity}, available {self.stock_quantity}"
            )
        self.stock_quantity -= quantity

    def add_stock(self, quantity: int) -> None:
        """
        Add stock quantity after restock.
        
        Args:
            quantity: Number of items to add
            
        Raises:
            ValueError: If quantity is not positive
        """
        if quantity <= 0:
            raise ValueError("Quantity must be positive")
        self.stock_quantity += quantity

    def to_dict(self, include_sensitive: bool = False) -> dict:
        """
        Convert product to dictionary for serialization.
        
        Args:
            include_sensitive: Include sensitive fields
            
        Returns:
            Dictionary representation of product
        """
        return {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "price": float(self.price),
            "price_display": self.price_display,
            "category": self.category,
            "category_display": self.category_display,
            "owner_id": str(self.owner_id) if self.owner_id else None,
            "is_available": self.is_available,
            "is_in_stock": self.is_in_stock,
            "stock_quantity": self.stock_quantity,
            "sku": self.sku,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        """Debug representation of product."""
        return f"<Product(id={self.id}, name={self.name}, price={self.price})>"

    def __str__(self) -> str:
        """User-friendly string representation."""
        return f"Product({self.name}, {self.price_display}, stock={self.stock_quantity})"