"""
Product creation and query rules.

This module provides the ProductService class, which encapsulates all
business logic related to product management. It coordinates between
repositories, enforces business rules, and manages inventory operations.

Design Pattern: Service Layer + Rich Domain Operations
    - Coordinates ProductRepository for data access
    - Enforces business rules (pricing, stock, ownership)
    - Manages inventory state transitions
    - Emits events (audit, notifications, alerts)

Responsibilities:
    - Product creation with validation
    - Product updates (whitelist + business rules)
    - Inventory management (stock adjustments)
    - Pricing operations (updates, discounts)
    - Search and filtering with pagination
    - Ownership transfer (admin operation)
    - Statistics and reporting
    - Low stock alerts

Design Principles:
    - Single Responsibility: Product-related business logic
    - Dependency Injection: Session + repository
    - Transactional: Atomic operations
    - Validation: Business rules at service level
    - Observable: Comprehensive logging
    - Idempotent where possible

Security Notes:
    - Ownership verification (prevent unauthorized edits)
    - Whitelist updates (prevent mass assignment)
    - Price validation (no negative values)
    - Stock validation (no negative stock)
    - SQL injection prevention (via repository)

Architecture:
    Endpoints → ProductService (this) → ProductRepository → Product Model → DB
                     ↓
              UserService (owner validation)
              Event Bus (alerts, audit)
              Settings (business rules)
"""

from decimal import Decimal
from typing import Any, Optional, Sequence
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config.settings import get_settings
from app.models.domain.product import Product
from app.models.schemas.product import ProductCreate, ProductUpdate
from app.repositories.product_repository import ProductRepository
from app.repositories.user_repository import UserRepository
from app.services.base.base_service import BaseService
from app.utils.logger import logger


# ============================================================
# BUSINESS RULES CONSTANTS
# ============================================================

# Pricing rules
MIN_PRODUCT_PRICE = Decimal("0.01")     # Minimum $0.01
MAX_PRODUCT_PRICE = Decimal("999999.99")  # Maximum $999,999.99

# Stock rules
MAX_STOCK_QUANTITY = 100000             # Maximum stock per product
LOW_STOCK_THRESHOLD = 5                 # Alert threshold

# Product name/description rules
MIN_NAME_LENGTH = 1
MAX_NAME_LENGTH = 200
MAX_DESCRIPTION_LENGTH = 10000

# Categories
DEFAULT_CATEGORY = "general"


# ============================================================
# PRODUCT SERVICE
# ============================================================

class ProductService(BaseService[Product]):
    """
    Service for product business logic.
    
    This service encapsulates all business rules related to products.
    It coordinates repositories and enforces domain constraints.
    
    Example:
        service = ProductService(session)
        
        # Create product
        product = await service.create_product(payload, owner_id=user.id)
        
        # Update stock
        product = await service.adjust_stock(product, delta=-5)
        
        # Search
        products = await service.search("laptop", category="electronics")
    """
    
    def __init__(self, session: AsyncSession):
        """
        Initialize product service.
        
        Args:
            session: Async database session
        """
        super().__init__(Product, session)
        self.session = session
        self.products = ProductRepository(session)
        self.users = UserRepository(session)
        self.settings = get_settings()
    
    # ============================================================
    # PRODUCT CREATION
    # ============================================================
    
    async def create_product(
        self,
        payload: ProductCreate,
        owner_id: Optional[UUID] = None,
    ) -> Product:
        """
        Create a new product with validated fields.
        
        Business Rules:
            - Name: 1-200 chars, required
            - Price: 0.01-999999.99, required
            - Category: default "general"
            - Stock: 0-100000, default 0
            - SKU: unique if provided
            - Owner: must exist if provided
        
        Args:
            payload: Product creation data
            owner_id: Optional owner user UUID
            
        Returns:
            Created product
            
        Raises:
            ValueError: If validation fails
            
        Example:
            product = await service.create_product(
                ProductCreate(
                    name="Laptop",
                    description="High-performance laptop",
                    price=Decimal("999.99"),
                    category="electronics",
                    stock_quantity=50,
                    sku="LAP-001",
                ),
                owner_id=user.id,
            )
        """
        # Validate business rules
        self._validate_product_data(payload)
        
        # Verify owner exists (if provided)
        if owner_id:
            owner = await self.users.get(owner_id)
            if owner is None:
                raise ValueError(f"Owner user not found: {owner_id}")
            if not owner.is_active:
                raise ValueError("Cannot assign product to inactive user")
        
        # Check SKU uniqueness (if provided)
        if payload.sku:
            if await self.products.exists_by_sku(payload.sku):
                raise ValueError(f"SKU already exists: {payload.sku}")
        
        # Create product entity
        product = Product(
            name=payload.name.strip(),
            description=(payload.description or "").strip(),
            price=payload.price,
            category=payload.category or DEFAULT_CATEGORY,
            owner_id=owner_id,
            stock_quantity=payload.stock_quantity or 0,
            sku=payload.sku,
            is_available=True,
        )
        
        # Persist
        product = await self.products.create(product)
        
        logger.info(
            "Product created",
            extra={
                "event": "product_created",
                "product_id": str(product.id),
                "name": product.name,
                "price": str(product.price),
                "category": product.category,
                "owner_id": str(owner_id) if owner_id else None,
            }
        )
        
        # Emit event for audit/notifications
        await self._emit_event("product.created", {
            "product_id": str(product.id),
            "owner_id": str(owner_id) if owner_id else None,
        })
        
        return product
    
    # ============================================================
    # PRODUCT UPDATES
    # ============================================================
    
    async def update_product(
        self,
        product: Product,
        payload: ProductUpdate,
        actor_id: Optional[UUID] = None,
    ) -> Product:
        """
        Update product with validated fields.
        
        Business Rules:
            - Only whitelisted fields can be updated
            - Price must remain in valid range
            - Name must remain valid length
            - Stock must remain non-negative
            - Actor must own product (or be admin)
        
        Args:
            product: Product instance to update
            payload: Update data
            actor_id: Optional actor user (for authorization)
            
        Returns:
            Updated product
            
        Raises:
            ValueError: If validation fails
            
        Example:
            product = await service.update_product(
                product,
                ProductUpdate(name="New Name", price=Decimal("199.99")),
                actor_id=user.id,
            )
        """
        # Authorization check
        if actor_id and product.owner_id and product.owner_id != actor_id:
            # TODO: Check if actor is admin
            logger.warning(
                "Unauthorized product update attempt",
                extra={
                    "event": "product_update_unauthorized",
                    "product_id": str(product.id),
                    "owner_id": str(product.owner_id),
                    "actor_id": str(actor_id),
                }
            )
            raise ValueError("Not authorized to update this product")
        
        # Whitelist of allowed update fields
        allowed_fields = {
            "name",
            "description",
            "price",
            "category",
            "is_available",
            "stock_quantity",
            "sku",
        }
        
        # Build update values (whitelisted)
        values: dict[str, Any] = {}
        payload_data = payload.model_dump(exclude_unset=True)
        
        for field, value in payload_data.items():
            if field not in allowed_fields:
                continue
            
            # Field-specific validation
            if field == "name":
                value = value.strip()
                if not (MIN_NAME_LENGTH <= len(value) <= MAX_NAME_LENGTH):
                    raise ValueError(
                        f"Name must be {MIN_NAME_LENGTH}-{MAX_NAME_LENGTH} characters"
                    )
            
            elif field == "price":
                if not (MIN_PRODUCT_PRICE <= value <= MAX_PRODUCT_PRICE):
                    raise ValueError(
                        f"Price must be between {MIN_PRODUCT_PRICE} and {MAX_PRODUCT_PRICE}"
                    )
            
            elif field == "stock_quantity":
                if value < 0:
                    raise ValueError("Stock quantity cannot be negative")
                if value > MAX_STOCK_QUANTITY:
                    raise ValueError(f"Stock cannot exceed {MAX_STOCK_QUANTITY}")
            
            elif field == "sku" and value:
                # Check uniqueness if SKU changed
                existing = await self.products.get_by_sku(value)
                if existing and existing.id != product.id:
                    raise ValueError(f"SKU already exists: {value}")
            
            elif field == "description":
                value = (value or "").strip()
                if len(value) > MAX_DESCRIPTION_LENGTH:
                    raise ValueError(
                        f"Description cannot exceed {MAX_DESCRIPTION_LENGTH} characters"
                    )
            
            values[field] = value
        
        # No changes to apply
        if not values:
            return product
        
        # Apply via repository
        product = await self.products.update(product, values)
        
        logger.info(
            "Product updated",
            extra={
                "event": "product_updated",
                "product_id": str(product.id),
                "fields": list(values.keys()),
                "actor_id": str(actor_id) if actor_id else None,
            }
        )
        
        return product
    
    # ============================================================
    # INVENTORY MANAGEMENT
    # ============================================================
    
    async def adjust_stock(
        self,
        product: Product,
        delta: int,
        reason: Optional[str] = None,
    ) -> Product:
        """
        Adjust product stock by a delta.
        
        Business Rules:
            - Positive delta: add stock (restock)
            - Negative delta: remove stock (sale)
            - Resulting stock cannot be negative
            - Cannot exceed MAX_STOCK_QUANTITY
        
        Args:
            product: Product instance
            delta: Amount to add (positive) or remove (negative)
            reason: Optional reason for audit
            
        Returns:
            Updated product
            
        Raises:
            ValueError: If insufficient stock or exceeds limit
            
        Example:
            # Sale of 5 units
            product = await service.adjust_stock(product, delta=-5, reason="sale")
            
            # Restock 100 units
            product = await service.adjust_stock(product, delta=100, reason="restock")
        """
        if delta == 0:
            return product
        
        # Calculate new quantity
        new_quantity = product.stock_quantity + delta
        
        # Validate
        if new_quantity < 0:
            raise ValueError(
                f"Insufficient stock: have {product.stock_quantity}, "
                f"need {abs(delta)}"
            )
        
        if new_quantity > MAX_STOCK_QUANTITY:
            raise ValueError(
                f"Stock cannot exceed {MAX_STOCK_QUANTITY}: "
                f"would be {new_quantity}"
            )
        
        # Apply change
        product = await self.products.update(
            product,
            {"stock_quantity": new_quantity}
        )
        
        logger.info(
            "Product stock adjusted",
            extra={
                "event": "product_stock_adjusted",
                "product_id": str(product.id),
                "delta": delta,
                "new_quantity": new_quantity,
                "reason": reason,
            }
        )
        
        # Low stock alert
        if new_quantity <= LOW_STOCK_THRESHOLD and new_quantity > 0:
            await self._emit_event("product.low_stock", {
                "product_id": str(product.id),
                "product_name": product.name,
                "stock_quantity": new_quantity,
                "threshold": LOW_STOCK_THRESHOLD,
            })
        
        # Out of stock alert
        if new_quantity == 0:
            await self._emit_event("product.out_of_stock", {
                "product_id": str(product.id),
                "product_name": product.name,
            })
        
        return product
    
    async def set_availability(
        self,
        product: Product,
        is_available: bool,
        actor_id: Optional[UUID] = None,
    ) -> Product:
        """
        Set product availability.
        
        Args:
            product: Product instance
            is_available: New availability status
            actor_id: Optional actor for audit
            
        Returns:
            Updated product
        """
        if product.is_available == is_available:
            return product
        
        product = await self.products.update(
            product,
            {"is_available": is_available}
        )
        
        logger.info(
            "Product availability changed",
            extra={
                "event": "product_availability_changed",
                "product_id": str(product.id),
                "is_available": is_available,
                "actor_id": str(actor_id) if actor_id else None,
            }
        )
        
        return product
    
    # ============================================================
    # PRICING
    # ============================================================
    
    async def update_price(
        self,
        product: Product,
        new_price: Decimal,
        actor_id: Optional[UUID] = None,
    ) -> Product:
        """
        Update product price with validation.
        
        Args:
            product: Product instance
            new_price: New price
            actor_id: Optional actor for audit
            
        Returns:
            Updated product
            
        Raises:
            ValueError: If price is invalid
        """
        if not (MIN_PRODUCT_PRICE <= new_price <= MAX_PRODUCT_PRICE):
            raise ValueError(
                f"Price must be between {MIN_PRODUCT_PRICE} and {MAX_PRODUCT_PRICE}"
            )
        
        old_price = product.price
        
        if old_price == new_price:
            return product
        
        product = await self.products.update(product, {"price": new_price})
        
        logger.info(
            "Product price updated",
            extra={
                "event": "product_price_updated",
                "product_id": str(product.id),
                "old_price": str(old_price),
                "new_price": str(new_price),
                "actor_id": str(actor_id) if actor_id else None,
            }
        )
        
        return product
    
    async def apply_bulk_price_update(
        self,
        product_ids: Sequence[UUID],
        percentage_change: Decimal,
        actor_id: Optional[UUID] = None,
    ) -> int:
        """
        Apply percentage change to multiple products.
        
        Args:
            product_ids: Product IDs to update
            percentage_change: e.g., Decimal("10") for +10%, Decimal("-5") for -5%
            actor_id: Optional actor for audit
            
        Returns:
            Number of products updated
            
        Example:
            # Increase prices by 15%:
            await service.apply_bulk_price_update(
                product_ids,
                Decimal("15"),
                actor_id=admin.id,
            )
        """
        if not product_ids:
            return 0
        
        multiplier = Decimal("1") + (percentage_change / Decimal("100"))
        updated_count = 0
        
        for product_id in product_ids:
            product = await self.products.get(product_id)
            if product is None:
                continue
            
            new_price = (product.price * multiplier).quantize(Decimal("0.01"))
            
            # Enforce minimum
            if new_price < MIN_PRODUCT_PRICE:
                new_price = MIN_PRODUCT_PRICE
            
            await self.products.update(product, {"price": new_price})
            updated_count += 1
        
        logger.warning(
            "Bulk price update applied",
            extra={
                "event": "products_bulk_price_updated",
                "count": updated_count,
                "percentage_change": str(percentage_change),
                "actor_id": str(actor_id) if actor_id else None,
            }
        )
        
        return updated_count
    
    # ============================================================
    # QUERIES
    # ============================================================
    
    async def get_product(self, product_id: UUID) -> Optional[Product]:
        """Get product by ID."""
        return await self.products.get(product_id)
    
    async def get_or_404(self, product_id: UUID) -> Product:
        """Get product by ID or raise LookupError."""
        product = await self.products.get(product_id)
        if product is None:
            raise LookupError(f"Product not found: {product_id}")
        return product
    
    async def list_products(
        self,
        offset: int = 0,
        limit: int = 50,
        category: Optional[str] = None,
        min_price: Optional[Decimal] = None,
        max_price: Optional[Decimal] = None,
        is_available: Optional[bool] = None,
        owner_id: Optional[UUID] = None,
        sort_by: str = "created_at",
        sort_desc: bool = True,
    ) -> Sequence[Product]:
        """
        List products with filters and sorting.
        
        See ProductRepository.get_all() for filter details.
        """
        return await self.products.get_all(
            offset=offset,
            limit=limit,
            category=category,
            min_price=min_price,
            max_price=max_price,
            is_available=is_available,
            owner_id=owner_id,
            sort_by=sort_by,
            sort_desc=sort_desc,
        )
    
    async def search(
        self,
        query: str,
        offset: int = 0,
        limit: int = 50,
    ) -> Sequence[Product]:
        """
        Search products by name/description.
        
        Args:
            query: Search term
            offset: Pagination offset
            limit: Page size
            
        Returns:
            Matching products
        """
        if not query or not query.strip():
            return []
        
        return await self.products.search_products(query, offset, limit)
    
    async def get_available_products(
        self,
        offset: int = 0,
        limit: int = 50,
    ) -> Sequence[Product]:
        """Get products available and in stock."""
        return await self.products.get_available_products(offset, limit)
    
    async def get_low_stock_products(
        self,
        threshold: int = LOW_STOCK_THRESHOLD,
    ) -> Sequence[Product]:
        """Get products with low stock (restock alerts)."""
        return await self.products.get_low_stock_products(threshold)
    
    async def get_categories(self) -> Sequence[str]:
        """Get all unique categories."""
        return await self.products.get_categories()
    
    async def get_statistics(self) -> dict[str, Any]:
        """Get product statistics."""
        return await self.products.get_statistics()
    
    # ============================================================
    # BULK OPERATIONS
    # ============================================================
    
    async def bulk_activate(
        self,
        product_ids: Sequence[UUID],
        actor_id: Optional[UUID] = None,
    ) -> int:
        """
        Activate multiple products at once.
        
        Args:
            product_ids: Product IDs to activate
            actor_id: Optional actor for audit
            
        Returns:
            Number of products updated
        """
        if not product_ids:
            return 0
        
        count = await self.products.bulk_update_availability(
            product_ids, True
        )
        
        logger.info(
            "Products bulk activated",
            extra={
                "event": "products_bulk_activated",
                "count": count,
                "actor_id": str(actor_id) if actor_id else None,
            }
        )
        
        return count
    
    async def bulk_deactivate(
        self,
        product_ids: Sequence[UUID],
        actor_id: Optional[UUID] = None,
    ) -> int:
        """Deactivate multiple products at once."""
        if not product_ids:
            return 0
        
        count = await self.products.bulk_update_availability(
            product_ids, False
        )
        
        logger.warning(
            "Products bulk deactivated",
            extra={
                "event": "products_bulk_deactivated",
                "count": count,
                "actor_id": str(actor_id) if actor_id else None,
            }
        )
        
        return count
    
    # ============================================================
    # DELETE OPERATIONS
    # ============================================================
    
    async def delete_product(
        self,
        product: Product,
        actor_id: Optional[UUID] = None,
        hard_delete: bool = False,
    ) -> None:
        """
        Delete a product (soft or hard).
        
        Args:
            product: Product instance
            actor_id: Optional actor for audit
            hard_delete: If True, hard delete (default: soft)
            
        Note:
            Soft delete sets is_available=False and preserves data.
            Hard delete removes the record permanently.
        """
        product_id = product.id
        product_name = product.name
        
        if hard_delete:
            await self.products.delete(product)
            logger.warning(
                "Product hard deleted",
                extra={
                    "event": "product_hard_deleted",
                    "product_id": str(product_id),
                    "name": product_name,
                    "actor_id": str(actor_id) if actor_id else None,
                }
            )
        else:
            # Soft delete via is_available
            await self.products.update(product, {"is_available": False})
            logger.info(
                "Product soft deleted",
                extra={
                    "event": "product_soft_deleted",
                    "product_id": str(product_id),
                    "name": product_name,
                    "actor_id": str(actor_id) if actor_id else None,
                }
            )
    
    # ============================================================
    # INTERNAL HELPERS
    # ============================================================
    
    def _validate_product_data(self, payload: ProductCreate) -> None:
        """
        Validate product creation data against business rules.
        
        Raises:
            ValueError: If any rule is violated
        """
        # Name validation
        if not payload.name or not payload.name.strip():
            raise ValueError("Product name is required")
        
        name = payload.name.strip()
        if not (MIN_NAME_LENGTH <= len(name) <= MAX_NAME_LENGTH):
            raise ValueError(
                f"Product name must be {MIN_NAME_LENGTH}-{MAX_NAME_LENGTH} characters"
            )
        
        # Description validation
        if payload.description and len(payload.description) > MAX_DESCRIPTION_LENGTH:
            raise ValueError(
                f"Description cannot exceed {MAX_DESCRIPTION_LENGTH} characters"
            )
        
        # Price validation
        if payload.price is None:
            raise ValueError("Price is required")
        
        if not (MIN_PRODUCT_PRICE <= payload.price <= MAX_PRODUCT_PRICE):
            raise ValueError(
                f"Price must be between {MIN_PRODUCT_PRICE} and {MAX_PRODUCT_PRICE}"
            )
        
        # Stock validation
        stock = payload.stock_quantity or 0
        if stock < 0:
            raise ValueError("Stock quantity cannot be negative")
        if stock > MAX_STOCK_QUANTITY:
            raise ValueError(f"Stock cannot exceed {MAX_STOCK_QUANTITY}")
    
    async def _emit_event(
        self,
        event_name: str,
        payload: dict[str, Any],
    ) -> None:
        """
        Emit a domain event.
        
        Placeholder for event bus integration.
        In production, this would publish to an event bus
        (e.g., Redis Pub/Sub, RabbitMQ, Kafka).
        """
        # TODO: Integrate with event bus
        # await self.event_bus.emit(event_name, payload)
        logger.debug(
            f"Event emitted: {event_name}",
            extra={
                "event": "domain_event",
                "event_name": event_name,
                "payload": payload,
            }
        )


# ============================================================
# EXPORTS
# ============================================================

__all__ = ["ProductService"]