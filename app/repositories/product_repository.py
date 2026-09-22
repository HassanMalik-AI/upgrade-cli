"""
Product-specific query repository.

This module provides the ProductRepository class, which handles all
database operations for the Product model. It extends BaseRepository
with product-specific queries and inherits generic CRUD operations.

Design Pattern: Repository Pattern + Inheritance
    - BaseRepository provides generic CRUD
    - ProductRepository adds product-specific methods
    - Services depend on ProductRepository, not SQLAlchemy directly

Responsibilities:
    - Product lookup (by ID, SKU, owner)
    - Product listing with filters (category, price, availability)
    - Product search (name, description)
    - Product creation with validation
    - Product updates (whitelist enforced)
    - Inventory management (stock adjustments)
    - Admin operations (list all products)

Design Decisions:
    - Class-based (extends BaseRepository)
    - Async methods (all DB operations)
    - Type-safe returns (Product | None, list[Product])
    - Bounded queries (prevent OOM)
    - Whitelist sorting (prevent SQL injection via sort_by)
    - Decimal pricing (exact money math)
    - Owner scoping (multi-tenancy ready)
"""

from decimal import Decimal
from typing import Any, Optional, Sequence
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.domain.product import Product
from app.repositories.base.base_repository import BaseRepository
from app.utils.logger import logger


class ProductRepository(BaseRepository[Product]):
    """
    Repository for Product model with specialized queries.
    
    Extends BaseRepository[Product] to inherit:
    - get(id), get_by_id(id)
    - list(offset, limit)
    - create(instance)
    - update(instance, values)
    - delete(instance)
    
    Adds product-specific methods:
    - get_all() with filters
    - get_by_sku(sku)
    - get_by_category()
    - get_by_owner()
    - search_products()
    - get_available_products()
    - get_low_stock_products()
    - update_stock()
    - get_statistics()
    
    Example:
        # In service:
        repo = ProductRepository(session)
        
        # Generic methods (from BaseRepository)
        product = await repo.get(product_id)
        
        # Product-specific methods
        products = await repo.get_all(
            category="electronics",
            min_price=Decimal("100"),
            max_price=Decimal("500"),
            sort_by="price",
        )
    """
    
    # Sortable columns whitelist (security!)
    # Prevents SQL injection via sort_by parameter
    SORTABLE_COLUMNS = {
        "name": Product.name,
        "price": Product.price,
        "category": Product.category,
        "created_at": Product.created_at,
        "updated_at": Product.updated_at,
        "stock_quantity": Product.stock_quantity,
    }
    
    def __init__(self, session: AsyncSession):
        """
        Initialize product repository.
        
        Args:
            session: Async database session
        """
        super().__init__(session, Product)
    
    # ============================================================
    # LISTING WITH FILTERS
    # ============================================================
    
    async def get_all(
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
        Return a bounded, filtered, sorted product page.
        
        This is the main listing method with all supported filters.
        
        Args:
            offset: Pagination offset
            limit: Page size (capped at 100)
            category: Filter by category (exact match)
            min_price: Filter by minimum price (inclusive)
            max_price: Filter by maximum price (inclusive)
            is_available: Filter by availability
            owner_id: Filter by owner
            sort_by: Column name (whitelisted)
            sort_desc: Sort descending if True
            
        Returns:
            List of matching products
            
        Example:
            # Electronics products, price range, newest first
            products = await repo.get_all(
                category="electronics",
                min_price=Decimal("100.00"),
                max_price=Decimal("1000.00"),
                is_available=True,
                sort_by="created_at",
                sort_desc=True,
            )
        
        Security Notes:
            - sort_by is whitelisted (prevents SQL injection)
            - limit is capped (prevents OOM)
            - Uses bound parameters (SQLAlchemy)
        """
        query = select(Product)
        
        # Apply filters
        if category is not None:
            query = query.where(Product.category == category)
        
        if min_price is not None:
            query = query.where(Product.price >= min_price)
        
        if max_price is not None:
            query = query.where(Product.price <= max_price)
        
        if is_available is not None:
            query = query.where(Product.is_available == is_available)
        
        if owner_id is not None:
            query = query.where(Product.owner_id == owner_id)
        
        # Apply sorting (whitelisted)
        sort_column = self.SORTABLE_COLUMNS.get(sort_by, Product.created_at)
        if sort_desc:
            sort_column = sort_column.desc()
        query = query.order_by(sort_column)
        
        # Apply pagination
        query = query.offset(offset).limit(min(limit, 100))
        
        result = await self.session.scalars(query)
        return result.all()
    
    async def get_by_category(
        self,
        category: str,
        offset: int = 0,
        limit: int = 50,
    ) -> Sequence[Product]:
        """
        Get products by category.
        
        Args:
            category: Category name
            offset: Pagination offset
            limit: Page size
            
        Returns:
            Products in the category
        """
        return await self.get_all(
            category=category,
            offset=offset,
            limit=limit,
        )
    
    async def get_by_owner(
        self,
        owner_id: UUID,
        offset: int = 0,
        limit: int = 50,
    ) -> Sequence[Product]:
        """
        Get products owned by a user.
        
        Args:
            owner_id: Owner user ID
            offset: Pagination offset
            limit: Page size
            
        Returns:
            Products owned by the user
        """
        return await self.get_all(
            owner_id=owner_id,
            offset=offset,
            limit=limit,
        )
    
    async def get_available_products(
        self,
        offset: int = 0,
        limit: int = 50,
    ) -> Sequence[Product]:
        """
        Get products that are available and in stock.
        
        Args:
            offset: Pagination offset
            limit: Page size
            
        Returns:
            Available products
        """
        query = (
            select(Product)
            .where(Product.is_available == True)  # noqa: E712
            .where(Product.stock_quantity > 0)
            .order_by(Product.created_at.desc())
            .offset(offset)
            .limit(min(limit, 100))
        )
        result = await self.session.scalars(query)
        return result.all()
    
    async def get_low_stock_products(
        self,
        threshold: int = 5,
        offset: int = 0,
        limit: int = 50,
    ) -> Sequence[Product]:
        """
        Get products with low stock (for restocking alerts).
        
        Args:
            threshold: Stock threshold (products with less than this)
            offset: Pagination offset
            limit: Page size
            
        Returns:
            Products with low stock
            
        Example:
            low_stock = await repo.get_low_stock_products(threshold=10)
            for product in low_stock:
                await send_restock_alert(product)
        """
        query = (
            select(Product)
            .where(Product.is_available == True)  # noqa: E712
            .where(Product.stock_quantity <= threshold)
            .where(Product.stock_quantity > 0)  # Not out of stock
            .order_by(Product.stock_quantity.asc())
            .offset(offset)
            .limit(min(limit, 100))
        )
        result = await self.session.scalars(query)
        return result.all()
    
    async def get_out_of_stock_products(
        self,
        offset: int = 0,
        limit: int = 50,
    ) -> Sequence[Product]:
        """Get products that are out of stock."""
        query = (
            select(Product)
            .where(Product.is_available == True)  # noqa: E712
            .where(Product.stock_quantity == 0)
            .offset(offset)
            .limit(min(limit, 100))
        )
        result = await self.session.scalars(query)
        return result.all()
    
    # ============================================================
    # LOOKUP METHODS
    # ============================================================
    
    async def get_by_sku(self, sku: str) -> Optional[Product]:
        """
        Find a product by SKU.
        
        Args:
            sku: Stock keeping unit
            
        Returns:
            Product if found, None otherwise
        """
        if not sku:
            return None
        
        stmt = select(Product).where(Product.sku == sku)
        return await self.session.scalar(stmt)
    
    async def get_by_skus(self, skus: Sequence[str]) -> Sequence[Product]:
        """
        Find multiple products by SKUs.
        
        Args:
            skus: List of SKUs
            
        Returns:
            List of found products
        """
        if not skus:
            return []
        
        stmt = select(Product).where(Product.sku.in_(skus))
        result = await self.session.scalars(stmt)
        return result.all()
    
    async def exists_by_sku(self, sku: str) -> bool:
        """
        Check if a SKU exists.
        
        Args:
            sku: SKU to check
            
        Returns:
            True if SKU exists
        """
        if not sku:
            return False
        
        stmt = select(func.count()).select_from(Product).where(
            Product.sku == sku
        )
        count = await self.session.scalar(stmt)
        return count > 0
    
    # ============================================================
    # SEARCH
    # ============================================================
    
    async def search_products(
        self,
        query_text: str,
        offset: int = 0,
        limit: int = 50,
    ) -> Sequence[Product]:
        """
        Search products by name or description.
        
        Case-insensitive search using ILIKE.
        
        Args:
            query_text: Search term
            offset: Pagination offset
            limit: Page size
            
        Returns:
            Matching products
            
        Example:
            products = await repo.search_products("laptop")
        """
        if not query_text or not query_text.strip():
            return []
        
        search_term = f"%{query_text.strip()}%"
        
        query = (
            select(Product)
            .where(
                or_(
                    Product.name.ilike(search_term),
                    Product.description.ilike(search_term),
                )
            )
            .where(Product.is_available == True)  # noqa: E712
            .order_by(Product.created_at.desc())
            .offset(offset)
            .limit(min(limit, 100))
        )
        
        result = await self.session.scalars(query)
        return result.all()
    
    async def search_by_name(
        self,
        name: str,
        offset: int = 0,
        limit: int = 50,
    ) -> Sequence[Product]:
        """Search products by name only (faster than full-text)."""
        if not name or not name.strip():
            return []
        
        search_term = f"%{name.strip()}%"
        
        query = (
            select(Product)
            .where(Product.name.ilike(search_term))
            .order_by(Product.name)
            .offset(offset)
            .limit(min(limit, 100))
        )
        
        result = await self.session.scalars(query)
        return result.all()
    
    # ============================================================
    # PRICE QUERIES
    # ============================================================
    
    async def get_by_price_range(
        self,
        min_price: Decimal,
        max_price: Decimal,
        offset: int = 0,
        limit: int = 50,
    ) -> Sequence[Product]:
        """
        Get products within a price range.
        
        Args:
            min_price: Minimum price (inclusive)
            max_price: Maximum price (inclusive)
            offset: Pagination offset
            limit: Page size
            
        Returns:
            Products in price range
        """
        if min_price > max_price:
            raise ValueError("min_price cannot exceed max_price")
        
        return await self.get_all(
            min_price=min_price,
            max_price=max_price,
            sort_by="price",
            sort_desc=False,
            offset=offset,
            limit=limit,
        )
    
    async def get_price_statistics(
        self,
        category: Optional[str] = None,
    ) -> dict[str, Optional[Decimal]]:
        """
        Get price statistics (min, max, avg) for products.
        
        Args:
            category: Optional category filter
            
        Returns:
            Dict with min, max, avg prices
        """
        query = select(
            func.min(Product.price).label("min_price"),
            func.max(Product.price).label("max_price"),
            func.avg(Product.price).label("avg_price"),
        )
        
        if category:
            query = query.where(Product.category == category)
        
        result = await self.session.execute(query)
        row = result.first()
        
        return {
            "min_price": row.min_price if row else None,
            "max_price": row.max_price if row else None,
            "avg_price": (
                Decimal(str(round(row.avg_price, 2))) 
                if row and row.avg_price 
                else None
            ),
        }
    
    # ============================================================
    # CATEGORY QUERIES
    # ============================================================
    
    async def get_categories(self) -> Sequence[str]:
        """
        Get all unique categories.
        
        Returns:
            List of category names
        """
        query = select(Product.category).distinct().order_by(Product.category)
        result = await self.session.scalars(query)
        return result.all()
    
    async def count_by_category(self) -> dict[str, int]:
        """
        Get product count per category.
        
        Returns:
            Dict mapping category to count
        """
        query = (
            select(
                Product.category,
                func.count(Product.id).label("count"),
            )
            .group_by(Product.category)
            .order_by(Product.category)
        )
        
        result = await self.session.execute(query)
        return {row.category: row.count for row in result.all()}
    
    # ============================================================
    # CREATE WITH VALIDATION
    # ============================================================
    
    async def create_product(
        self,
        name: str,
        price: Decimal,
        description: str = "",
        category: str = "general",
        owner_id: Optional[UUID] = None,
        stock_quantity: int = 0,
        sku: Optional[str] = None,
        is_available: bool = True,
    ) -> Product:
        """
        Create a new product with validated fields.
        
        Args:
            name: Product name
            price: Product price (Decimal)
            description: Product description
            category: Product category
            owner_id: Owner user ID
            stock_quantity: Initial stock
            sku: Optional SKU
            is_available: Whether product is available
            
        Returns:
            Created product
            
        Raises:
            ValueError: If validation fails
        """
        # Validate
        if not name or not name.strip():
            raise ValueError("Product name is required")
        
        if price < Decimal("0"):
            raise ValueError("Price cannot be negative")
        
        if stock_quantity < 0:
            raise ValueError("Stock quantity cannot be negative")
        
        # Check SKU uniqueness
        if sku and await self.exists_by_sku(sku):
            raise ValueError(f"SKU {sku} already exists")
        
        # Create product
        product = Product(
            name=name.strip(),
            description=description.strip() if description else "",
            price=price,
            category=category or "general",
            owner_id=owner_id,
            stock_quantity=stock_quantity,
            sku=sku,
            is_available=is_available,
        )
        
        product = await self.create(product)
        
        logger.info(
            f"Product created",
            extra={
                "event": "product_created",
                "product_id": str(product.id),
                "category": category,
                "owner_id": str(owner_id) if owner_id else None,
            }
        )
        
        return product
    
    # ============================================================
    # UPDATE METHODS
    # ============================================================
    
    async def update_stock(
        self,
        product: Product,
        quantity_change: int,
    ) -> Product:
        """
        Adjust product stock by a delta.
        
        Positive delta = restock (add)
        Negative delta = sale (remove)
        
        Args:
            product: Product instance
            quantity_change: Amount to add (positive) or remove (negative)
            
        Returns:
            Updated product
            
        Raises:
            ValueError: If resulting stock would be negative
        """
        new_quantity = product.stock_quantity + quantity_change
        
        if new_quantity < 0:
            raise ValueError(
                f"Insufficient stock: have {product.stock_quantity}, "
                f"need {abs(quantity_change)}"
            )
        
        return await self.update(product, {"stock_quantity": new_quantity})
    
    async def set_availability(
        self,
        product: Product,
        is_available: bool,
    ) -> Product:
        """Set product availability."""
        return await self.update(product, {"is_available": is_available})
    
    async def update_price(
        self,
        product: Product,
        new_price: Decimal,
    ) -> Product:
        """
        Update product price.
        
        Args:
            product: Product instance
            new_price: New price (must be >= 0)
            
        Returns:
            Updated product
        """
        if new_price < Decimal("0"):
            raise ValueError("Price cannot be negative")
        
        return await self.update(product, {"price": new_price})
    
    async def update_details(
        self,
        product: Product,
        name: Optional[str] = None,
        description: Optional[str] = None,
        category: Optional[str] = None,
    ) -> Product:
        """
        Update product details (safe fields).
        
        Args:
            product: Product instance
            name: New name
            description: New description
            category: New category
            
        Returns:
            Updated product
        """
        values: dict[str, Any] = {}
        
        if name is not None:
            values["name"] = name.strip()
        
        if description is not None:
            values["description"] = description.strip()
        
        if category is not None:
            values["category"] = category
        
        if not values:
            return product
        
        return await self.update(product, values)
    
    # ============================================================
    # STATISTICS
    # ============================================================
    
    async def get_statistics(self) -> dict[str, Any]:
        """
        Get product statistics.
        
        Returns:
            Dict with counts and aggregate stats
        """
        total = await self.count()
        
        # Available count
        available_stmt = (
            select(func.count())
            .select_from(Product)
            .where(Product.is_available == True)  # noqa: E712
        )
        available = await self.session.scalar(available_stmt) or 0
        
        # Out of stock count
        out_of_stock_stmt = (
            select(func.count())
            .select_from(Product)
            .where(Product.stock_quantity == 0)
            .where(Product.is_available == True)  # noqa: E712
        )
        out_of_stock = await self.session.scalar(out_of_stock_stmt) or 0
        
        # Category count
        category_stmt = select(func.count(func.distinct(Product.category)))
        categories = await self.session.scalar(category_stmt) or 0
        
        return {
            "total": total,
            "available": available,
            "out_of_stock": out_of_stock,
            "categories": categories,
        }
    
    # ============================================================
    # BULK OPERATIONS
    # ============================================================
    
    async def delete_by_owner(self, owner_id: UUID) -> int:
        """
        Delete all products owned by a user.
        
        WARNING: This is a bulk hard delete!
        
        Args:
            owner_id: Owner user ID
            
        Returns:
            Number of products deleted
        """
        from sqlalchemy import delete as sql_delete
        
        stmt = sql_delete(Product).where(Product.owner_id == owner_id)
        result = await self.session.execute(stmt)
        await self.session.commit()
        count = result.rowcount
        
        if count > 0:
            logger.warning(
                f"Products deleted by owner",
                extra={
                    "event": "products_deleted_by_owner",
                    "owner_id": str(owner_id),
                    "count": count,
                }
            )
        
        return count
    
    async def bulk_update_availability(
        self,
        product_ids: Sequence[UUID],
        is_available: bool,
    ) -> int:
        """
        Bulk update product availability.
        
        Args:
            product_ids: List of product IDs
            is_available: New availability status
            
        Returns:
            Number of products updated
        """
        if not product_ids:
            return 0
        
        from sqlalchemy import update as sql_update
        
        stmt = (
            sql_update(Product)
            .where(Product.id.in_(product_ids))
            .values(is_available=is_available)
        )
        result = await self.session.execute(stmt)
        await self.session.commit()
        return result.rowcount


# ============================================================
# EXPORTS
# ============================================================

__all__ = ["ProductRepository"]