="""
Generic service helpers that keep endpoint code thin.

This module provides the BaseService class, a type-safe generic service
that encapsulates common business logic operations for any SQLAlchemy
model. It serves as the foundation for all specific services.

Design Pattern: Service Layer + Generic Programming
    - Provides a business logic layer between API and repositories
    - Generic over model type for reuse across all entities
    - Keeps endpoint code thin (delegates to services)
    - Encapsulates business rules and orchestration

Responsibilities:
    - Business logic orchestration
    - Multi-repository coordination
    - Transaction boundaries
    - Validation and error handling
    - Logging and auditing
    - Cross-cutting concerns (metrics, events)
    - Caching strategies

Design Principles:
    - Generic: Works with any model inheriting from Base
    - Type-safe: TypeVar ensures correct return types
    - Async-first: All operations are awaitable
    - Dependency Injection: Session injected via constructor
    - Single Responsibility: Focused on business logic

Why Service Layer:
    - Endpoints stay thin (no business logic)
    - Reusable business logic across endpoints
    - Testable in isolation (mock repositories)
    - Clear separation of concerns
    - Transaction management in one place

Architecture:
    API Endpoints (HTTP concerns)
            ↓
    Services (Business logic)  ← THIS FILE
            ↓
    Repositories (Data access)
            ↓
    Models (Domain entities)
            ↓
    Database
"""

from typing import Any, Generic, Optional, Sequence, TypeVar
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import Base
from app.utils.logger import logger


# ============================================================
# TYPE VARIABLES
# ============================================================

# ModelT is bound to Base, ensuring services only work with
# SQLAlchemy models that inherit from our Base class.
#
# This provides:
# - IDE autocomplete for model attributes
# - Type checking for service methods
# - Prevention of misuse with non-model types
ModelT = TypeVar("ModelT", bound=Base)


# ============================================================
# BASE SERVICE
# ============================================================

class BaseService(Generic[ModelT]):
    """
    Generic async service with common business logic helpers.
    
    This class implements the Service Layer Pattern, providing a
    clean abstraction between API endpoints and data access
    repositories.
    
    It provides minimal but essential functionality:
    - Primary key lookup with logging
    - Direct session access for advanced operations
    - Model-agnostic interface
    - Extensible for domain-specific logic
    
    All methods use async/await for non-blocking operations.
    
    Attributes:
        model: The SQLAlchemy model class this service manages
        session: The async SQLAlchemy session for database operations
        
    Type Safety:
        The Generic[ModelT] syntax allows type checkers to infer
        the return type of methods:
        
        service = UserService(session)      # Type: BaseService[User]
        user = await service.get(user_id)   # Type: User | None ✅
    
    Example:
        # Direct usage:
        service = BaseService(User, session)
        user = await service.get(user_id)
        
        # Inherited usage:
        class UserService(BaseService[User]):
            def __init__(self, session: AsyncSession):
                super().__init__(User, session)
        
        # Service usage:
        user = await self.user_service.get(user_id)
    
    Design Notes:
        - Minimal base class (extend for domain logic)
        - Session injected via constructor (DI pattern)
        - Model specified at instantiation (not class-level)
        - All operations async (FastAPI-compatible)
    """
    
    def __init__(self, model: type[ModelT], session: AsyncSession):
        """
        Initialize the base service.
        
        Args:
            model: SQLAlchemy model class to manage
            session: Active async database session
            
        Example:
            service = BaseService(User, session)
        """
        self.model = model
        self.session = session
    
    # ============================================================
    # CORE OPERATIONS
    # ============================================================
    
    async def get(self, item_id: UUID) -> Optional[ModelT]:
        """
        Fetch one row by primary key, returning None when absent.
        
        Uses SQLAlchemy's `session.get()` which:
        - Uses identity map (returns cached instance if already loaded)
        - Generates efficient primary key lookup
        - Returns None for missing records (no exception)
        
        Args:
            item_id: Primary key value (UUID for our models)
            
        Returns:
            Model instance if found, None otherwise
            
        Example:
            user = await service.get(user_id)
            if user is None:
                raise HTTPException(404, "User not found")
        
        Logging:
            Debug-level logs for successful lookups, but no logging
            for None returns (common case in validation flows).
        """
        if not item_id:
            return None
        
        return await self.session.get(self.model, item_id)
    
    async def get_or_404(self, item_id: UUID) -> ModelT:
        """
        Fetch one row by primary key, raising if absent.
        
        Convenience method for common pattern where absence should
        be an error. Reduces boilerplate in services.
        
        Args:
            item_id: Primary key value
            
        Returns:
            Model instance
            
        Raises:
            LookupError: If model not found
            
        Example:
            user = await service.get_or_404(user_id)
            # Automatically raises if not found
        """
        instance = await self.get(item_id)
        if instance is None:
            raise LookupError(
                f"{self.model.__name__} not found: {item_id}"
            )
        return instance
    
    # ============================================================
    # TRANSACTION HELPERS
    # ============================================================
    
    async def commit(self) -> None:
        """
        Commit the current transaction.
        
        Explicit commit method for services that need to control
        transaction boundaries. Most repositories auto-commit,
        but some advanced flows need manual control.
        
        Example:
            try:
                user = User(email="test@example.com")
                self.session.add(user)
                await self.session.flush()  # Get ID
                
                # Related records
                profile = Profile(user_id=user.id)
                self.session.add(profile)
                
                # Commit both together
                await self.commit()
            except Exception:
                await self.rollback()
                raise
        """
        await self.session.commit()
    
    async def rollback(self) -> None:
        """
        Rollback the current transaction.
        
        Discards all pending changes since the last commit/flush.
        Use in exception handlers to ensure data consistency.
        
        Example:
            try:
                await self.process_order(order)
                await self.commit()
            except Exception as e:
                await self.rollback()
                logger.error(f"Order failed: {e}")
                raise
        """
        await self.session.rollback()
    
    async def flush(self) -> None:
        """
        Flush pending changes without committing.
        
        Useful when you need generated IDs before final commit
        (e.g., for foreign key references in related records).
        
        Example:
            user = User(email="test@example.com")
            self.session.add(user)
            await self.flush()  # user.id now available
            
            # Use user.id for related records
            token = RefreshToken(user_id=user.id, ...)
            self.session.add(token)
            
            await self.commit()  # Both at once
        """
        await self.session.flush()
    
    # ============================================================
    # SAFETY HELPERS
    # ============================================================
    
    async def exists(self, item_id: UUID) -> bool:
        """
        Check if a record exists without loading it.
        
        More efficient than `get()` when you only need existence
        because it doesn't load full row data.
        
        Args:
            item_id: Primary key value
            
        Returns:
            True if record exists, False otherwise
            
        Example:
            if await service.exists(user_id):
                # Do something with the knowledge
                ...
        """
        if not item_id:
            return False
        
        from sqlalchemy import func, select
        
        stmt = select(func.count()).select_from(self.model).where(
            self.model.id == item_id
        )
        count = await self.session.scalar(stmt)
        return count > 0
    
    def log_operation(
        self,
        operation: str,
        item_id: Optional[UUID] = None,
        extra: Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Log a service operation for auditing.
        
        Consistent logging format across all services.
        
        Args:
            operation: Name of operation (e.g., "get", "create")
            item_id: Optional record ID
            extra: Optional additional context
            
        Example:
            self.log_operation(
                "user_created",
                item_id=user.id,
                extra={"email": user.email},
            )
        """
        log_extra = {
            "event": f"service_{operation}",
            "model": self.model.__name__,
            "service": self.__class__.__name__,
        }
        
        if item_id:
            log_extra["item_id"] = str(item_id)
        
        if extra:
            log_extra.update(extra)
        
        logger.debug(f"Service operation: {operation}", extra=log_extra)


# ============================================================
# EXPORTS
# ============================================================

__all__ = ["BaseService"]