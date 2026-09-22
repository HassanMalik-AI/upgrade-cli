"""
Generic async CRUD repository using SQLAlchemy expressions.

This module provides the BaseRepository class, a type-safe generic
repository that implements common CRUD operations for any SQLAlchemy
model. It serves as the foundation for all specific repositories.

Design Pattern: Repository Pattern
    The repository pattern abstracts data access logic behind a
    collection-like interface, providing:
    - Separation of concerns (data access vs business logic)
    - Testability (easy to mock repositories)
    - Flexibility (swap ORM without changing services)
    - Consistency (all models use same CRUD operations)

Design Principles:
    - Generic: Works with any model inheriting from Base
    - Type-safe: TypeVar ensures correct return types
    - Async-first: All operations are awaitable
    - Composable: Base for specialized repositories
    - Explicit: Clear method names and behavior

Usage:
    class UserRepository(BaseRepository[User]):
        def __init__(self, session: AsyncSession):
            super().__init__(session, User)
        
        async def get_by_email(self, email: str) -> User | None:
            stmt = select(User).where(User.email == email)
            return await self.session.scalar(stmt)

    # In service:
    repo = UserRepository(session)
    user = await repo.get(user_id)
"""

from typing import Any, Generic, Optional, Sequence, TypeVar
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import Base
from app.utils.logger import logger


# ============================================================
# TYPE VARIABLES
# ============================================================

# ModelT is bound to Base, ensuring repositories only work with
# SQLAlchemy models that inherit from our Base class.
# 
# This provides:
# - IDE autocomplete for model attributes
# - Type checking for repository methods
# - Prevention of misuse with non-model types
ModelT = TypeVar("ModelT", bound=Base)


# ============================================================
# BASE REPOSITORY
# ============================================================

class BaseRepository(Generic[ModelT]):
    """
    Generic async repository providing CRUD operations for any model.
    
    This class implements the Repository Pattern, providing a clean
    abstraction layer between services and database operations.
    
    All methods use SQLAlchemy's expression language (select, where, etc.)
    ensuring SQL injection is prevented via bound parameters.
    
    Attributes:
        session: The async SQLAlchemy session for database operations
        model: The SQLAlchemy model class this repository manages
        
    Type Safety:
        The Generic[ModelT] syntax allows type checkers to infer
        the return type of methods:
        
        repo = UserRepository(session)  # Type: BaseRepository[User]
        user = await repo.get(user_id)   # Type: User | None ✅
        users = await repo.list()        # Type: list[User] ✅
    
    Example:
        # Direct usage:
        repo = BaseRepository(session, User)
        user = await repo.get(user_id)
        
        # Inherited usage:
        class UserRepository(BaseRepository[User]):
            pass
        
        # Service usage:
        user = await self.user_repo.get(user_id)
    """
    
    def __init__(self, session: AsyncSession, model: type[ModelT]):
        """
        Initialize the repository.
        
        Args:
            session: Active async database session
            model: SQLAlchemy model class to manage
        """
        self.session = session
        self.model = model
    
    # ============================================================
    # READ OPERATIONS
    # ============================================================
    
    async def get(self, item_id: UUID) -> Optional[ModelT]:
        """
        Fetch a single record by primary key.
        
        Uses SQLAlchemy's `session.get()` which:
        - Uses identity map (returns cached instance if already loaded)
        - Generates efficient primary key lookup
        - Prevents SQL injection via bound parameters
        
        Args:
            item_id: Primary key value (UUID for our models)
            
        Returns:
            Model instance if found, None otherwise
            
        Example:
            user = await repo.get(UUID("abc-123..."))
            if user is None:
                raise HTTPException(404, "User not found")
        """
        return await self.session.get(self.model, item_id)
    
    async def get_by_id(self, item_id: UUID) -> Optional[ModelT]:
        """
        Alias for `get()` with explicit name.
        
        Provides clarity in service code where "by_id" makes
        the intent obvious:
        
        user = await repo.get_by_id(user_id)  # ✅ Clear
        user = await repo.get(user_id)         # ✅ Also fine
        
        Args:
            item_id: Primary key value
            
        Returns:
            Model instance if found, None otherwise
        """
        return await self.get(item_id)
    
    async def get_many(
        self,
        ids: Sequence[UUID],
    ) -> Sequence[ModelT]:
        """
        Fetch multiple records by primary keys in a single query.
        
        More efficient than N+1 queries when loading multiple records.
        
        Args:
            ids: Sequence of primary key values
            
        Returns:
            List of found models (missing IDs are omitted)
            
        Example:
            users = await repo.get_many([id1, id2, id3])
            # Single query instead of 3!
        """
        if not ids:
            return []
        
        stmt = select(self.model).where(self.model.id.in_(ids))
        result = await self.session.scalars(stmt)
        return result.all()
    
    async def exists(self, item_id: UUID) -> bool:
        """
        Check if a record exists without loading it.
        
        More efficient than `get()` when you only need existence check
        because it doesn't load full row data.
        
        Args:
            item_id: Primary key value
            
        Returns:
            True if record exists, False otherwise
            
        Example:
            if await repo.exists(user_id):
                # Do something
        """
        stmt = select(func.count()).select_from(self.model).where(
            self.model.id == item_id
        )
        count = await self.session.scalar(stmt)
        return count > 0
    
    async def count(self) -> int:
        """
        Count all records in the table.
        
        Returns:
            Total number of records
            
        Example:
            total = await repo.count()
        """
        stmt = select(func.count()).select_from(self.model)
        return await self.session.scalar(stmt) or 0
    
    async def list(
        self,
        offset: int = 0,
        limit: int = 50,
        max_limit: int = 100,
    ) -> Sequence[ModelT]:
        """
        Return a bounded page of records.
        
        Prevents unbounded database reads by capping limit.
        This is critical for production:
        - No user can request 1,000,000 records
        - Memory usage stays bounded
        - Response time stays reasonable
        
        Args:
            offset: Number of records to skip (pagination)
            limit: Number of records to return
            max_limit: Hard cap on limit (safety)
            
        Returns:
            List of models (max: max_limit)
            
        Example:
            # First page
            page1 = await repo.list(offset=0, limit=20)
            
            # Second page
            page2 = await repo.list(offset=20, limit=20)
            
            # Attempt to fetch too many (capped at 100)
            huge = await repo.list(limit=10000)  # Returns max 100
        """
        safe_limit = min(limit, max_limit)
        stmt = select(self.model).offset(offset).limit(safe_limit)
        result = await self.session.scalars(stmt)
        return result.all()
    
    async def list_all(self) -> Sequence[ModelT]:
        """
        Return ALL records (use with caution!).
        
        WARNING: Only use when you know the table is small.
        For large tables, use `list()` with pagination.
        
        Returns:
            All records in the table
            
        Example:
            # Small lookup table (categories, settings)
            categories = await category_repo.list_all()
        """
        stmt = select(self.model)
        result = await self.session.scalars(stmt)
        return result.all()
    
    # ============================================================
    # CREATE OPERATIONS
    # ============================================================
    
    async def create(self, instance: ModelT) -> ModelT:
        """
        Persist a new record.
        
        Performs three operations:
        1. Add instance to session (pending)
        2. Commit transaction (persist to DB)
        3. Refresh instance (load DB-generated values)
        
        Args:
            instance: Model instance to create
            
        Returns:
            The created instance (with DB-generated fields populated)
            
        Example:
            user = User(email="test@example.com", password_hash="...")
            created = await repo.create(user)
            print(created.id)  # UUID auto-generated
            print(created.created_at)  # Timestamp set by DB
        """
        self.session.add(instance)
        await self.session.commit()
        await self.session.refresh(instance)
        return instance
    
    async def create_many(
        self,
        instances: Sequence[ModelT],
    ) -> Sequence[ModelT]:
        """
        Persist multiple records in a single transaction.
        
        More efficient than calling `create()` in a loop
        (single commit instead of N commits).
        
        Args:
            instances: List of model instances
            
        Returns:
            The created instances
            
        Example:
            users = [User(...), User(...), User(...)]
            created = await repo.create_many(users)
            # Single INSERT + single COMMIT
        """
        self.session.add_all(instances)
        await self.session.commit()
        for instance in instances:
            await self.session.refresh(instance)
        return instances
    
    # ============================================================
    # UPDATE OPERATIONS
    # ============================================================
    
    async def update(
        self,
        instance: ModelT,
        values: dict[str, Any],
    ) -> ModelT:
        """
        Apply updates to an existing record.
        
        Args:
            instance: Existing model instance to update
            values: Dictionary of field names to new values
            
        Returns:
            The updated instance
            
        Example:
            user = await repo.get(user_id)
            updated = await repo.update(user, {
                "email": "new@example.com",
                "full_name": "New Name",
            })
        
        Security Notes:
            - Only fields in `values` are updated
            - Caller is responsible for whitelisting fields
            - Prevents mass-assignment vulnerabilities
            
        Example of whitelisting:
            ALLOWED_FIELDS = {"email", "full_name"}
            safe_values = {k: v for k, v in data.items() if k in ALLOWED_FIELDS}
            await repo.update(user, safe_values)
        """
        for field, value in values.items():
            setattr(instance, field, value)
        await self.session.commit()
        await self.session.refresh(instance)
        return instance
    
    async def update_by_id(
        self,
        item_id: UUID,
        values: dict[str, Any],
    ) -> Optional[ModelT]:
        """
        Update a record by ID.
        
        Convenience method that fetches then updates.
        
        Args:
            item_id: Primary key value
            values: Dictionary of field updates
            
        Returns:
            Updated instance if found, None otherwise
        """
        instance = await self.get(item_id)
        if instance is None:
            return None
        return await self.update(instance, values)
    
    # ============================================================
    # DELETE OPERATIONS
    # ============================================================
    
    async def delete(self, instance: ModelT) -> None:
        """
        Delete a record permanently.
        
        WARNING: This is a HARD DELETE. For soft delete,
        use the `soft_delete()` method from SoftDeleteMixin.
        
        Args:
            instance: Model instance to delete
            
        Example:
            user = await repo.get(user_id)
            if user:
                await repo.delete(user)
        """
        await self.session.delete(instance)
        await self.session.commit()
    
    async def delete_by_id(self, item_id: UUID) -> bool:
        """
        Delete a record by ID.
        
        Args:
            item_id: Primary key value
            
        Returns:
            True if deleted, False if not found
            
        Example:
            deleted = await repo.delete_by_id(user_id)
            if not deleted:
                raise HTTPException(404, "User not found")
        """
        instance = await self.get(item_id)
        if instance is None:
            return False
        await self.delete(instance)
        return True
    
    async def delete_many(self, ids: Sequence[UUID]) -> int:
        """
        Delete multiple records by IDs.
        
        Args:
            ids: List of primary key values
            
        Returns:
            Number of records deleted
            
        Example:
            count = await repo.delete_many([id1, id2, id3])
            print(f"Deleted {count} records")
        """
        if not ids:
            return 0
        
        # Use bulk delete for efficiency
        from sqlalchemy import delete as sql_delete
        
        stmt = sql_delete(self.model).where(self.model.id.in_(ids))
        result = await self.session.execute(stmt)
        await self.session.commit()
        return result.rowcount
    
    # ============================================================
    # TRANSACTION HELPERS
    # ============================================================
    
    async def commit(self) -> None:
        """
        Commit the current transaction.
        
        Useful when you need explicit transaction control:
        
        user = User(...)
        await repo.create(user)
        # ... more operations ...
        await repo.commit()
        """
        await self.session.commit()
    
    async def rollback(self) -> None:
        """
        Rollback the current transaction.
        
        Useful for error recovery:
        
        try:
            await repo.create(user)
            await repo.commit()
        except Exception:
            await repo.rollback()
            raise
        """
        await self.session.rollback()
    
    async def flush(self) -> None:
        """
        Flush pending changes without committing.
        
        Useful when you need IDs before final commit:
        
        user = User(...)
        repo.session.add(user)
        await repo.flush()  # User now has ID
        # Use user.id for related records
        await repo.commit()
        """
        await self.session.flush()