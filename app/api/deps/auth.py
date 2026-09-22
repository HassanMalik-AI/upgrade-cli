# FILE: backend/app/api/dependencies/auth.py

"""
Bearer-token dependencies for protected routes.
"""

# ============================================
# IMPORTS
# ============================================

from uuid import UUID
# UUID: Used to parse user ID from JWT token subject claim.
# Ensures the "sub" field is a valid UUID format.

from fastapi import Depends
# Depends: FastAPI's dependency injection system.
# Injects dependencies like database session, token extraction, etc.

from fastapi.security import OAuth2PasswordBearer
# OAuth2PasswordBearer: Creates a dependency that extracts the token
# from the Authorization: Bearer <token> header automatically.

from sqlalchemy.ext.asyncio import AsyncSession
# AsyncSession: SQLAlchemy's async database session for async/await operations.

# CUSTOM IMPORTS
from app.core.exceptions.custom_exceptions import UnauthorizedError
# Custom exception for unauthorized access (HTTP 401).

from app.core.security.jwt import decode_token
# JWT decoder function - validates and decodes the JWT token.

from app.db.session import get_db
# Database session dependency - creates async database connection.

from app.models.domain.user import User
# User domain model - represents the user entity in our system.


# ============================================
# OAUTH2 SCHEME
# ============================================

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")
# Creates an OAuth2PasswordBearer instance that tells FastAPI:
# - The token endpoint is "/api/v1/auth/login"
# - It will extract the token from the "Authorization: Bearer <token>" header
# - If no token, it returns a 401 Unauthorized automatically
# - The token is passed as a string to the dependency


# ============================================
# DEPENDENCY 1: GET CURRENT USER
# ============================================

async def get_current_user(
    token: str = Depends(oauth2_scheme),  # Extract token from header
    session: AsyncSession = Depends(get_db)  # Get database session
) -> User:
    """
    Decode an access token and load its user, failing closed on any error.
    
    This is the PRIMARY authentication dependency.
    Every protected route uses this to get the current authenticated user.
    
    FLOW:
    1. Extract JWT token from Authorization header
    2. Decode and validate the JWT token
    3. Extract user ID (subject) from token claims
    4. Fetch user from database using that ID
    5. Return User object or raise UnauthorizedError
    
    ERROR CASES HANDLED:
    - Invalid token format
    - Expired token
    - Invalid UUID format in token
    - User not found in database
    - Any other JWT decoding error
    
    Returns:
        User: The authenticated user object
        
    Raises:
        UnauthorizedError: If any validation fails
    """
    
    try:
        # STEP 1: Decode the JWT token
        # decode_token() validates signature, expiration, and returns payload
        # The "sub" claim typically contains the user ID
        token_payload = decode_token(token)
        
        # STEP 2: Extract and validate UUID
        # Convert string to UUID - raises ValueError if invalid format
        user_id = UUID(token_payload["sub"])
        
    except (ValueError, KeyError) as exc:
        # ValueError: Invalid UUID format
        # KeyError: "sub" claim missing from token
        # Re-raise as UnauthorizedError with generic message for security
        raise UnauthorizedError() from exc
    
    # STEP 3: Fetch user from database
    # session.get() performs: SELECT * FROM users WHERE id = user_id
    user = await session.get(User, user_id)
    
    # STEP 4: Validate user exists
    if user is None:
        # User might have been deleted after token was issued
        raise UnauthorizedError()
    
    # STEP 5: Return authenticated user
    return user


# ============================================
# DEPENDENCY 2: GET ACTIVE USER
# ============================================

async def get_current_active_user(
    user: User = Depends(get_current_user)  # First authenticate user
) -> User:
    """
    Reject deactivated accounts before protected business operations.
    
    This adds an extra layer of security by checking if the user account
    is active (not deactivated by admin or soft-deleted).
    
    USE CASE:
    - A user might be temporarily suspended
    - Account might be deactivated but token still valid
    - Prevents deactivated users from accessing routes
    
    Returns:
        User: The authenticated AND active user
        
    Raises:
        UnauthorizedError: If user account is not active
    """
    
    # Check if user account is active
    if not user.is_active:
        # Account is deactivated - reject access
        raise UnauthorizedError("Inactive account")
    
    # User is both authenticated and active
    return user


# ============================================
# DEPENDENCY 3: GET ADMIN USER
# ============================================

async def get_current_admin(
    user: User = Depends(get_current_active_user)  # First auth + active check
) -> User:
    """
    Require an active account with administrator privileges.
    
    This is the strictest authorization level.
    Only users with admin role can access these routes.
    
    USE CASE:
    - Admin dashboard
    - User management operations
    - System configuration endpoints
    - Analytics and reports
    
    Returns:
        User: The authenticated, active, and admin user
        
    Raises:
        UnauthorizedError: If user is not an admin
    """
    
    # Check if user has admin privileges
    if not user.is_admin:
        # User is authenticated but not authorized for admin routes
        raise UnauthorizedError("Administrator privileges required")
    
    # User is authenticated, active, AND admin
    return user


# ============================================
# DEPENDENCY CHAIN - HOW IT WORKS
# ============================================

"""
DEPENDENCY HIERARCHY:

get_current_user (Base level)
    └── get_current_active_user (Adds active check)
        └── get_current_admin (Adds admin check)

USAGE IN ROUTES:

@router.get("/profile")
async def get_profile(user: User = Depends(get_current_active_user)):
    # Any authenticated active user can access
    return user

@router.get("/admin/stats")
async def get_stats(user: User = Depends(get_current_admin)):
    # Only admin users can access
    return {"stats": "data"}

@router.post("/logout")
async def logout(user: User = Depends(get_current_user)):
    # Any authenticated user (even inactive) can logout
    return {"message": "Logged out"}
"""


# ============================================
# ALTERNATIVE: OPTIONAL AUTHENTICATION
# ============================================

"""
Sometimes you need optional authentication (e.g., public routes with extra features for logged-in users):

async def get_optional_user(
    token: Optional[str] = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_db)
) -> Optional[User]:
    try:
        if token:
            return await get_current_user(token, session)
    except UnauthorizedError:
        pass
    return None

# Usage:
@router.get("/public-items")
async def get_public_items(
    user: Optional[User] = Depends(get_optional_user)
):
    if user:
        # Show personalized items
        return items_with_user_preferences(user)
    # Show generic items
    return generic_items
"""