# Backend\app\auth\dependencies.py
"""Authentication dependencies for protected routes with granular permissions"""
from fastapi import Depends, HTTPException, status, Cookie, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from typing import Optional
import logging

from app.core.database import get_db
from app.core.config import settings
from app.users.models import User, UserRole

# Setup logging
logger = logging.getLogger(__name__)

# OAuth2 scheme (for Swagger UI documentation)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)


def get_token_from_cookie(request: Request) -> Optional[str]:
    """Extract JWT token from HTTP-Only cookie"""
    return request.cookies.get(settings.COOKIE_NAME)


async def get_current_user(
    request: Request,
    db: Session = Depends(get_db)
) -> User:
    """
    Get current authenticated user from JWT token in cookie.
    Works with HTTP-Only cookies for security.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # Get token from cookie
    token = get_token_from_cookie(request)

    if not token:
        logger.warning(f"Authentication failed: No token in cookies for {request.url.path}")
        raise credentials_exception

    try:
        # Decode JWT token
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=["HS256"]
        )
        email: str = payload.get("sub")

        if email is None:
            logger.warning("Authentication failed: No email in token payload")
            raise credentials_exception

    except JWTError as e:
        logger.warning(f"JWT validation failed: {str(e)}")
        raise credentials_exception

    # Get user from database
    user = db.query(User).filter(User.email == email).first()

    if user is None:
        logger.warning(f"User not found: {email}")
        raise credentials_exception

    if not user.is_active:
        logger.warning(f"Inactive user attempted access: {email}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive"
        )

    logger.info(f"User authenticated: {user.email} (Role: {user.role})")
    return user


async def get_optional_user(
    request: Request,
    db: Session = Depends(get_db)
) -> Optional[User]:
    """
    Get current authenticated user from JWT token in cookie, or None if not authenticated.
    Use for endpoints that work for both authenticated and non-authenticated users.
    """
    # Get token from cookie
    token = get_token_from_cookie(request)

    if not token:
        return None

    try:
        # Decode JWT token
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=["HS256"]
        )
        email: str = payload.get("sub")

        if email is None:
            return None

    except JWTError:
        return None

    # Get user from database
    user = db.query(User).filter(User.email == email).first()

    if user is None or not user.is_active:
        return None

    return user


# ============================================================================
# ROLE-BASED PERMISSION CHECKS
# ============================================================================

async def require_admin(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Require admin role for route access.
    Use for system administration routes.
    """
    if current_user.role != UserRole.ADMIN:
        logger.warning(f"Admin access denied for user {current_user.email}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user


async def require_tutor_or_admin(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Require tutor role OR course creation permission.
    Use for course management routes.
    """
    if not current_user.is_tutor:
        logger.warning(f"Tutor access denied for user {current_user.email}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tutor privileges required to create courses"
        )
    return current_user


async def require_author_or_admin(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Require author role OR blog writing permission.
    Use for blog management routes.
    """
    if not current_user.is_author:
        logger.warning(f"Author access denied for user {current_user.email}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Author privileges required to write blog posts"
        )
    return current_user


async def require_moderator(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Require moderation permission.
    Use for content moderation routes.
    """
    if not (current_user.can_moderate or current_user.is_admin):
        logger.warning(f"Moderator access denied for user {current_user.email}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Moderator privileges required"
        )
    return current_user


async def require_mentor_or_above(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Require mentor, tutor, author, or admin role.
    Use for helping/teaching features.
    """
    allowed_roles = [UserRole.MENTOR, UserRole.TUTOR, UserRole.AUTHOR, UserRole.ADMIN]
    if current_user.role not in allowed_roles:
        logger.warning(f"Mentor access denied for user {current_user.email}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Mentor privileges or higher required"
        )
    return current_user


async def require_contributor_or_above(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Require contributor, mentor, tutor, author, or admin role.
    Use for community contribution features.
    """
    allowed_roles = [
        UserRole.CONTRIBUTOR, 
        UserRole.MENTOR, 
        UserRole.TUTOR, 
        UserRole.AUTHOR, 
        UserRole.ADMIN
    ]
    if current_user.role not in allowed_roles:
        logger.warning(f"Contributor access denied for user {current_user.email}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Contributor privileges or higher required"
        )
    return current_user


# ============================================================================
# SUBSCRIPTION-BASED ACCESS
# ============================================================================

async def require_active_subscription(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Require active paid subscription OR elevated role.
    Use for premium content routes.
    """
    if not current_user.can_access_premium_content:
        logger.info(f"Premium access denied for user {current_user.email}")
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="Active subscription required to access premium content"
        )
    return current_user


# ============================================================================
# GRANULAR PERMISSION CHECKS
# ============================================================================

async def require_course_creation_permission(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Require explicit course creation permission.
    More strict than role-based check.
    """
    if not (current_user.can_create_courses or current_user.is_admin):
        logger.warning(f"Course creation denied for user {current_user.email}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Course creation permission required"
        )
    return current_user


async def require_blog_writing_permission(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Require explicit blog writing permission.
    More strict than role-based check.
    """
    if not (current_user.can_write_blog or current_user.is_admin):
        logger.warning(f"Blog writing denied for user {current_user.email}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Blog writing permission required"
        )
    return current_user


# ============================================================================
# LEGACY COMPATIBILITY (deprecated)
# ============================================================================

async def get_current_admin_user(
    current_user: User = Depends(require_admin)
) -> User:
    """
    DEPRECATED: Use require_admin instead.
    Kept for backwards compatibility.
    """
    return current_user


# ============================================================================
# CSRF TOKEN VALIDATION
# ============================================================================

def verify_csrf_token(
    request: Request,
    csrf_token: Optional[str] = Cookie(None, alias="csrf_token")
) -> bool:
    """
    Verify CSRF token from cookie matches header.
    Use for state-changing operations (POST, PUT, DELETE).
    """
    header_token = request.headers.get("X-CSRF-Token")
    
    if not csrf_token or not header_token:
        logger.warning("CSRF validation failed: Missing token")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token missing"
        )
    
    if csrf_token != header_token:
        logger.warning("CSRF validation failed: Token mismatch")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid CSRF token"
        )
    
    return True