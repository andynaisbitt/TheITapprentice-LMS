# Backend\app\auth\routes.py (SECURITY HARDENED VERSION)
"""Enhanced authentication routes with comprehensive security measures"""
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import timedelta, datetime, timezone
import logging

from app.core.database import get_db
from app.core.security import verify_password, create_access_token, get_password_hash
from app.core.config import settings
from app.core.security_utils import mask_email, SafeLogger
from app.core.rate_limit_middleware import limiter, user_limiter
from app.users.models import User
from app.users.schemas import UserResponse, UserProfileUpdate, UserPasswordChange
from app.auth.dependencies import get_current_user
from app.plugins.shared.xp_service import xp_service
from app.plugins.shared.achievement_service import achievement_service
import secrets

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Setup secure logging
logger = logging.getLogger(__name__)
safe_logger = SafeLogger(logger)


@router.post("/login")
@limiter.limit("5/minute")  # Max 5 login attempts per minute per IP
async def login(
    request: Request,  # Required for rate limiting
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    Login with email and password.
    Returns user data and sets HTTP-Only cookie with JWT token.

    Rate Limited: 5 attempts per minute per IP
    """
    # Use safe logging with email masking
    safe_logger.info("Login attempt from {email}", email=form_data.username)

    # Find user by email
    user = db.query(User).filter(User.email == form_data.username).first()

    # Verify credentials
    if not user or not verify_password(form_data.password, user.hashed_password):
        safe_logger.warning("Failed login attempt for {email}", email=form_data.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if user is active
    if not user.is_active:
        safe_logger.warning("Inactive user login attempt: {email}", email=user.email)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive. Please contact support."
        )

    safe_logger.info("User authenticated: {email} (Role: {role})", email=user.email, role=user.role)

    # Update last login (using timezone-aware datetime)
    user.last_login = datetime.now(timezone.utc)
    user.login_count += 1
    db.commit()

    # Check and update daily streak
    streak_result = xp_service.check_and_update_streak(db, user.id)
    safe_logger.info("Streak updated for {email}: {streak} days", email=user.email, streak=streak_result.get("streak", 0))

    # Check for streak-based achievements
    achievement_service.check_and_unlock_achievements(db, user.id, "daily_login", {"streak": streak_result.get("streak", 0)})
    
    # Create access token
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=access_token_expires
    )

    safe_logger.info("Access token created for {email}", email=user.email)
    
    # Generate CSRF token
    csrf_token = secrets.token_urlsafe(32)
    
    # Set HTTP-Only cookie with JWT
    response.set_cookie(
        key=settings.COOKIE_NAME,
        value=access_token,
        max_age=settings.COOKIE_MAX_AGE,
        httponly=settings.COOKIE_HTTPONLY,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        path="/"
    )
    
    # Set CSRF token cookie (not HTTP-Only, needs to be read by JS)
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        max_age=settings.COOKIE_MAX_AGE,
        httponly=False,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        path="/"
    )
    
    print("[LOGIN] Cookies set in response")
    print("=" * 80)
    
    # Return user data, CSRF token, and access token for WebSocket auth
    return {
        "message": "Login successful",
        "user": {
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "role": user.role,
            "is_admin": user.is_admin,
            "is_active": user.is_active,
            "is_verified": user.is_verified,
            "subscription_status": user.subscription_status,
            "subscription_plan": user.subscription_plan,
            "total_points": user.total_points,
            "level": user.level,
            "current_streak": user.current_streak,
        },
        "streak": streak_result,  # Include streak info in response
        "csrf_token": csrf_token,
        "access_token": access_token,  # For WebSocket authentication
        "token_type": "bearer"
    }


@router.post("/logout")
async def logout(response: Response):
    """
    Logout user by clearing authentication cookies.
    """
    # Clear JWT cookie
    response.delete_cookie(
        key=settings.COOKIE_NAME,
        path="/"
    )
    
    # Clear CSRF cookie
    response.delete_cookie(
        key="csrf_token",
        path="/"
    )
    
    return {"message": "Logout successful"}


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """
    Get current authenticated user information.
    Requires valid JWT token in cookie.
    """
    return current_user


@router.put("/me", response_model=UserResponse)
async def update_profile(
    profile_data: UserProfileUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update current user's profile information.
    """
    
    # Update fields if provided
    if profile_data.first_name is not None:
        current_user.first_name = profile_data.first_name
    if profile_data.last_name is not None:
        current_user.last_name = profile_data.last_name
    if profile_data.bio is not None:
        current_user.bio = profile_data.bio
    if profile_data.avatar_url is not None:
        current_user.avatar_url = profile_data.avatar_url
    
    db.commit()
    db.refresh(current_user)
    
    return current_user


@router.post("/change-password")
async def change_password(
    password_data: UserPasswordChange,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Change user's password.
    Requires current password for verification.
    """
    
    # Verify current password
    if not verify_password(password_data.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Check new password is different
    if verify_password(password_data.new_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from current password"
        )
    
    # Update password
    current_user.hashed_password = get_password_hash(password_data.new_password)
    db.commit()
    
    return {"message": "Password changed successfully"}


@router.post("/refresh")
async def refresh_token(
    response: Response,
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """
    Refresh JWT token.
    Generates new token and CSRF token, extends session.
    """
    # Create new access token
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": current_user.email},
        expires_delta=access_token_expires
    )
    
    # Generate new CSRF token
    csrf_token = secrets.token_urlsafe(32)
    
    # Set new cookies
    response.set_cookie(
        key=settings.COOKIE_NAME,
        value=access_token,
        max_age=settings.COOKIE_MAX_AGE,
        httponly=settings.COOKIE_HTTPONLY,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        path="/"
    )
    
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        max_age=settings.COOKIE_MAX_AGE,
        httponly=False,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        path="/"
    )
    
    return {
        "message": "Token refreshed",
        "csrf_token": csrf_token
    }