# Backend\app\auth\oauth.py
"""
Google OAuth authentication support
TODO: Implement when Google OAuth is needed
"""
from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import create_access_token
from app.auth.dependencies import get_current_user
from app.users.models import User, UserRole
from app.users.schemas import GoogleOAuthRegister, UserResponse
from datetime import timedelta
from app.core.config import settings
from app.api.v1.services.site_settings.models import SiteSettings
import secrets
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/oauth", tags=["OAuth"])


@router.post("/google", response_model=UserResponse)
async def google_oauth_login(
    oauth_data: GoogleOAuthRegister,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Google OAuth login/registration.
    
    - If user exists with google_id → Login
    - If user exists with email → Link Google account
    - If new user → Create account
    """
    
    print("=" * 80)
    print("🔐 GOOGLE OAUTH LOGIN ATTEMPT")
    print(f"📧 Email: {oauth_data.email}")
    print(f"🆔 Google ID: {oauth_data.google_id}")
    
    # Check if user exists by google_id
    user = db.query(User).filter(User.google_id == oauth_data.google_id).first()
    
    if user:
        print(f"✅ Existing Google user found: {user.email}")
    else:
        # Check if user exists by email
        user = db.query(User).filter(User.email == oauth_data.email).first()
        
        if user:
            # Link Google account to existing user
            print(f"🔗 Linking Google account to existing user: {user.email}")
            user.google_id = oauth_data.google_id

            # Update avatar if not set
            if not user.avatar_url and oauth_data.avatar_url:
                user.avatar_url = oauth_data.avatar_url

            # Mark as verified (Google verified the email)
            from datetime import datetime
            user.is_verified = True
            if not user.email_verified_at:
                user.email_verified_at = datetime.utcnow()

            db.commit()
        else:
            # Check if registration is enabled before creating new user
            site_settings = db.query(SiteSettings).first()
            if site_settings and not site_settings.registration_enabled:
                # Get custom message or use default
                message = site_settings.registration_disabled_message or \
                         "Registration is currently disabled. We are optimizing our systems and have enough users for this beta release. Thank you for your interest!"

                logger.info(f"Google OAuth registration blocked - feature disabled: {oauth_data.email}")
                print(f"❌ Registration blocked (disabled in settings): {oauth_data.email}")
                print("=" * 80)
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=message
                )

            # Create new user
            print(f"✨ Creating new user from Google OAuth: {oauth_data.email}")
            
            # Generate username from email
            username = oauth_data.email.split('@')[0].lower()
            base_username = username
            counter = 1
            
            # Ensure username is unique
            while db.query(User).filter(User.username == username).first():
                username = f"{base_username}{counter}"
                counter += 1
            
            from datetime import datetime

            user = User(
                email=oauth_data.email,
                username=username,
                first_name=oauth_data.first_name,
                last_name=oauth_data.last_name,
                google_id=oauth_data.google_id,
                avatar_url=oauth_data.avatar_url,

                # OAuth users don't need password
                hashed_password=None,

                # Default settings
                role=UserRole.APPRENTICE,  # Free learner (default role)
                is_active=True,
                is_verified=True,  # Google verified the email
                email_verified_at=datetime.utcnow(),  # Mark email as verified immediately

                # Initialize gamification
                total_points=0,
                level=1,
                login_count=0,
            )
            
            db.add(user)
            db.commit()
            db.refresh(user)
            
            print(f"✅ New user created: {user.username} (ID: {user.id})")
    
    # Check if user is active
    if not user.is_active:
        print("❌ User inactive")
        print("=" * 80)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive. Please contact support."
        )
    
    # Update last login
    from datetime import datetime
    user.last_login = datetime.utcnow()
    user.login_count += 1
    db.commit()
    
    # Create access token
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=access_token_expires
    )
    
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
    
    # Set CSRF token cookie
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        max_age=settings.COOKIE_MAX_AGE,
        httponly=False,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        path="/"
    )
    
    print(f"✅ Google OAuth successful: {user.email}")
    print("=" * 80)
    
    return user


@router.post("/google/unlink")
async def unlink_google_account(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Unlink Google account from user.
    Requires user to have a password set.
    """
    
    if not current_user.google_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No Google account linked"
        )
    
    if not current_user.hashed_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot unlink Google account without setting a password first"
        )
    
    current_user.google_id = None
    db.commit()
    
    return {"message": "Google account unlinked successfully"}


# ============================================================================
# TODO: Implement these when ready
# ============================================================================

# 1. Google OAuth Configuration
#    - Set up Google Cloud Console project
#    - Get OAuth 2.0 client ID and secret
#    - Add to .env file
#    - Configure redirect URIs

# 2. Frontend Integration
#    - Install @react-oauth/google
#    - Add GoogleLogin button
#    - Handle OAuth callback

# 3. Token Verification
#    - Use google.oauth2.credentials to verify tokens
#    - Extract user info from Google

# Example .env additions needed:
# GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
# GOOGLE_CLIENT_SECRET=your-client-secret
# GOOGLE_REDIRECT_URI=http://localhost:5173/auth/google/callback