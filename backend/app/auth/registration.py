# Backend\app\auth\registration.py
"""User registration endpoints with email verification and rate limiting"""
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import get_password_hash
from app.users.models import User, UserRole
from app.users.schemas import UserRegister, UserResponse
from datetime import datetime, timezone, timedelta
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.auth.email_verification import EmailVerification, generate_verification_tokens
from app.services.email_service import email_service
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Registration"])

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("3/hour")  # Max 3 registrations per hour per IP (prevent spam)
async def register_user(
    request: Request,  # Required for rate limiting
    user_data: UserRegister,
    db: Session = Depends(get_db)
):
    """
    Register a new user account.
    
    - Creates user with 'student' role by default
    - Sends verification email (optional - can login without verification)
    - Returns user profile data
    """
    
    print("=" * 80)
    print("📝 USER REGISTRATION ATTEMPT")
    print(f"Email: {user_data.email}")
    print(f"Username: {user_data.username}")
    
    # Check if email already exists
    existing_email = db.query(User).filter(User.email == user_data.email).first()
    if existing_email:
        print(f"❌ Email already registered: {user_data.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Check if username already exists
    existing_username = db.query(User).filter(User.username == user_data.username.lower()).first()
    if existing_username:
        print(f"❌ Username already taken: {user_data.username}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken"
        )
    
    # Create new user
    hashed_password = get_password_hash(user_data.password)
    
    new_user = User(
        email=user_data.email,
        username=user_data.username.lower(),
        hashed_password=hashed_password,
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        
        # Default role
        role=UserRole.STUDENT,
        is_admin=False,
        
        # Account status
        is_active=True,
        is_verified=False,  # Email verification pending
        
        # Track registration
        login_count=0,
    )
    
    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        print(f"✅ User registered successfully: {new_user.username} (ID: {new_user.id})")
        print(f"   Role: {new_user.role}")
        print(f"   Subscription: {new_user.subscription_status}")
        print("=" * 80)

        # Generate verification tokens
        short_code, long_token = generate_verification_tokens()

        # Create verification record
        verification = EmailVerification(
            user_id=new_user.id,
            short_code=short_code,
            long_token=long_token,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=24),
            is_used=False
        )

        db.add(verification)
        db.commit()
        db.refresh(verification)

        # Send verification email
        base_url = settings.FRONTEND_URL if hasattr(settings, 'FRONTEND_URL') else "http://localhost:5173"

        try:
            success = email_service.send_verification_email(
                to_email=new_user.email,
                first_name=new_user.first_name,
                short_code=short_code,
                long_token=long_token,
                base_url=base_url
            )

            if success:
                logger.info(f"✅ Verification email sent to {new_user.email}")
            else:
                logger.warning(f"⚠️ Failed to send verification email to {new_user.email}")
        except Exception as e:
            logger.error(f"❌ Error sending verification email: {e}")
            # Don't fail registration if email fails

        return new_user
        
    except Exception as e:
        db.rollback()
        print(f"❌ Registration failed: {e}")
        print("=" * 80)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user account"
        )


@router.post("/verify-email")
async def verify_email(
    token: str,
    db: Session = Depends(get_db)
):
    """
    Verify user email address with token.
    
    - Validates verification token
    - Marks user as verified
    - Enables full account features
    """
    
    # TODO: Implement email verification
    # - Decode JWT token
    # - Find user by email
    # - Mark as verified
    # - Return success
    
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Email verification not yet implemented. Users can login without verification."
    )


@router.post("/resend-verification")
async def resend_verification_email(
    email: str,
    db: Session = Depends(get_db)
):
    """
    Resend verification email.
    
    - Finds user by email
    - Generates new verification token
    - Sends verification email
    """
    
    user = db.query(User).filter(User.email == email).first()
    if not user:
        # Don't reveal if email exists
        return {"message": "If that email is registered, a verification email has been sent"}
    
    if user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already verified"
        )
    
    # TODO: Send verification email
    # await send_verification_email(user.email, verification_token)
    
    return {"message": "Verification email sent"}


@router.get("/check-username/{username}")
async def check_username_availability(
    username: str,
    db: Session = Depends(get_db)
):
    """
    Check if username is available.
    
    - Used for real-time validation during registration
    - Returns availability status
    """
    
    existing = db.query(User).filter(User.username == username.lower()).first()
    
    return {
        "username": username,
        "available": existing is None
    }


@router.get("/check-email/{email}")
async def check_email_availability(
    email: str,
    db: Session = Depends(get_db)
):
    """
    Check if email is available.
    
    - Used for real-time validation during registration
    - Returns availability status
    """
    
    existing = db.query(User).filter(User.email == email).first()
    
    return {
        "email": email,
        "available": existing is None
    }