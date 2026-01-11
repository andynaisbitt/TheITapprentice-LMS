# Backend\app\auth\verification_routes.py
"""
Email Verification Routes
Handles email verification for user registration
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from app.core.database import get_db
from app.auth.email_verification import EmailVerification, generate_verification_tokens
from app.users.models import User
from app.services.email_service import email_service
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/verification", tags=["Email Verification"])


class SendVerificationRequest(BaseModel):
    email: EmailStr


class VerifyEmailRequest(BaseModel):
    token: str  # Can be either short_code (6 digits) or long_token


class ResendVerificationRequest(BaseModel):
    email: EmailStr


@router.post("/send")
async def send_verification_email(
    request: SendVerificationRequest,
    db: Session = Depends(get_db)
):
    """
    Send verification email to user
    Called internally after registration
    """
    # Find user by email
    user = db.query(User).filter(User.email == request.email).first()

    if not user:
        # Don't reveal if email exists (security)
        return {"message": "If this email is registered, a verification email will be sent."}

    # Check if already verified
    if user.email_verified_at:
        return {"message": "Email already verified"}

    # Check rate limit: Max 3 verification emails per 24 hours
    recent_verifications = db.query(EmailVerification).filter(
        EmailVerification.user_id == user.id,
        EmailVerification.created_at >= datetime.utcnow() - timedelta(hours=24)
    ).count()

    if recent_verifications >= 3:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many verification emails sent. Please try again later."
        )

    # Generate verification tokens
    short_code, long_token = generate_verification_tokens()

    # Create verification record
    verification = EmailVerification(
        user_id=user.id,
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

    success = email_service.send_verification_email(
        to_email=user.email,
        first_name=user.first_name,
        short_code=short_code,
        long_token=long_token,
        base_url=base_url
    )

    if success:
        logger.info(f"✅ Verification email sent to {user.email}")
        return {
            "message": "Verification email sent successfully",
            "email": user.email
        }
    else:
        logger.error(f"❌ Failed to send verification email to {user.email}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send verification email"
        )


@router.post("/verify")
async def verify_email(
    request: VerifyEmailRequest,
    db: Session = Depends(get_db)
):
    """
    Verify email using code or token

    Args:
        token: Either 6-digit code OR long token
    """
    token = request.token.strip()

    # Determine if it's short code (6 digits) or long token
    if len(token) == 6 and token.isdigit():
        # Short code
        verification = db.query(EmailVerification).filter(
            EmailVerification.short_code == token,
            EmailVerification.is_used == False,
            EmailVerification.expires_at > datetime.utcnow()
        ).first()
    else:
        # Long token
        verification = db.query(EmailVerification).filter(
            EmailVerification.long_token == token,
            EmailVerification.is_used == False,
            EmailVerification.expires_at > datetime.utcnow()
        ).first()

    if not verification:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification code"
        )

    # Get user
    user = db.query(User).filter(User.id == verification.user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Mark email as verified
    user.email_verified_at = datetime.utcnow()
    user.is_verified = True

    # Mark verification as used
    verification.is_used = True
    verification.verified_at = datetime.utcnow()

    db.commit()

    logger.info(f"✅ Email verified for user: {user.email}")

    return {
        "message": "Email verified successfully",
        "email": user.email,
        "verified_at": user.email_verified_at
    }


@router.post("/resend")
async def resend_verification_email(
    request: ResendVerificationRequest,
    db: Session = Depends(get_db)
):
    """
    Resend verification email
    Same as /send but explicit resend endpoint
    """
    return await send_verification_email(
        SendVerificationRequest(email=request.email),
        db
    )


@router.get("/status/{email}")
async def check_verification_status(
    email: str,
    db: Session = Depends(get_db)
):
    """
    Check if email is verified (public endpoint, doesn't reveal if email exists)
    """
    user = db.query(User).filter(User.email == email).first()

    if not user:
        # Don't reveal if email exists
        return {"is_verified": False}

    return {
        "is_verified": user.is_verified,
        "verified_at": user.email_verified_at
    }
