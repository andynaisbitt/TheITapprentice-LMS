# Backend\app\auth\email_verification.py
"""
Email Verification System
Handles email verification for new user registrations
"""
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
from app.core.database import Base
import secrets
import random
import hashlib


class EmailVerification(Base):
    """Email verification tokens for user registration"""
    __tablename__ = "email_verifications"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    short_code = Column(String(6), nullable=False, index=True)  # 6-digit code
    long_token = Column(String(64), nullable=False, unique=True, index=True)  # UUID-like token
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    verified_at = Column(DateTime, nullable=True)
    is_used = Column(Boolean, nullable=False, default=False)

    # Relationship
    user = relationship("User", back_populates="email_verifications")


def generate_verification_tokens() -> tuple[str, str]:
    """
    Generate both short code (6 digits) and long token (64 chars)

    Returns:
        tuple: (short_code, long_token)
    """
    # Short code: 6 random digits
    short_code = ''.join([str(random.randint(0, 9)) for _ in range(6)])

    # Long token: 64-char secure random token
    long_token = secrets.token_urlsafe(48)[:64]  # URL-safe random string

    return short_code, long_token


def hash_token(token: str) -> str:
    """
    Hash token for secure storage

    Args:
        token: Plain token string

    Returns:
        str: SHA-256 hashed token
    """
    return hashlib.sha256(token.encode()).hexdigest()
