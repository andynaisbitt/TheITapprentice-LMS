# Backend\app\users\models.py
"""Enhanced User model with multiple roles and granular permissions"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, Enum as SQLEnum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base
import enum


class UserRole(str, enum.Enum):
    """User role types - comprehensive role system"""
    APPRENTICE = "apprentice"      # Free learners (default)
    SUPPORTER = "supporter"        # Paid learners (active subscription)
    CONTRIBUTOR = "contributor"    # Volunteers, coders, content helpers
    MENTOR = "mentor"              # Experienced volunteers/guides
    TUTOR = "tutor"                # Course creators/teachers
    AUTHOR = "author"              # Blog writers
    ADMIN = "admin"                # Full system access


class SubscriptionStatus(str, enum.Enum):
    """Subscription status types"""
    FREE = "free"
    ACTIVE = "active"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    PAST_DUE = "past_due"


class SubscriptionPlan(str, enum.Enum):
    """Subscription plan types"""
    PRO = "pro"                    # $9.99/month
    PREMIUM = "premium"            # $19.99/month
    ENTERPRISE = "enterprise"      # Custom pricing


class User(Base):
    """Enhanced User model with comprehensive profile and subscription management"""
    __tablename__ = "users"
    
    # Core authentication fields
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=True)  # Nullable for OAuth users
    
    # OAuth support
    google_id = Column(String(255), unique=True, nullable=True, index=True)
    
    # Profile information
    first_name = Column(String(50), nullable=False)
    last_name = Column(String(50), nullable=False)
    avatar_url = Column(String(500), nullable=True)
    bio = Column(Text, nullable=True)
    location = Column(String(100), nullable=True)
    
    # Role & permissions
    role = Column(SQLEnum(UserRole), default=UserRole.APPRENTICE, nullable=False, index=True)
    is_active = Column(Boolean, default=True, index=True)
    is_verified = Column(Boolean, default=False, index=True)
    
    # Granular permissions (can be granted to any role)
    can_create_courses = Column(Boolean, default=False, index=True)
    can_write_blog = Column(Boolean, default=False, index=True)
    can_moderate = Column(Boolean, default=False, index=True)
    
    # Subscription management
    subscription_status = Column(
        SQLEnum(SubscriptionStatus), 
        default=SubscriptionStatus.FREE, 
        nullable=False,
        index=True
    )
    subscription_plan = Column(SQLEnum(SubscriptionPlan), nullable=True)
    subscription_expires = Column(DateTime(timezone=True), nullable=True)
    
    # Stripe integration
    stripe_customer_id = Column(String(255), unique=True, nullable=True, index=True)
    stripe_subscription_id = Column(String(255), unique=True, nullable=True)
    
    # Gamification & progress
    total_points = Column(Integer, default=0, index=True)
    level = Column(Integer, default=1)
    courses_completed = Column(Integer, default=0)
    current_streak = Column(Integer, default=0)  # Daily login streak
    
    # Activity tracking
    last_login = Column(DateTime(timezone=True), nullable=True)
    login_count = Column(Integer, default=0)

    # Security & verification
    email_verified_at = Column(DateTime(timezone=True), nullable=True)  # When email was verified
    mfa_enabled = Column(Boolean, default=False, index=True)  # Multi-factor authentication enabled
    failed_login_attempts = Column(Integer, default=0)  # Failed login counter
    locked_until = Column(DateTime(timezone=True), nullable=True)  # Account lockout expiry

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    # NOTE: BlogCMS doesn't have skills/courses, so no relationships needed here
    # Blog posts are linked via BlogPost.author_id foreign key
    email_verifications = relationship("EmailVerification", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"
    
    @property
    def full_name(self) -> str:
        """Get user's full name"""
        return f"{self.first_name} {self.last_name}"
    
    @property
    def display_name(self) -> str:
        """Get display name (full name or username)"""
        if self.first_name and self.last_name:
            return self.full_name
        return self.username
    
    @property
    def has_active_subscription(self) -> bool:
        """Check if user has active paid subscription"""
        return self.subscription_status == SubscriptionStatus.ACTIVE
    
    @property
    def is_admin(self) -> bool:
        """Check if user is admin"""
        return self.role == UserRole.ADMIN
    
    @property
    def is_tutor(self) -> bool:
        """Check if user is a tutor or has course creation permission"""
        return self.role == UserRole.TUTOR or self.can_create_courses or self.is_admin
    
    @property
    def is_author(self) -> bool:
        """Check if user can write blog posts"""
        return self.role == UserRole.AUTHOR or self.can_write_blog or self.is_admin
    
    @property
    def is_mentor(self) -> bool:
        """Check if user is a mentor"""
        return self.role == UserRole.MENTOR
    
    @property
    def is_contributor(self) -> bool:
        """Check if user is a contributor"""
        return self.role == UserRole.CONTRIBUTOR
    
    @property
    def can_access_premium_content(self) -> bool:
        """Check if user can access premium content"""
        return (
            self.has_active_subscription or 
            self.role in [UserRole.SUPPORTER, UserRole.TUTOR, UserRole.AUTHOR, UserRole.ADMIN]
        )