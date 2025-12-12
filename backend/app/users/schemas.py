# Backend\app\users\schemas.py
"""Enhanced user schemas with registration and profile management"""
from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional
from datetime import datetime
from enum import Enum


class UserRole(str, Enum):
    """User role types - matches models.py"""
    APPRENTICE = "apprentice"      # Free learners (default)
    SUPPORTER = "supporter"        # Paid learners (active subscription)
    CONTRIBUTOR = "contributor"    # Volunteers, coders, content helpers
    MENTOR = "mentor"              # Experienced volunteers/guides
    TUTOR = "tutor"                # Course creators/teachers
    AUTHOR = "author"              # Blog writers
    ADMIN = "admin"                # Full system access


class SubscriptionStatus(str, Enum):
    """Subscription status"""
    FREE = "free"
    ACTIVE = "active"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    PAST_DUE = "past_due"


class SubscriptionPlan(str, Enum):
    """Subscription plan types"""
    BASIC = "basic"
    PRO = "pro"
    ENTERPRISE = "enterprise"


# ============================================================================
# REGISTRATION
# ============================================================================

class UserRegister(BaseModel):
    """User registration schema"""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50, pattern=r'^[a-zA-Z0-9_-]+$')
    password: str = Field(..., min_length=8, max_length=100)
    first_name: str = Field(..., min_length=1, max_length=50)
    last_name: str = Field(..., min_length=1, max_length=50)
    
    @field_validator('username')
    @classmethod
    def username_alphanumeric(cls, v: str) -> str:
        """Validate username is alphanumeric with underscores and hyphens"""
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('Username must be alphanumeric (underscores and hyphens allowed)')
        return v.lower()
    
    @field_validator('password')
    @classmethod
    def password_strength(cls, v: str) -> str:
        """Validate password strength"""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one number')
        return v


class GoogleOAuthRegister(BaseModel):
    """Google OAuth registration/login"""
    email: EmailStr
    google_id: str
    first_name: str
    last_name: str
    avatar_url: Optional[str] = None


# ============================================================================
# USER PROFILE
# ============================================================================

class UserProfileUpdate(BaseModel):
    """Update user profile"""
    first_name: Optional[str] = Field(None, min_length=1, max_length=50)
    last_name: Optional[str] = Field(None, min_length=1, max_length=50)
    bio: Optional[str] = Field(None, max_length=500)
    avatar_url: Optional[str] = None


class UserPasswordChange(BaseModel):
    """Change user password"""
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=100)
    
    @field_validator('new_password')
    @classmethod
    def password_strength(cls, v: str) -> str:
        """Validate password strength"""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one number')
        return v


# ============================================================================
# USER RESPONSES
# ============================================================================

class UserResponse(BaseModel):
    """User response schema (safe - no sensitive data)"""
    id: int
    email: str
    username: str
    first_name: str
    last_name: str
    avatar_url: Optional[str] = None
    bio: Optional[str] = None
    
    # OAuth
    google_id: Optional[str] = None  # For OAuth users
    
    # Role & status
    role: UserRole
    is_admin: bool
    is_active: bool
    is_verified: bool
    
    # Subscription
    subscription_status: SubscriptionStatus
    subscription_plan: Optional[SubscriptionPlan] = None
    subscription_expires: Optional[datetime] = None
    
    # Gamification
    total_points: int
    level: int
    
    # Timestamps
    created_at: datetime
    last_login: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class UserPublicProfile(BaseModel):
    """Public user profile (minimal info for other users to see)"""
    id: int
    username: str
    first_name: str
    last_name: str
    avatar_url: Optional[str] = None
    bio: Optional[str] = None
    role: UserRole
    total_points: int
    level: int
    created_at: datetime
    
    class Config:
        from_attributes = True


class UserStats(BaseModel):
    """User statistics and progress"""
    total_points: int
    level: int
    courses_enrolled: int
    courses_completed: int
    quizzes_taken: int
    achievements_earned: int
    current_streak: int  # Days in a row
    total_time_minutes: int


# ============================================================================
# ADMIN USER MANAGEMENT
# ============================================================================

class UserAdminUpdate(BaseModel):
    """Admin-only user update schema"""
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None
    subscription_status: Optional[SubscriptionStatus] = None
    subscription_plan: Optional[SubscriptionPlan] = None


class UserListResponse(BaseModel):
    """Paginated user list response"""
    users: list[UserResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# ============================================================================
# LEGACY (Keep for backwards compatibility)
# ============================================================================

class UserCreate(BaseModel):
    """Legacy user creation (admin only)"""
    email: EmailStr
    username: str
    password: str
    first_name: str
    last_name: str
    is_admin: bool = False


class Token(BaseModel):
    """JWT token response"""
    access_token: str
    token_type: str = "bearer"