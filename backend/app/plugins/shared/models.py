# backend/app/plugins/shared/models.py
"""
Shared models for XP, Achievements, and Activity tracking.
"""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, DateTime, ForeignKey,
    JSON, Float, Enum as SQLEnum
)
from sqlalchemy.orm import relationship
import enum

from app.core.database import Base


class AchievementCategory(str, enum.Enum):
    """Achievement categories"""
    TUTORIALS = "tutorials"
    COURSES = "courses"
    TYPING = "typing"
    SOCIAL = "social"
    STREAK = "streak"
    SPECIAL = "special"


class AchievementRarity(str, enum.Enum):
    """Achievement rarity levels"""
    COMMON = "common"
    UNCOMMON = "uncommon"
    RARE = "rare"
    EPIC = "epic"
    LEGENDARY = "legendary"


class Achievement(Base):
    """Achievement definitions"""
    __tablename__ = "achievements"

    id = Column(String(100), primary_key=True)  # e.g., "first_tutorial_complete"
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    icon = Column(String(100), default="trophy")  # Lucide icon name
    category = Column(SQLEnum(AchievementCategory), nullable=False, index=True)
    rarity = Column(SQLEnum(AchievementRarity), default=AchievementRarity.COMMON)
    xp_reward = Column(Integer, default=50)

    # Unlock conditions (JSON for flexibility)
    # Examples:
    # {"type": "count", "action": "tutorial_complete", "count": 1}
    # {"type": "count", "action": "typing_game_complete", "count": 10}
    # {"type": "value", "metric": "typing_wpm", "operator": ">=", "value": 100}
    # {"type": "streak", "days": 7}
    unlock_condition = Column(JSON, nullable=False)

    # Display settings
    is_hidden = Column(Boolean, default=False)  # Hidden until unlocked
    is_active = Column(Boolean, default=True)  # Can be earned
    sort_order = Column(Integer, default=0)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user_achievements = relationship("UserAchievement", back_populates="achievement")


class UserAchievement(Base):
    """User's unlocked achievements"""
    __tablename__ = "user_achievements"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    achievement_id = Column(String(100), ForeignKey("achievements.id", ondelete="CASCADE"), nullable=False, index=True)

    unlocked_at = Column(DateTime, default=datetime.utcnow)

    # Progress tracking (for achievements that require multiple actions)
    progress = Column(Integer, default=0)
    progress_max = Column(Integer, default=1)

    # Metadata
    unlock_context = Column(JSON)  # Store context of how it was unlocked

    # Relationships
    achievement = relationship("Achievement", back_populates="user_achievements")

    class Config:
        unique_together = [("user_id", "achievement_id")]


class ActivityType(str, enum.Enum):
    """Types of user activities"""
    TUTORIAL_START = "tutorial_start"
    TUTORIAL_STEP = "tutorial_step"
    TUTORIAL_COMPLETE = "tutorial_complete"
    COURSE_ENROLL = "course_enroll"
    LESSON_COMPLETE = "lesson_complete"
    MODULE_COMPLETE = "module_complete"
    COURSE_COMPLETE = "course_complete"
    TYPING_GAME = "typing_game"
    TYPING_PVP = "typing_pvp"
    ACHIEVEMENT_UNLOCK = "achievement_unlock"
    LEVEL_UP = "level_up"
    STREAK_MILESTONE = "streak_milestone"
    LOGIN = "login"


class UserActivity(Base):
    """User activity log for timeline and analytics"""
    __tablename__ = "user_activities"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    activity_type = Column(SQLEnum(ActivityType), nullable=False, index=True)

    # Reference to related content (optional)
    reference_type = Column(String(50))  # "tutorial", "course", "typing_game", etc.
    reference_id = Column(String(100))  # ID of the referenced content

    # Activity details
    title = Column(String(300))  # Human-readable description
    metadata = Column(JSON)  # Additional context data
    xp_earned = Column(Integer, default=0)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class XPTransaction(Base):
    """XP transaction log for auditing"""
    __tablename__ = "xp_transactions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    amount = Column(Integer, nullable=False)  # Can be negative for penalties
    action = Column(String(100), nullable=False)
    reason = Column(String(500))

    # Before/after state
    balance_before = Column(Integer, nullable=False)
    balance_after = Column(Integer, nullable=False)
    level_before = Column(Integer, nullable=False)
    level_after = Column(Integer, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class LevelConfig(Base):
    """Configurable level system settings"""
    __tablename__ = "level_config"

    id = Column(Integer, primary_key=True)
    level = Column(Integer, unique=True, nullable=False)
    xp_required = Column(Integer, nullable=False)
    title = Column(String(100))  # e.g., "Novice", "Apprentice", "Expert"
    badge_color = Column(String(50))  # Hex color or tailwind class
    perks = Column(JSON)  # List of perks unlocked at this level

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
