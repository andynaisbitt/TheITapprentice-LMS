# backend/app/plugins/shared/schemas.py
"""
Pydantic schemas for shared XP, Achievements, and Activity systems.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

from .models import AchievementCategory, AchievementRarity, ActivityType


# ============== XP Schemas ==============

class XPAwardRequest(BaseModel):
    """Request to award XP"""
    user_id: int
    action: str
    multiplier: float = 1.0
    reason: Optional[str] = None


class XPAwardResponse(BaseModel):
    """Response after awarding XP"""
    xp_awarded: int
    total_xp: int
    old_level: int
    new_level: int
    level_up: bool
    action: str
    reason: Optional[str] = None


class LevelProgressResponse(BaseModel):
    """User's level progress"""
    level: int
    total_xp: int
    xp_for_current_level: int
    xp_in_current_level: int
    xp_for_next_level: int
    progress_percent: int
    xp_to_next_level: int


class XPLeaderboardEntry(BaseModel):
    """Leaderboard entry"""
    rank: int
    user_id: int
    username: str
    display_name: Optional[str] = None
    total_xp: int
    level: int
    streak: int = 0


# ============== Achievement Schemas ==============

class AchievementBase(BaseModel):
    """Base achievement schema"""
    id: str = Field(..., min_length=1, max_length=100)
    name: str = Field(..., min_length=1, max_length=200)
    description: str
    icon: str = "trophy"
    category: AchievementCategory
    rarity: AchievementRarity = AchievementRarity.COMMON
    xp_reward: int = 50
    unlock_condition: Dict[str, Any]
    is_hidden: bool = False
    is_active: bool = True
    sort_order: int = 0


class AchievementCreate(AchievementBase):
    """Create achievement schema"""
    pass


class AchievementUpdate(BaseModel):
    """Update achievement schema"""
    name: Optional[str] = None
    description: Optional[str] = None
    icon: Optional[str] = None
    category: Optional[AchievementCategory] = None
    rarity: Optional[AchievementRarity] = None
    xp_reward: Optional[int] = None
    unlock_condition: Optional[Dict[str, Any]] = None
    is_hidden: Optional[bool] = None
    is_active: Optional[bool] = None
    sort_order: Optional[int] = None


class AchievementResponse(AchievementBase):
    """Achievement response schema"""
    created_at: datetime
    updated_at: datetime
    unlock_count: int = 0  # How many users have this

    class Config:
        from_attributes = True


class UserAchievementResponse(BaseModel):
    """User's achievement with unlock info"""
    achievement: AchievementResponse
    unlocked_at: datetime
    progress: int
    progress_max: int
    unlock_context: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True


class AchievementProgressResponse(BaseModel):
    """Achievement progress for a user"""
    achievement_id: str
    name: str
    description: str
    icon: str
    category: AchievementCategory
    rarity: AchievementRarity
    is_unlocked: bool
    unlocked_at: Optional[datetime] = None
    progress: int
    progress_max: int
    progress_percent: int


class AchievementUnlockResponse(BaseModel):
    """Response when achievement is unlocked"""
    achievement_id: str
    name: str
    description: str
    icon: str
    rarity: AchievementRarity
    xp_reward: int
    unlocked_at: datetime
    is_new: bool = True


# ============== Activity Schemas ==============

class ActivityCreate(BaseModel):
    """Create activity log entry"""
    user_id: int
    activity_type: ActivityType
    reference_type: Optional[str] = None
    reference_id: Optional[str] = None
    title: str
    activity_data: Optional[Dict[str, Any]] = None
    xp_earned: int = 0


class ActivityResponse(BaseModel):
    """Activity log entry response"""
    id: int
    user_id: int
    activity_type: ActivityType
    reference_type: Optional[str] = None
    reference_id: Optional[str] = None
    title: str
    activity_data: Optional[Dict[str, Any]] = None
    xp_earned: int
    created_at: datetime

    class Config:
        from_attributes = True


class ActivityTimelineResponse(BaseModel):
    """Timeline of activities"""
    activities: List[ActivityResponse]
    total: int
    has_more: bool


# ============== Dashboard Schemas ==============

class UserStatsResponse(BaseModel):
    """User statistics for dashboard"""
    # XP and Level
    total_xp: int
    level: int
    level_progress: LevelProgressResponse
    level_title: Optional[str] = None

    # Streak
    current_streak: int
    longest_streak: int = 0

    # Counts
    tutorials_completed: int = 0
    courses_completed: int = 0
    typing_games_played: int = 0
    achievements_unlocked: int = 0

    # Typing stats
    best_wpm: Optional[float] = None
    avg_accuracy: Optional[float] = None

    # Rankings
    xp_rank: Optional[int] = None
    typing_rank: Optional[int] = None


class DashboardResponse(BaseModel):
    """Full dashboard data"""
    stats: UserStatsResponse
    recent_achievements: List[AchievementUnlockResponse] = []
    recent_activities: List[ActivityResponse] = []
    in_progress: List[Dict[str, Any]] = []  # Tutorials/courses in progress
    suggested_content: List[Dict[str, Any]] = []


# ============== Level Config Schemas ==============

class LevelConfigBase(BaseModel):
    """Base level config schema"""
    level: int
    xp_required: int
    title: Optional[str] = None
    badge_color: Optional[str] = None
    perks: Optional[List[str]] = None


class LevelConfigCreate(LevelConfigBase):
    """Create level config"""
    pass


class LevelConfigUpdate(BaseModel):
    """Update level config"""
    xp_required: Optional[int] = None
    title: Optional[str] = None
    badge_color: Optional[str] = None
    perks: Optional[List[str]] = None


class LevelConfigResponse(LevelConfigBase):
    """Level config response"""
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ============== Admin Schemas ==============

class AchievementStatsResponse(BaseModel):
    """Admin stats for achievements"""
    total_achievements: int
    active_achievements: int
    total_unlocks: int
    unlocks_today: int
    most_unlocked: List[Dict[str, Any]]
    rarest_unlocked: List[Dict[str, Any]]


class XPStatsResponse(BaseModel):
    """Admin stats for XP system"""
    total_xp_awarded: int
    xp_awarded_today: int
    avg_level: float
    max_level: int
    level_distribution: Dict[str, int]  # {"1-10": 50, "11-20": 30, ...}
    top_earners_today: List[XPLeaderboardEntry]
