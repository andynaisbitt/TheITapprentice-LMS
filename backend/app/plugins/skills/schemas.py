# backend/app/plugins/skills/schemas.py
"""
Skill System Pydantic Schemas

Request/response models for the skills API.
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


# =============================================================================
# SKILL SCHEMAS (Base skill definitions)
# =============================================================================

class SkillBase(BaseModel):
    """Base skill fields"""
    name: str = Field(..., min_length=1, max_length=100)
    slug: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    icon: Optional[str] = Field(None, max_length=10)  # Emoji
    category: str = Field(default="technical")  # technical or soft
    display_order: int = Field(default=0)


class SkillCreate(SkillBase):
    """Schema for creating a new skill (admin)"""
    pass


class SkillUpdate(BaseModel):
    """Schema for updating a skill (admin)"""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None
    icon: Optional[str] = Field(None, max_length=10)
    category: Optional[str] = None
    display_order: Optional[int] = None
    is_active: Optional[bool] = None


class SkillResponse(BaseModel):
    """Public skill information"""
    id: int
    name: str
    slug: str
    description: Optional[str] = None
    icon: Optional[str] = None
    category: str
    display_order: int
    is_active: bool

    class Config:
        from_attributes = True


# =============================================================================
# USER SKILL PROGRESS SCHEMAS
# =============================================================================

class UserSkillProgress(BaseModel):
    """User's progress on a single skill"""
    skill_id: int
    skill_name: str
    skill_slug: str
    skill_icon: Optional[str] = None
    skill_category: str

    # XP and level
    current_xp: int
    current_level: int  # 1-99
    xp_to_next_level: int
    xp_for_next_level: int  # Total XP needed for next level
    xp_progress_percentage: float  # 0-100

    # Activity stats
    total_activities_completed: int
    last_activity_at: Optional[datetime] = None

    # Tier info (Novice, Apprentice, Journeyman, Expert, Master, Grandmaster)
    tier: str
    tier_color: str

    # Milestone achievements
    level_10_achieved: bool = False
    level_30_achieved: bool = False
    level_50_achieved: bool = False
    level_75_achieved: bool = False
    level_99_achieved: bool = False

    class Config:
        from_attributes = True


class UserSkillsOverview(BaseModel):
    """Complete overview of all user skills"""
    skills: List[UserSkillProgress]

    # Aggregate stats
    total_level: int  # Sum of all skill levels (max 1188 = 12 skills * 99)
    max_total_level: int = 1188
    it_level: int  # Combat Level equivalent (max 126)
    max_it_level: int = 126

    # Specialization detection
    specialization: str  # "Infrastructure Specialist", "Development Specialist", etc.
    specialization_path: str  # "systems", "development", "cloud_security", "versatile"

    # Stats
    average_level: float
    total_xp: int
    skills_at_99: int
    skills_at_50_plus: int


# =============================================================================
# XP GAIN SCHEMAS
# =============================================================================

class SkillXPGainResponse(BaseModel):
    """Response after awarding skill XP"""
    skill_slug: str
    skill_name: str
    xp_gained: int
    total_xp: int
    old_level: int
    new_level: int
    level_up: bool
    new_tier: Optional[str] = None  # Only set if tier changed
    tier_changed: bool = False
    achievements_unlocked: List[str] = []  # Achievement IDs unlocked


class SkillXPLogEntry(BaseModel):
    """Single XP log entry"""
    id: int
    skill_slug: str
    skill_name: str
    xp_gained: int
    source_type: str
    source_id: Optional[str] = None
    source_metadata: Optional[Dict[str, Any]] = None
    level_before: int
    level_after: int
    level_up: bool
    earned_at: datetime

    class Config:
        from_attributes = True


class SkillXPHistory(BaseModel):
    """XP history for a skill"""
    skill_slug: str
    entries: List[SkillXPLogEntry]
    total_xp_gained: int
    total_level_ups: int


# =============================================================================
# LEADERBOARD SCHEMAS
# =============================================================================

class SkillLeaderboardEntry(BaseModel):
    """Single entry in a per-skill leaderboard"""
    rank: int
    user_id: int
    username: str
    display_name: Optional[str] = None
    avatar_url: Optional[str] = None
    skill_level: int
    skill_xp: int
    total_activities: int


class SkillLeaderboard(BaseModel):
    """Per-skill leaderboard"""
    skill_slug: str
    skill_name: str
    entries: List[SkillLeaderboardEntry]
    total_participants: int


class GlobalLeaderboardEntry(BaseModel):
    """Single entry in the global leaderboard"""
    rank: int
    user_id: int
    username: str
    display_name: Optional[str] = None
    avatar_url: Optional[str] = None
    it_level: int  # Combat Level equivalent (1-126)
    total_level: int  # Sum of all skills (max 1188)
    total_xp: int
    specialization: str  # Detected career path label
    skills_at_99: int


class GlobalLeaderboard(BaseModel):
    """Global leaderboard (by IT Level or Total Level)"""
    leaderboard_type: str  # "it_level" or "total_level"
    entries: List[GlobalLeaderboardEntry]
    total_participants: int


# =============================================================================
# PROGRESSION DATA SCHEMAS (for charts)
# =============================================================================

class ProgressionDataPoint(BaseModel):
    """Single data point for progression graph"""
    date: datetime
    xp: int
    level: int


class SkillProgression(BaseModel):
    """XP progression data for charting"""
    skill_slug: str
    skill_name: str
    current_xp: int
    current_level: int
    data_points: List[ProgressionDataPoint]
    period_days: int


# =============================================================================
# ADMIN ANALYTICS SCHEMAS
# =============================================================================

class SkillAnalytics(BaseModel):
    """Analytics for a single skill (admin)"""
    skill_slug: str
    skill_name: str
    total_users_with_progress: int
    total_xp_awarded: int
    average_level: float
    users_at_level_99: int
    level_distribution: Dict[str, int]  # {"1-9": 100, "10-29": 50, ...}
    xp_by_source: Dict[str, int]  # {"quiz": 5000, "tutorial": 3000, ...}


class SystemAnalytics(BaseModel):
    """System-wide skill analytics (admin)"""
    total_users_with_skills: int
    total_xp_awarded: int
    total_level_ups: int
    most_popular_skills: List[Dict[str, Any]]  # [{"slug": "programming", "users": 500}, ...]
    xp_by_source_type: Dict[str, int]
    recent_activity_count: int  # Last 24 hours


class RecentXPActivity(BaseModel):
    """Recent XP activity log entry (admin)"""
    user_id: int
    username: str
    skill_slug: str
    skill_name: str
    xp_gained: int
    source_type: str
    level_before: int
    level_after: int
    earned_at: datetime


# =============================================================================
# SKILL ACTIVITIES SCHEMAS (Related content for a skill)
# =============================================================================

class SkillActivityItem(BaseModel):
    """A single activity (course, quiz, tutorial, etc.) linked to a skill"""
    id: str
    title: str
    description: Optional[str] = None
    activity_type: str  # "course" | "quiz" | "tutorial" | "typing_practice"
    difficulty: Optional[str] = None
    xp_reward: int = 0
    url: str  # Frontend route, e.g. "/courses/abc123"
    estimated_time: Optional[str] = None
    category: Optional[str] = None


class SkillActivitiesResponse(BaseModel):
    """All activities linked to a skill, grouped by type"""
    skill_slug: str
    skill_name: str
    courses: List[SkillActivityItem] = []
    quizzes: List[SkillActivityItem] = []
    tutorials: List[SkillActivityItem] = []
    typing_practice: List[SkillActivityItem] = []
    total_count: int = 0


# =============================================================================
# UTILITY SCHEMAS
# =============================================================================

class TierDefinition(BaseModel):
    """Tier definition"""
    name: str
    min_level: int
    max_level: int
    color: str  # Hex color


class XPCalculatorResponse(BaseModel):
    """XP calculator response"""
    level: int
    xp_required: int
    xp_to_next_level: int
    tier: str
    tier_color: str
