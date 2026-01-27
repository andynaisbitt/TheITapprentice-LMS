# backend/app/plugins/skills/models.py
"""
Skill System Models - OSRS-style skill progression

Models:
- Skill: The 12 IT skills (Networking, Security, Programming, etc.)
- UserSkill: Per-user progress tracking for each skill
- SkillXPLog: Audit trail of all XP gains
"""
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, DateTime,
    ForeignKey, Enum as SQLEnum, JSON, UniqueConstraint
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base
import enum


class SkillCategory(str, enum.Enum):
    """Skill category - technical or soft skill"""
    technical = "technical"
    soft = "soft"


class Skill(Base):
    """
    Skill definition - one of the 12 IT skills

    Technical skills: Networking, Security, Programming, Systems Administration,
                     Cloud Computing, Databases, DevOps, Web Development, Hardware & Support
    Soft skills: Communication, Problem Solving, Project Management
    """
    __tablename__ = "skills"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False)  # e.g., "Networking"
    slug = Column(String(100), unique=True, nullable=False, index=True)  # e.g., "networking"
    description = Column(Text, nullable=True)
    icon = Column(String(10), nullable=True)  # Emoji icon, e.g., "🌐"
    category = Column(SQLEnum(SkillCategory), nullable=False, default=SkillCategory.technical)
    display_order = Column(Integer, nullable=False, default=0)
    is_active = Column(Boolean, nullable=False, default=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    user_skills = relationship("UserSkill", back_populates="skill", cascade="all, delete-orphan")
    xp_logs = relationship("SkillXPLog", back_populates="skill", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Skill {self.slug}: {self.name}>"


class UserSkill(Base):
    """
    User's progress on a specific skill

    Tracks XP, level (1-99), milestone achievements, and activity history.
    Uses OSRS XP formula for level calculation.
    """
    __tablename__ = "user_skills"
    __table_args__ = (
        UniqueConstraint("user_id", "skill_id", name="uq_user_skill"),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    skill_id = Column(Integer, ForeignKey("skills.id", ondelete="CASCADE"), nullable=False, index=True)

    # XP and Level tracking
    current_xp = Column(Integer, nullable=False, default=0, index=True)
    current_level = Column(Integer, nullable=False, default=1, index=True)  # 1-99

    # Activity stats
    total_activities_completed = Column(Integer, nullable=False, default=0)
    last_activity_at = Column(DateTime(timezone=True), nullable=True)

    # OSRS-style milestone timestamps
    level_10_achieved_at = Column(DateTime(timezone=True), nullable=True)
    level_30_achieved_at = Column(DateTime(timezone=True), nullable=True)
    level_50_achieved_at = Column(DateTime(timezone=True), nullable=True)
    level_75_achieved_at = Column(DateTime(timezone=True), nullable=True)
    level_99_achieved_at = Column(DateTime(timezone=True), nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    skill = relationship("Skill", back_populates="user_skills")

    def __repr__(self):
        return f"<UserSkill user={self.user_id} skill={self.skill_id} level={self.current_level}>"


class SkillXPLog(Base):
    """
    Audit log for skill XP gains

    Records every XP award with source information for analytics and verification.
    """
    __tablename__ = "skill_xp_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    skill_id = Column(Integer, ForeignKey("skills.id", ondelete="CASCADE"), nullable=False, index=True)

    # XP details
    xp_gained = Column(Integer, nullable=False)

    # Source tracking
    source_type = Column(String(50), nullable=False, index=True)  # quiz, tutorial, course, typing_game, achievement
    source_id = Column(String(100), nullable=True)  # ID of content that awarded XP
    source_metadata = Column(JSON, nullable=True)  # Additional context (score, difficulty, etc.)

    # Level tracking (for detecting level-ups)
    level_before = Column(Integer, nullable=False)
    level_after = Column(Integer, nullable=False)

    # Timestamp
    earned_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

    # Relationships
    skill = relationship("Skill", back_populates="xp_logs")

    @property
    def level_up(self) -> bool:
        """Check if this XP gain resulted in a level up"""
        return self.level_after > self.level_before

    def __repr__(self):
        return f"<SkillXPLog user={self.user_id} skill={self.skill_id} +{self.xp_gained}xp>"
