# backend/app/plugins/skills/service.py
"""
Skill System Service - Core XP and Level Logic

Implements OSRS-style XP formula with:
- Exponential XP curve to level 99
- 6-tier progression system
- IT Level (Combat Level equivalent) calculation
- Specialization path detection
"""
import math
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
from sqlalchemy.orm import Session
import logging

from .models import Skill, UserSkill, SkillXPLog
from .schemas import SkillXPGainResponse, UserSkillProgress, UserSkillsOverview

logger = logging.getLogger(__name__)


# =============================================================================
# CONSTANTS
# =============================================================================

# Tier definitions (OSRS-style)
TIERS = [
    {"name": "Novice", "min_level": 1, "max_level": 9, "color": "#9CA3AF"},      # Gray
    {"name": "Apprentice", "min_level": 10, "max_level": 29, "color": "#10B981"},  # Green
    {"name": "Journeyman", "min_level": 30, "max_level": 49, "color": "#3B82F6"},  # Blue
    {"name": "Expert", "min_level": 50, "max_level": 69, "color": "#A855F7"},     # Purple
    {"name": "Master", "min_level": 70, "max_level": 89, "color": "#F59E0B"},     # Gold
    {"name": "Grandmaster", "min_level": 90, "max_level": 99, "color": "#06B6D4"}, # Cyan
]

# Skill path definitions for IT Level calculation
FOUNDATION_SKILLS = ["problem-solving", "communication", "project-management"]
SYSTEMS_PATH = ["networking", "systems-administration", "hardware-support"]
DEVELOPMENT_PATH = ["programming", "web-development", "databases"]
CLOUD_SECURITY_PATH = ["cloud-computing", "devops", "security"]

# Category to skills mapping (for automatic XP distribution)
CATEGORY_TO_SKILLS_MAP = {
    "networking": ["networking", "problem-solving"],
    "security": ["security", "problem-solving"],
    "cybersecurity": ["security", "problem-solving"],
    "python": ["programming", "problem-solving"],
    "programming": ["programming", "problem-solving"],
    "javascript": ["programming", "web-development"],
    "web-development": ["web-development", "programming"],
    "web": ["web-development", "programming"],
    "cloud": ["cloud-computing", "systems-administration"],
    "aws": ["cloud-computing", "devops"],
    "azure": ["cloud-computing", "devops"],
    "devops": ["devops", "cloud-computing"],
    "docker": ["devops", "systems-administration"],
    "kubernetes": ["devops", "cloud-computing"],
    "linux": ["systems-administration", "problem-solving"],
    "windows": ["systems-administration", "problem-solving"],
    "database": ["databases", "programming"],
    "sql": ["databases", "programming"],
    "hardware": ["hardware-support", "problem-solving"],
    "support": ["hardware-support", "communication"],
    "project-management": ["project-management", "communication"],
    "agile": ["project-management", "communication"],
    "communication": ["communication"],
    "soft-skills": ["communication", "problem-solving"],
}


# =============================================================================
# XP FORMULA (OSRS-style)
# =============================================================================

def calculate_xp_for_level(level: int) -> int:
    """
    Calculate total XP required to reach a given level (1-99).
    Uses OSRS formula: sum of (lvl + 300 * 2^(lvl/7)) / 4 for all levels up to target.

    Key milestones:
    - Level 10: 1,154 XP
    - Level 50: 101,333 XP
    - Level 99: 13,034,431 XP
    """
    if level <= 1:
        return 0

    total = 0
    for lvl in range(1, level):
        total += int(lvl + 300 * (2 ** (lvl / 7)))
    return total // 4


def calculate_level_from_xp(xp: int) -> int:
    """
    Calculate level from total XP.
    Returns level 1-99.
    """
    if xp <= 0:
        return 1

    for level in range(99, 0, -1):
        if xp >= calculate_xp_for_level(level):
            return level

    return 1


def calculate_xp_to_next_level(current_xp: int, current_level: int) -> int:
    """Calculate XP remaining to reach the next level."""
    if current_level >= 99:
        return 0

    xp_for_next = calculate_xp_for_level(current_level + 1)
    return max(0, xp_for_next - current_xp)


def calculate_xp_progress_percentage(current_xp: int, current_level: int) -> float:
    """Calculate progress percentage towards next level (0-100)."""
    if current_level >= 99:
        return 100.0

    xp_for_current = calculate_xp_for_level(current_level)
    xp_for_next = calculate_xp_for_level(current_level + 1)

    xp_in_level = current_xp - xp_for_current
    xp_needed = xp_for_next - xp_for_current

    if xp_needed <= 0:
        return 100.0

    return min(100.0, (xp_in_level / xp_needed) * 100)


# =============================================================================
# TIER SYSTEM
# =============================================================================

def get_skill_tier(level: int) -> Tuple[str, str]:
    """
    Get tier name and color for a given level.
    Returns (tier_name, tier_color_hex).
    """
    for tier in TIERS:
        if tier["min_level"] <= level <= tier["max_level"]:
            return tier["name"], tier["color"]

    # Fallback to highest tier if somehow above 99
    return TIERS[-1]["name"], TIERS[-1]["color"]


def get_all_tiers() -> List[Dict[str, Any]]:
    """Get all tier definitions."""
    return TIERS.copy()


# =============================================================================
# IT LEVEL (Combat Level equivalent)
# =============================================================================

def calculate_it_level(skill_levels: Dict[str, int]) -> int:
    """
    Calculate IT Level (1-126) from individual skill levels.
    Mirrors OSRS Combat Level formula structure.

    Formula:
    - Base = 0.25 * (Problem Solving + Communication + floor(Project Management / 2))
    - Systems Path = 0.325 * (Networking + SysAdmin + Hardware) / 1.5
    - Development Path = 0.325 * (Programming + Web Dev + Databases) / 1.5
    - Cloud/Security Path = 0.325 * (Cloud + DevOps + Security) / 1.5
    - IT Level = floor(Base + max(Systems, Development, Cloud/Security))
    """
    # Default all skills to 1 if not present
    def get_level(slug: str) -> int:
        return skill_levels.get(slug, 1)

    # Foundation (always contributes)
    base = 0.25 * (
        get_level("problem-solving")
        + get_level("communication")
        + math.floor(get_level("project-management") / 2)
    )

    # Specialization paths (only highest counts)
    systems = 0.325 * (
        get_level("networking")
        + get_level("systems-administration")
        + get_level("hardware-support")
    ) / 1.5

    development = 0.325 * (
        get_level("programming")
        + get_level("web-development")
        + get_level("databases")
    ) / 1.5

    cloud_security = 0.325 * (
        get_level("cloud-computing")
        + get_level("devops")
        + get_level("security")
    ) / 1.5

    return math.floor(base + max(systems, development, cloud_security))


def get_specialization(skill_levels: Dict[str, int]) -> Tuple[str, str]:
    """
    Detect user's specialization based on which path contributes most to IT Level.

    Returns: (path_key, display_label)
    """
    def get_level(slug: str) -> int:
        return skill_levels.get(slug, 1)

    # Calculate path scores
    systems = sum(get_level(s) for s in SYSTEMS_PATH)
    development = sum(get_level(s) for s in DEVELOPMENT_PATH)
    cloud_security = sum(get_level(s) for s in CLOUD_SECURITY_PATH)

    max_score = max(systems, development, cloud_security)

    # Check if paths are tied (within 5%)
    threshold = max_score * 0.95
    tied_count = sum([
        systems >= threshold,
        development >= threshold,
        cloud_security >= threshold
    ])

    if tied_count >= 2:
        return "versatile", "Versatile IT Professional"

    if systems == max_score:
        return "systems", "Infrastructure Specialist"
    elif development == max_score:
        return "development", "Development Specialist"
    else:
        return "cloud_security", "Cloud & Security Specialist"


# =============================================================================
# TYPING GAME XP CALCULATION
# =============================================================================

def calculate_typing_skill_xp(wpm: float, accuracy: float) -> int:
    """
    Calculate skill XP from typing game performance.

    Base: 10 XP per game
    WPM bonuses: +10 at 40+, +20 at 60+, +30 at 80+, +50 at 100+
    Accuracy bonuses: +10 at 90%+, +20 at 95%+, +30 at 100%
    """
    base_xp = 10

    # WPM bonuses
    if wpm >= 100:
        base_xp += 50
    elif wpm >= 80:
        base_xp += 30
    elif wpm >= 60:
        base_xp += 20
    elif wpm >= 40:
        base_xp += 10

    # Accuracy bonuses
    if accuracy >= 100:
        base_xp += 30
    elif accuracy >= 95:
        base_xp += 20
    elif accuracy >= 90:
        base_xp += 10

    return base_xp


# =============================================================================
# CORE XP AWARD FUNCTION
# =============================================================================

async def award_skill_xp(
    db: Session,
    user_id: int,
    skill_slug: str,
    xp_amount: int,
    source_type: str,
    source_id: Optional[str] = None,
    source_metadata: Optional[Dict[str, Any]] = None
) -> SkillXPGainResponse:
    """
    Award XP to a user for a specific skill.

    Args:
        db: Database session
        user_id: User ID
        skill_slug: Skill slug (e.g., "networking")
        xp_amount: Amount of XP to award
        source_type: What triggered this (quiz, tutorial, course, typing_game, achievement)
        source_id: Optional ID of the content
        source_metadata: Optional additional context

    Returns:
        SkillXPGainResponse with level up info
    """
    from app.core.config import settings

    # Check if skills plugin is enabled
    if not settings.PLUGINS_ENABLED.get("skills", False):
        logger.debug("Skills plugin disabled, skipping XP award")
        return SkillXPGainResponse(
            skill_slug=skill_slug,
            skill_name=skill_slug,
            xp_gained=0,
            total_xp=0,
            old_level=1,
            new_level=1,
            level_up=False
        )

    # Get skill
    skill = db.query(Skill).filter(Skill.slug == skill_slug, Skill.is_active == True).first()
    if not skill:
        logger.warning(f"Skill not found: {skill_slug}")
        return SkillXPGainResponse(
            skill_slug=skill_slug,
            skill_name=skill_slug,
            xp_gained=0,
            total_xp=0,
            old_level=1,
            new_level=1,
            level_up=False
        )

    # Get or create user skill
    user_skill = db.query(UserSkill).filter(
        UserSkill.user_id == user_id,
        UserSkill.skill_id == skill.id
    ).first()

    if not user_skill:
        user_skill = UserSkill(
            user_id=user_id,
            skill_id=skill.id,
            current_xp=0,
            current_level=1
        )
        db.add(user_skill)
        db.flush()

    # Store old values
    old_level = user_skill.current_level
    old_tier, _ = get_skill_tier(old_level)

    # Award XP
    user_skill.current_xp += xp_amount
    new_level = calculate_level_from_xp(user_skill.current_xp)
    user_skill.current_level = new_level
    user_skill.total_activities_completed += 1
    user_skill.last_activity_at = datetime.now(timezone.utc)

    # Check for milestone achievements
    now = datetime.now(timezone.utc)
    if new_level >= 10 and not user_skill.level_10_achieved_at:
        user_skill.level_10_achieved_at = now
    if new_level >= 30 and not user_skill.level_30_achieved_at:
        user_skill.level_30_achieved_at = now
    if new_level >= 50 and not user_skill.level_50_achieved_at:
        user_skill.level_50_achieved_at = now
    if new_level >= 75 and not user_skill.level_75_achieved_at:
        user_skill.level_75_achieved_at = now
    if new_level >= 99 and not user_skill.level_99_achieved_at:
        user_skill.level_99_achieved_at = now

    # Create XP log entry
    xp_log = SkillXPLog(
        user_id=user_id,
        skill_id=skill.id,
        xp_gained=xp_amount,
        source_type=source_type,
        source_id=source_id,
        source_metadata=source_metadata,
        level_before=old_level,
        level_after=new_level
    )
    db.add(xp_log)

    db.commit()

    # Check tier change
    new_tier, new_tier_color = get_skill_tier(new_level)
    tier_changed = new_tier != old_tier

    level_up = new_level > old_level

    if level_up:
        logger.info(
            f"User {user_id} leveled up {skill.name}: {old_level} -> {new_level}"
            + (f" (New tier: {new_tier})" if tier_changed else "")
        )

    # TODO: Check for skill achievements
    achievements_unlocked = []

    return SkillXPGainResponse(
        skill_slug=skill.slug,
        skill_name=skill.name,
        xp_gained=xp_amount,
        total_xp=user_skill.current_xp,
        old_level=old_level,
        new_level=new_level,
        level_up=level_up,
        new_tier=new_tier if tier_changed else None,
        tier_changed=tier_changed,
        achievements_unlocked=achievements_unlocked
    )


# =============================================================================
# USER SKILLS OVERVIEW
# =============================================================================

def get_user_skills_overview(db: Session, user_id: int) -> UserSkillsOverview:
    """
    Get complete skills overview for a user.
    Returns all 12 skills with progress, plus aggregate stats.
    """
    # Get all active skills
    skills = db.query(Skill).filter(Skill.is_active == True).order_by(Skill.display_order).all()

    # Get user's skill progress
    user_skills = db.query(UserSkill).filter(UserSkill.user_id == user_id).all()
    user_skill_map = {us.skill_id: us for us in user_skills}

    # Build skill progress list
    skill_progress_list = []
    skill_levels = {}
    total_xp = 0

    for skill in skills:
        user_skill = user_skill_map.get(skill.id)

        if user_skill:
            current_xp = user_skill.current_xp
            current_level = user_skill.current_level
            total_activities = user_skill.total_activities_completed
            last_activity = user_skill.last_activity_at
        else:
            current_xp = 0
            current_level = 1
            total_activities = 0
            last_activity = None

        tier, tier_color = get_skill_tier(current_level)
        xp_to_next = calculate_xp_to_next_level(current_xp, current_level)
        xp_for_next = calculate_xp_for_level(current_level + 1) if current_level < 99 else current_xp
        progress_pct = calculate_xp_progress_percentage(current_xp, current_level)

        skill_levels[skill.slug] = current_level
        total_xp += current_xp

        skill_progress_list.append(UserSkillProgress(
            skill_id=skill.id,
            skill_name=skill.name,
            skill_slug=skill.slug,
            skill_icon=skill.icon,
            skill_category=skill.category.value if hasattr(skill.category, 'value') else str(skill.category),
            current_xp=current_xp,
            current_level=current_level,
            xp_to_next_level=xp_to_next,
            xp_for_next_level=xp_for_next,
            xp_progress_percentage=round(progress_pct, 1),
            total_activities_completed=total_activities,
            last_activity_at=last_activity,
            tier=tier,
            tier_color=tier_color,
            level_10_achieved=user_skill.level_10_achieved_at is not None if user_skill else False,
            level_30_achieved=user_skill.level_30_achieved_at is not None if user_skill else False,
            level_50_achieved=user_skill.level_50_achieved_at is not None if user_skill else False,
            level_75_achieved=user_skill.level_75_achieved_at is not None if user_skill else False,
            level_99_achieved=user_skill.level_99_achieved_at is not None if user_skill else False,
        ))

    # Calculate aggregates
    total_level = sum(skill_levels.values())
    it_level = calculate_it_level(skill_levels)
    specialization_path, specialization = get_specialization(skill_levels)
    skills_at_99 = sum(1 for lvl in skill_levels.values() if lvl >= 99)
    skills_at_50_plus = sum(1 for lvl in skill_levels.values() if lvl >= 50)
    average_level = total_level / len(skills) if skills else 1

    return UserSkillsOverview(
        skills=skill_progress_list,
        total_level=total_level,
        max_total_level=1188,
        it_level=it_level,
        max_it_level=126,
        specialization=specialization,
        specialization_path=specialization_path,
        average_level=round(average_level, 1),
        total_xp=total_xp,
        skills_at_99=skills_at_99,
        skills_at_50_plus=skills_at_50_plus,
    )
