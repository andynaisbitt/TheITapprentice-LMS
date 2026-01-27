# backend/app/plugins/skills/crud.py
"""
Skill System CRUD Operations

Database operations for skills, user skills, and XP logs.
"""
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from .models import Skill, UserSkill, SkillXPLog
from .schemas import SkillCreate, SkillUpdate
from .service import calculate_level_from_xp, get_skill_tier, calculate_it_level


# =============================================================================
# SKILL CRUD (Admin)
# =============================================================================

def get_skill(db: Session, skill_id: int) -> Optional[Skill]:
    """Get skill by ID."""
    return db.query(Skill).filter(Skill.id == skill_id).first()


def get_skill_by_slug(db: Session, slug: str) -> Optional[Skill]:
    """Get skill by slug."""
    return db.query(Skill).filter(Skill.slug == slug).first()


def get_skills(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    active_only: bool = True
) -> List[Skill]:
    """Get all skills."""
    query = db.query(Skill)
    if active_only:
        query = query.filter(Skill.is_active == True)
    return query.order_by(Skill.display_order).offset(skip).limit(limit).all()


def create_skill(db: Session, skill_data: SkillCreate) -> Skill:
    """Create a new skill."""
    skill = Skill(**skill_data.model_dump())
    db.add(skill)
    db.commit()
    db.refresh(skill)
    return skill


def update_skill(db: Session, skill_id: int, skill_data: SkillUpdate) -> Optional[Skill]:
    """Update a skill."""
    skill = get_skill(db, skill_id)
    if not skill:
        return None

    update_data = skill_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(skill, field, value)

    db.commit()
    db.refresh(skill)
    return skill


def delete_skill(db: Session, skill_id: int) -> bool:
    """
    Delete a skill (soft delete by setting is_active=False).
    Only hard delete if no users have progress on this skill.
    """
    skill = get_skill(db, skill_id)
    if not skill:
        return False

    # Check if any users have progress
    user_skill_count = db.query(UserSkill).filter(UserSkill.skill_id == skill_id).count()

    if user_skill_count > 0:
        # Soft delete
        skill.is_active = False
        db.commit()
    else:
        # Hard delete
        db.delete(skill)
        db.commit()

    return True


# =============================================================================
# USER SKILL CRUD
# =============================================================================

def get_user_skill(db: Session, user_id: int, skill_id: int) -> Optional[UserSkill]:
    """Get user's progress on a specific skill."""
    return db.query(UserSkill).filter(
        UserSkill.user_id == user_id,
        UserSkill.skill_id == skill_id
    ).first()


def get_user_skill_by_slug(db: Session, user_id: int, skill_slug: str) -> Optional[UserSkill]:
    """Get user's progress on a skill by slug."""
    skill = get_skill_by_slug(db, skill_slug)
    if not skill:
        return None
    return get_user_skill(db, user_id, skill.id)


def get_user_skills(db: Session, user_id: int) -> List[UserSkill]:
    """Get all skill progress for a user."""
    return db.query(UserSkill).filter(UserSkill.user_id == user_id).all()


def get_or_create_user_skill(db: Session, user_id: int, skill_id: int) -> UserSkill:
    """Get or create user skill progress record."""
    user_skill = get_user_skill(db, user_id, skill_id)
    if not user_skill:
        user_skill = UserSkill(
            user_id=user_id,
            skill_id=skill_id,
            current_xp=0,
            current_level=1
        )
        db.add(user_skill)
        db.commit()
        db.refresh(user_skill)
    return user_skill


# =============================================================================
# XP LOG CRUD
# =============================================================================

def get_user_skill_xp_history(
    db: Session,
    user_id: int,
    skill_slug: str,
    limit: int = 20
) -> List[SkillXPLog]:
    """Get recent XP history for a user's skill."""
    skill = get_skill_by_slug(db, skill_slug)
    if not skill:
        return []

    return db.query(SkillXPLog).filter(
        SkillXPLog.user_id == user_id,
        SkillXPLog.skill_id == skill.id
    ).order_by(desc(SkillXPLog.earned_at)).limit(limit).all()


def get_user_all_xp_history(
    db: Session,
    user_id: int,
    limit: int = 50
) -> List[SkillXPLog]:
    """Get recent XP history across all skills for a user."""
    return db.query(SkillXPLog).filter(
        SkillXPLog.user_id == user_id
    ).order_by(desc(SkillXPLog.earned_at)).limit(limit).all()


def get_skill_progression_data(
    db: Session,
    user_id: int,
    skill_slug: str,
    days: int = 30
) -> List[Dict[str, Any]]:
    """Get XP progression data for charting."""
    skill = get_skill_by_slug(db, skill_slug)
    if not skill:
        return []

    since = datetime.now(timezone.utc) - timedelta(days=days)

    logs = db.query(SkillXPLog).filter(
        SkillXPLog.user_id == user_id,
        SkillXPLog.skill_id == skill.id,
        SkillXPLog.earned_at >= since
    ).order_by(SkillXPLog.earned_at).all()

    # Build cumulative progression
    data_points = []
    running_xp = 0

    # Get starting XP (before the period)
    user_skill = get_user_skill(db, user_id, skill.id)
    if user_skill:
        total_xp_in_period = sum(log.xp_gained for log in logs)
        running_xp = user_skill.current_xp - total_xp_in_period

    for log in logs:
        running_xp += log.xp_gained
        data_points.append({
            "date": log.earned_at,
            "xp": running_xp,
            "level": log.level_after
        })

    return data_points


# =============================================================================
# LEADERBOARD QUERIES
# =============================================================================

def get_skill_leaderboard(
    db: Session,
    skill_slug: str,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """Get leaderboard for a specific skill."""
    from app.users.models import User

    skill = get_skill_by_slug(db, skill_slug)
    if not skill:
        return []

    results = db.query(
        UserSkill.user_id,
        UserSkill.current_level,
        UserSkill.current_xp,
        UserSkill.total_activities_completed,
        User.username,
        User.first_name,
        User.last_name,
        User.avatar_url
    ).join(User, User.id == UserSkill.user_id).filter(
        UserSkill.skill_id == skill.id,
        User.is_active == True
    ).order_by(
        desc(UserSkill.current_xp)
    ).limit(limit).all()

    return [
        {
            "rank": idx + 1,
            "user_id": r.user_id,
            "username": r.username,
            "display_name": f"{r.first_name} {r.last_name}".strip() if r.first_name and r.last_name else r.username,
            "avatar_url": r.avatar_url,
            "skill_level": r.current_level,
            "skill_xp": r.current_xp,
            "total_activities": r.total_activities_completed
        }
        for idx, r in enumerate(results)
    ]


def get_global_leaderboard(
    db: Session,
    leaderboard_type: str = "it_level",  # "it_level" or "total_level"
    limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Get global leaderboard.

    - "it_level": Ranked by IT Level (Combat Level equivalent)
    - "total_level": Ranked by sum of all skill levels
    """
    from app.users.models import User
    from .service import get_specialization

    # Get all users with any skill progress
    user_skills = db.query(
        UserSkill.user_id,
        func.sum(UserSkill.current_level).label("total_level"),
        func.sum(UserSkill.current_xp).label("total_xp"),
        func.count(func.nullif(UserSkill.current_level >= 99, False)).label("skills_at_99")
    ).group_by(UserSkill.user_id).all()

    # Build user data with IT Level calculation
    user_data = []
    for us in user_skills:
        # Get individual skill levels for IT Level calculation
        skill_levels = {}
        user_skill_records = db.query(
            UserSkill.current_level,
            Skill.slug
        ).join(Skill).filter(UserSkill.user_id == us.user_id).all()

        for record in user_skill_records:
            skill_levels[record.slug] = record.current_level

        it_level = calculate_it_level(skill_levels)
        _, specialization = get_specialization(skill_levels)

        user = db.query(User).filter(User.id == us.user_id, User.is_active == True).first()
        if user:
            user_data.append({
                "user_id": us.user_id,
                "username": user.username,
                "display_name": user.display_name,
                "avatar_url": user.avatar_url,
                "it_level": it_level,
                "total_level": us.total_level,
                "total_xp": us.total_xp,
                "specialization": specialization,
                "skills_at_99": us.skills_at_99 or 0
            })

    # Sort by requested type
    if leaderboard_type == "it_level":
        user_data.sort(key=lambda x: (x["it_level"], x["total_xp"]), reverse=True)
    else:  # total_level
        user_data.sort(key=lambda x: (x["total_level"], x["total_xp"]), reverse=True)

    # Add ranks and limit
    return [
        {**data, "rank": idx + 1}
        for idx, data in enumerate(user_data[:limit])
    ]


# =============================================================================
# ANALYTICS QUERIES (Admin)
# =============================================================================

def get_system_analytics(db: Session) -> Dict[str, Any]:
    """Get system-wide skill analytics."""
    # Total users with any skill progress
    total_users = db.query(func.count(func.distinct(UserSkill.user_id))).scalar() or 0

    # Total XP awarded
    total_xp = db.query(func.sum(SkillXPLog.xp_gained)).scalar() or 0

    # Total level ups
    total_level_ups = db.query(SkillXPLog).filter(
        SkillXPLog.level_after > SkillXPLog.level_before
    ).count()

    # XP by source type
    xp_by_source = db.query(
        SkillXPLog.source_type,
        func.sum(SkillXPLog.xp_gained).label("total_xp")
    ).group_by(SkillXPLog.source_type).all()

    # Most popular skills (by user count)
    popular_skills = db.query(
        Skill.slug,
        Skill.name,
        func.count(UserSkill.id).label("user_count")
    ).join(UserSkill).group_by(Skill.id).order_by(
        desc("user_count")
    ).limit(10).all()

    # Recent activity (last 24 hours)
    yesterday = datetime.now(timezone.utc) - timedelta(hours=24)
    recent_count = db.query(SkillXPLog).filter(
        SkillXPLog.earned_at >= yesterday
    ).count()

    return {
        "total_users_with_skills": total_users,
        "total_xp_awarded": total_xp,
        "total_level_ups": total_level_ups,
        "xp_by_source_type": {r.source_type: r.total_xp for r in xp_by_source},
        "most_popular_skills": [
            {"slug": r.slug, "name": r.name, "users": r.user_count}
            for r in popular_skills
        ],
        "recent_activity_count": recent_count
    }


def get_skill_analytics(db: Session, skill_slug: str) -> Optional[Dict[str, Any]]:
    """Get analytics for a specific skill."""
    skill = get_skill_by_slug(db, skill_slug)
    if not skill:
        return None

    # User count
    user_count = db.query(UserSkill).filter(UserSkill.skill_id == skill.id).count()

    # Total XP awarded
    total_xp = db.query(func.sum(SkillXPLog.xp_gained)).filter(
        SkillXPLog.skill_id == skill.id
    ).scalar() or 0

    # Average level
    avg_level = db.query(func.avg(UserSkill.current_level)).filter(
        UserSkill.skill_id == skill.id
    ).scalar() or 1

    # Users at level 99
    at_99 = db.query(UserSkill).filter(
        UserSkill.skill_id == skill.id,
        UserSkill.current_level >= 99
    ).count()

    # Level distribution
    level_distribution = {
        "1-9": 0, "10-29": 0, "30-49": 0,
        "50-69": 0, "70-89": 0, "90-99": 0
    }

    user_skills = db.query(UserSkill.current_level).filter(
        UserSkill.skill_id == skill.id
    ).all()

    for (level,) in user_skills:
        if level < 10:
            level_distribution["1-9"] += 1
        elif level < 30:
            level_distribution["10-29"] += 1
        elif level < 50:
            level_distribution["30-49"] += 1
        elif level < 70:
            level_distribution["50-69"] += 1
        elif level < 90:
            level_distribution["70-89"] += 1
        else:
            level_distribution["90-99"] += 1

    # XP by source
    xp_by_source = db.query(
        SkillXPLog.source_type,
        func.sum(SkillXPLog.xp_gained).label("total_xp")
    ).filter(SkillXPLog.skill_id == skill.id).group_by(
        SkillXPLog.source_type
    ).all()

    return {
        "skill_slug": skill.slug,
        "skill_name": skill.name,
        "total_users_with_progress": user_count,
        "total_xp_awarded": total_xp,
        "average_level": round(avg_level, 1),
        "users_at_level_99": at_99,
        "level_distribution": level_distribution,
        "xp_by_source": {r.source_type: r.total_xp for r in xp_by_source}
    }


def get_recent_xp_activity(db: Session, limit: int = 50) -> List[Dict[str, Any]]:
    """Get recent XP activity across all users (admin)."""
    from app.users.models import User

    logs = db.query(
        SkillXPLog,
        User.username,
        Skill.slug,
        Skill.name
    ).join(User, User.id == SkillXPLog.user_id).join(
        Skill, Skill.id == SkillXPLog.skill_id
    ).order_by(desc(SkillXPLog.earned_at)).limit(limit).all()

    return [
        {
            "user_id": log.SkillXPLog.user_id,
            "username": log.username,
            "skill_slug": log.slug,
            "skill_name": log.name,
            "xp_gained": log.SkillXPLog.xp_gained,
            "source_type": log.SkillXPLog.source_type,
            "level_before": log.SkillXPLog.level_before,
            "level_after": log.SkillXPLog.level_after,
            "earned_at": log.SkillXPLog.earned_at
        }
        for log in logs
    ]
