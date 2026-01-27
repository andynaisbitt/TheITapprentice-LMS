# backend/app/plugins/skills/routes.py
"""
Skills API Routes - Public and Protected Endpoints

Public endpoints for skill info, protected endpoints for user progress.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.auth.dependencies import get_current_user, get_optional_user
from app.users.models import User

from . import crud, schemas
from .service import (
    get_user_skills_overview,
    get_skill_tier,
    get_all_tiers,
    calculate_xp_for_level,
    calculate_xp_to_next_level,
    calculate_xp_progress_percentage
)

router = APIRouter()


# =============================================================================
# PUBLIC ENDPOINTS (No auth required)
# =============================================================================

@router.get("/", response_model=List[schemas.SkillResponse])
async def list_skills(
    db: Session = Depends(get_db)
):
    """Get all active skills."""
    skills = crud.get_skills(db, active_only=True)
    return skills


@router.get("/utils/tiers", response_model=List[schemas.TierDefinition])
async def get_tier_definitions():
    """Get tier definitions (Novice, Apprentice, etc.)."""
    return get_all_tiers()


@router.get("/utils/xp-calculator", response_model=schemas.XPCalculatorResponse)
async def xp_calculator(
    level: int = Query(..., ge=1, le=99, description="Target level")
):
    """Calculate XP requirements for a given level."""
    xp_required = calculate_xp_for_level(level)
    xp_to_next = calculate_xp_for_level(level + 1) - xp_required if level < 99 else 0
    tier, tier_color = get_skill_tier(level)

    return schemas.XPCalculatorResponse(
        level=level,
        xp_required=xp_required,
        xp_to_next_level=xp_to_next,
        tier=tier,
        tier_color=tier_color
    )


@router.get("/slug/{slug}", response_model=schemas.SkillResponse)
async def get_skill_by_slug(
    slug: str,
    db: Session = Depends(get_db)
):
    """Get skill by slug."""
    skill = crud.get_skill_by_slug(db, slug)
    if not skill:
        raise HTTPException(status_code=404, detail="Skill not found")
    return skill


@router.get("/{skill_id}", response_model=schemas.SkillResponse)
async def get_skill(
    skill_id: int,
    db: Session = Depends(get_db)
):
    """Get skill by ID."""
    skill = crud.get_skill(db, skill_id)
    if not skill:
        raise HTTPException(status_code=404, detail="Skill not found")
    return skill


# =============================================================================
# PROTECTED ENDPOINTS (Auth required)
# =============================================================================

@router.get("/me/overview", response_model=schemas.UserSkillsOverview)
async def get_my_skills_overview(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get current user's complete skills overview."""
    return get_user_skills_overview(db, current_user.id)


@router.get("/me/{slug}", response_model=schemas.UserSkillProgress)
async def get_my_skill_progress(
    slug: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get current user's progress on a specific skill."""
    skill = crud.get_skill_by_slug(db, slug)
    if not skill:
        raise HTTPException(status_code=404, detail="Skill not found")

    user_skill = crud.get_user_skill(db, current_user.id, skill.id)

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

    return schemas.UserSkillProgress(
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
    )


@router.get("/me/{slug}/history", response_model=schemas.SkillXPHistory)
async def get_my_skill_history(
    slug: str,
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get XP history for a skill."""
    skill = crud.get_skill_by_slug(db, slug)
    if not skill:
        raise HTTPException(status_code=404, detail="Skill not found")

    logs = crud.get_user_skill_xp_history(db, current_user.id, slug, limit)

    entries = [
        schemas.SkillXPLogEntry(
            id=log.id,
            skill_slug=skill.slug,
            skill_name=skill.name,
            xp_gained=log.xp_gained,
            source_type=log.source_type,
            source_id=log.source_id,
            source_metadata=log.source_metadata,
            level_before=log.level_before,
            level_after=log.level_after,
            level_up=log.level_after > log.level_before,
            earned_at=log.earned_at
        )
        for log in logs
    ]

    total_xp = sum(e.xp_gained for e in entries)
    total_level_ups = sum(1 for e in entries if e.level_up)

    return schemas.SkillXPHistory(
        skill_slug=slug,
        entries=entries,
        total_xp_gained=total_xp,
        total_level_ups=total_level_ups
    )


@router.get("/me/{slug}/progression", response_model=schemas.SkillProgression)
async def get_my_skill_progression(
    slug: str,
    days: int = Query(30, ge=7, le=365),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get XP progression data for charting."""
    skill = crud.get_skill_by_slug(db, slug)
    if not skill:
        raise HTTPException(status_code=404, detail="Skill not found")

    data_points = crud.get_skill_progression_data(db, current_user.id, slug, days)
    user_skill = crud.get_user_skill(db, current_user.id, skill.id)

    return schemas.SkillProgression(
        skill_slug=slug,
        skill_name=skill.name,
        current_xp=user_skill.current_xp if user_skill else 0,
        current_level=user_skill.current_level if user_skill else 1,
        data_points=[
            schemas.ProgressionDataPoint(
                date=dp["date"],
                xp=dp["xp"],
                level=dp["level"]
            )
            for dp in data_points
        ],
        period_days=days
    )


# =============================================================================
# LEADERBOARD ENDPOINTS
# =============================================================================

@router.get("/leaderboards/global", response_model=schemas.GlobalLeaderboard)
async def get_global_leaderboard(
    leaderboard_type: str = Query("it_level", regex="^(it_level|total_level)$"),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db)
):
    """
    Get global leaderboard.

    - it_level: Ranked by IT Level (Combat Level equivalent, max 126)
    - total_level: Ranked by sum of all skill levels (max 1188)
    """
    entries = crud.get_global_leaderboard(db, leaderboard_type, limit)

    return schemas.GlobalLeaderboard(
        leaderboard_type=leaderboard_type,
        entries=[
            schemas.GlobalLeaderboardEntry(**entry)
            for entry in entries
        ],
        total_participants=len(entries)
    )


@router.get("/{slug}/leaderboard", response_model=schemas.SkillLeaderboard)
async def get_skill_leaderboard(
    slug: str,
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db)
):
    """Get leaderboard for a specific skill."""
    skill = crud.get_skill_by_slug(db, slug)
    if not skill:
        raise HTTPException(status_code=404, detail="Skill not found")

    entries = crud.get_skill_leaderboard(db, slug, limit)

    return schemas.SkillLeaderboard(
        skill_slug=slug,
        skill_name=skill.name,
        entries=[
            schemas.SkillLeaderboardEntry(**entry)
            for entry in entries
        ],
        total_participants=len(entries)
    )
