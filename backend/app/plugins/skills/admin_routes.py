# backend/app/plugins/skills/admin_routes.py
"""
Skills Admin API Routes

Admin-only endpoints for skill management and analytics.
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.auth.dependencies import get_current_admin_user
from app.users.models import User

from . import crud, schemas
from .seed import seed_skills

router = APIRouter()


# =============================================================================
# SKILL MANAGEMENT
# =============================================================================

@router.get("/", response_model=List[schemas.SkillResponse])
async def admin_list_all_skills(
    include_inactive: bool = Query(False),
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Get all skills including inactive ones."""
    skills = crud.get_skills(db, active_only=not include_inactive)
    return skills


@router.post("/", response_model=schemas.SkillResponse)
async def admin_create_skill(
    skill_data: schemas.SkillCreate,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Create a new skill."""
    # Check for duplicate slug
    existing = crud.get_skill_by_slug(db, skill_data.slug)
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"Skill with slug '{skill_data.slug}' already exists"
        )

    skill = crud.create_skill(db, skill_data)
    return skill


@router.put("/{skill_id}", response_model=schemas.SkillResponse)
async def admin_update_skill(
    skill_id: int,
    skill_data: schemas.SkillUpdate,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Update a skill."""
    skill = crud.update_skill(db, skill_id, skill_data)
    if not skill:
        raise HTTPException(status_code=404, detail="Skill not found")
    return skill


@router.delete("/{skill_id}")
async def admin_delete_skill(
    skill_id: int,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Delete a skill.

    - If users have progress, skill is deactivated (soft delete)
    - If no users have progress, skill is permanently deleted
    """
    success = crud.delete_skill(db, skill_id)
    if not success:
        raise HTTPException(status_code=404, detail="Skill not found")

    return {"success": True, "message": "Skill deleted/deactivated"}


@router.post("/seed")
async def admin_seed_skills(
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Seed/reset the default 12 IT skills.

    This will:
    - Create missing skills
    - Update existing skills to match defaults
    - Skip skills that are already up to date
    """
    result = seed_skills(db)
    return {
        "success": True,
        "message": f"Seeded {result['created']} new, updated {result['updated']}, skipped {result['skipped']} of {result['total']} skills"
    }


# =============================================================================
# ANALYTICS
# =============================================================================

@router.get("/analytics/overview", response_model=schemas.SystemAnalytics)
async def admin_get_system_analytics(
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Get system-wide skill analytics."""
    analytics = crud.get_system_analytics(db)
    return schemas.SystemAnalytics(**analytics)


@router.get("/analytics/{slug}", response_model=schemas.SkillAnalytics)
async def admin_get_skill_analytics(
    slug: str,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Get analytics for a specific skill."""
    analytics = crud.get_skill_analytics(db, slug)
    if not analytics:
        raise HTTPException(status_code=404, detail="Skill not found")
    return schemas.SkillAnalytics(**analytics)


@router.get("/analytics/xp-logs/recent", response_model=List[schemas.RecentXPActivity])
async def admin_get_recent_xp_activity(
    limit: int = Query(50, ge=1, le=200),
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Get recent XP activity across all users."""
    activity = crud.get_recent_xp_activity(db, limit)
    return [schemas.RecentXPActivity(**a) for a in activity]
