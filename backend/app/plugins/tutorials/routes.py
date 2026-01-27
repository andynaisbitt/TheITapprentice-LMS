# backend/app/plugins/tutorials/routes.py
"""
Tutorial API routes for FastReactCMS LMS Edition
Public and admin endpoints for tutorials
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional
import logging

from app.core.database import get_db
from app.auth.dependencies import (
    get_current_user,
    get_optional_user,
    require_admin,
    require_author_or_admin
)
from app.users.models import User

from . import crud, schemas
from .models import Tutorial, TutorialProgress
from app.plugins.shared.xp_service import xp_service
from app.plugins.shared.achievement_service import achievement_service
from app.plugins.shared.models import ActivityType, ChallengeType
from app.plugins.shared.challenge_service import challenge_service
from app.plugins.skills.service import award_skill_xp, CATEGORY_TO_SKILLS_MAP
from app.core.config import settings

logger = logging.getLogger(__name__)

# Create router
router = APIRouter()


# ============================================================================
# PUBLIC ROUTES - Tutorial Browsing/Viewing
# ============================================================================

@router.get("/categories", response_model=List[schemas.TutorialCategoryResponse])
async def get_tutorial_categories(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Get all tutorial categories"""
    categories = crud.get_tutorial_categories(db, skip=skip, limit=limit)
    return categories


@router.get("", response_model=List[schemas.TutorialListResponse])
async def get_tutorials(
    category_id: Optional[int] = None,
    difficulty: Optional[str] = None,
    search: Optional[str] = None,
    is_featured: Optional[bool] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    current_user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db)
):
    """
    Get all published tutorials with optional filtering

    - **category_id**: Filter by category
    - **difficulty**: beginner, intermediate, or advanced
    - **search**: Search in title and description
    - **is_featured**: Filter featured tutorials
    """
    tutorials = crud.get_tutorials(
        db,
        category_id=category_id,
        difficulty=difficulty,
        is_published=True,  # Only show published tutorials to public
        is_featured=is_featured,
        search=search,
        skip=skip,
        limit=limit
    )

    # Enrich with user progress if authenticated
    result = []
    for tutorial in tutorials:
        tutorial_dict = schemas.TutorialListResponse.from_orm(tutorial).model_dump()

        if current_user:
            progress = crud.get_tutorial_progress(db, current_user.id, tutorial.id)
            if progress:
                total_steps = len(tutorial.steps)
                completed_steps = len(progress.completed_step_ids)
                tutorial_dict["user_progress_percentage"] = int((completed_steps / total_steps * 100)) if total_steps > 0 else 0
                tutorial_dict["user_completed"] = progress.status == "completed"

        result.append(schemas.TutorialListResponse(**tutorial_dict))

    return result


@router.get("/featured", response_model=List[schemas.TutorialListResponse])
async def get_featured_tutorials(
    limit: int = Query(5, ge=1, le=10),
    current_user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db)
):
    """Get featured tutorials"""
    tutorials = crud.get_featured_tutorials(db, limit=limit)
    return tutorials


@router.get("/popular", response_model=List[schemas.TutorialListResponse])
async def get_popular_tutorials(
    limit: int = Query(10, ge=1, le=20),
    db: Session = Depends(get_db)
):
    """Get most popular tutorials by view count"""
    tutorials = crud.get_popular_tutorials(db, limit=limit)
    return tutorials


@router.get("/{slug}", response_model=schemas.TutorialDetailResponse)
async def get_tutorial_by_slug(
    slug: str,
    current_user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db)
):
    """
    Get tutorial by slug with all steps
    Increments view count
    """
    tutorial = crud.get_tutorial_by_slug(db, slug)
    if not tutorial:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tutorial not found"
        )

    # Only show published tutorials to non-admins
    if not tutorial.is_published:
        if not current_user or not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tutorial not found"
            )

    # Increment view count
    crud.increment_tutorial_views(db, tutorial.id)

    # Enrich with user progress if authenticated
    tutorial_dict = schemas.TutorialDetailResponse.from_orm(tutorial).model_dump()

    if current_user:
        progress = crud.get_tutorial_progress(db, current_user.id, tutorial.id)
        if progress:
            total_steps = len(tutorial.steps)
            completed_steps = len(progress.completed_step_ids)
            tutorial_dict["user_progress"] = {
                "current_step_id": progress.current_step_id,
                "completed_step_ids": progress.completed_step_ids,
                "progress_percentage": int((completed_steps / total_steps * 100)) if total_steps > 0 else 0,
                "status": progress.status,
                "time_spent_minutes": progress.time_spent_minutes
            }

    return schemas.TutorialDetailResponse(**tutorial_dict)


# ============================================================================
# USER PROGRESS ROUTES - Authenticated Users Only
# ============================================================================

@router.post("/{tutorial_id}/start", response_model=schemas.TutorialProgressResponse)
async def start_tutorial(
    tutorial_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Start a tutorial (or return existing progress)"""
    # Verify tutorial exists
    tutorial = crud.get_tutorial(db, tutorial_id)
    if not tutorial:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tutorial not found"
        )

    if not tutorial.is_published:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tutorial is not published"
        )

    # Start or resume tutorial
    progress = crud.start_tutorial(db, current_user.id, tutorial_id)

    # Add computed fields
    progress_dict = schemas.TutorialProgressResponse.from_orm(progress).model_dump()
    total_steps = len(tutorial.steps)
    completed_steps = len(progress.completed_step_ids)
    progress_dict["progress_percentage"] = int((completed_steps / total_steps * 100)) if total_steps > 0 else 0
    progress_dict["total_steps"] = total_steps

    return schemas.TutorialProgressResponse(**progress_dict)


@router.post("/{tutorial_id}/steps/{step_id}/complete", response_model=schemas.CompleteStepResponse)
async def complete_tutorial_step(
    tutorial_id: int,
    step_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Mark a tutorial step as complete"""
    # Verify tutorial and step exist
    tutorial = crud.get_tutorial(db, tutorial_id)
    if not tutorial:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tutorial not found"
        )

    step = crud.get_tutorial_step(db, step_id)
    if not step or step.tutorial_id != tutorial_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tutorial step not found"
        )

    # Check if step was already completed (to avoid double XP)
    existing_progress = crud.get_tutorial_progress(db, current_user.id, tutorial_id)
    step_already_completed = existing_progress and step_id in existing_progress.completed_step_ids

    # Complete the step
    progress = crud.complete_tutorial_step(db, current_user.id, tutorial_id, step_id)

    # Calculate progress percentage
    total_steps = len(tutorial.steps)
    completed_steps = len(progress.completed_step_ids)
    progress_percentage = int((completed_steps / total_steps * 100)) if total_steps > 0 else 0

    # Track total XP awarded this request
    xp_awarded = 0

    # Award per-step XP if step wasn't already completed
    if not step_already_completed:
        step_xp_result = xp_service.award_xp(
            db=db,
            user_id=current_user.id,
            action="tutorial_step_complete",
            reason=f"Completed step: {step.title}"
        )
        xp_awarded += step_xp_result.get("xp_awarded", 0)

        # Log step completion activity
        achievement_service.log_activity(
            db=db,
            user_id=current_user.id,
            activity_type=ActivityType.TUTORIAL_STEP,
            title=f"Completed step: {step.title}",
            reference_type="tutorial_step",
            reference_id=str(step_id),
            activity_data={
                "tutorial_id": tutorial_id,
                "tutorial_title": tutorial.title,
                "step_order": step.step_order,
                "progress_percentage": progress_percentage
            },
            xp_earned=step_xp_result.get("xp_awarded", 0)
        )

        logger.info(f"User {current_user.id} completed step {step_id}, awarded {step_xp_result.get('xp_awarded', 0)} XP")

        # Track challenge progress for tutorial step
        challenge_service.increment_progress(
            db=db,
            user_id=current_user.id,
            challenge_type=ChallengeType.TUTORIAL,
            amount=1
        )

        # Track XP earned for XP challenges
        if step_xp_result.get("xp_awarded", 0) > 0:
            challenge_service.increment_progress(
                db=db,
                user_id=current_user.id,
                challenge_type=ChallengeType.XP_EARN,
                amount=step_xp_result.get("xp_awarded", 0)
            )

    # Check if tutorial is complete
    tutorial_completed = progress.status == "completed"

    # Award XP if tutorial just completed
    if tutorial_completed and progress.completed_at:
        # Use tutorial's custom xp_reward if set, otherwise use default
        if tutorial.xp_reward and tutorial.xp_reward > 0:
            # Award custom XP amount using a multiplier
            base_xp = xp_service.config.REWARDS.get("tutorial_complete", 100)
            multiplier = tutorial.xp_reward / base_xp if base_xp > 0 else 1.0
            xp_result = xp_service.award_xp(
                db=db,
                user_id=current_user.id,
                action="tutorial_complete",
                multiplier=multiplier,
                reason=f"Completed tutorial: {tutorial.title}"
            )
        else:
            # Award default XP
            xp_result = xp_service.award_xp(
                db=db,
                user_id=current_user.id,
                action="tutorial_complete",
                reason=f"Completed tutorial: {tutorial.title}"
            )

        xp_awarded += xp_result.get("xp_awarded", 0)

        # Check for level up
        if xp_result.get("level_up"):
            logger.info(f"User {current_user.id} leveled up to {xp_result.get('new_level')}!")

            # Log level up activity
            achievement_service.log_activity(
                db=db,
                user_id=current_user.id,
                activity_type=ActivityType.LEVEL_UP,
                title=f"Reached level {xp_result.get('new_level')}!",
                activity_data={
                    "old_level": xp_result.get("old_level"),
                    "new_level": xp_result.get("new_level"),
                    "trigger": "tutorial_complete"
                }
            )

        # Log tutorial completion activity
        achievement_service.log_activity(
            db=db,
            user_id=current_user.id,
            activity_type=ActivityType.TUTORIAL_COMPLETE,
            title=f"Completed tutorial: {tutorial.title}",
            reference_type="tutorial",
            reference_id=str(tutorial_id),
            activity_data={
                "difficulty": tutorial.difficulty,
                "time_spent_minutes": progress.time_spent_minutes,
                "total_steps": total_steps
            },
            xp_earned=xp_result.get("xp_awarded", 0)
        )

        # Check and unlock any achievements
        unlocked_achievements = achievement_service.check_and_unlock_achievements(
            db=db,
            user_id=current_user.id,
            action="tutorial_complete",
            context={
                "tutorial_id": tutorial_id,
                "difficulty": tutorial.difficulty,
                "time_spent_minutes": progress.time_spent_minutes
            }
        )

        if unlocked_achievements:
            logger.info(f"User {current_user.id} unlocked {len(unlocked_achievements)} achievement(s)")

        # Track XP earned for XP challenges
        if xp_result.get("xp_awarded", 0) > 0:
            challenge_service.increment_progress(
                db=db,
                user_id=current_user.id,
                challenge_type=ChallengeType.XP_EARN,
                amount=xp_result.get("xp_awarded", 0)
            )

        logger.info(f"User {current_user.id} completed tutorial {tutorial_id}, awarded {xp_result.get('xp_awarded', 0)} XP")

        # =========== SKILL XP INTEGRATION ===========
        # Award skill XP based on tutorial category (if skills plugin enabled)
        if settings.PLUGINS_ENABLED.get("skills", False):
            try:
                # Get skill slugs from tutorial category
                category_slug = tutorial.category.slug.lower() if tutorial.category else "problem-solving"
                skill_slugs = CATEGORY_TO_SKILLS_MAP.get(category_slug, ["problem-solving"])

                # Base XP for tutorial completion (split across skills)
                skill_xp_base = tutorial.xp_reward if tutorial.xp_reward else 50
                xp_per_skill = skill_xp_base // len(skill_slugs)

                for skill_slug in skill_slugs:
                    skill_result = await award_skill_xp(
                        db=db,
                        user_id=current_user.id,
                        skill_slug=skill_slug,
                        xp_amount=xp_per_skill,
                        source_type="tutorial",
                        source_id=str(tutorial_id),
                        source_metadata={
                            "tutorial_title": tutorial.title,
                            "difficulty": tutorial.difficulty,
                            "category": category_slug
                        }
                    )
                    if skill_result.level_up:
                        logger.info(f"User {current_user.id} leveled up {skill_slug}: {skill_result.old_level} -> {skill_result.new_level}")
            except Exception as e:
                logger.error(f"Failed to award skill XP for tutorial {tutorial_id}: {e}")

    # Find next step
    next_step_id = None
    if not tutorial_completed:
        # Get next uncompleted step
        for s in sorted(tutorial.steps, key=lambda x: x.step_order):
            if s.id not in progress.completed_step_ids:
                next_step_id = s.id
                break

    return schemas.CompleteStepResponse(
        message="Step completed successfully",
        progress_percentage=progress_percentage,
        tutorial_completed=tutorial_completed,
        xp_awarded=xp_awarded if xp_awarded > 0 else None,
        next_step_id=next_step_id
    )


@router.get("/progress/my-tutorials", response_model=List[schemas.TutorialProgressResponse])
async def get_my_tutorial_progress(
    status: Optional[str] = Query(None, regex="^(in_progress|completed)$"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all tutorial progress for current user"""
    progress_records = crud.get_user_tutorial_progress_all(db, current_user.id, status=status)

    result = []
    for progress in progress_records:
        tutorial = crud.get_tutorial(db, progress.tutorial_id)
        if tutorial:
            progress_dict = schemas.TutorialProgressResponse.from_orm(progress).model_dump()
            total_steps = len(tutorial.steps)
            completed_steps = len(progress.completed_step_ids)
            progress_dict["progress_percentage"] = int((completed_steps / total_steps * 100)) if total_steps > 0 else 0
            progress_dict["total_steps"] = total_steps
            result.append(schemas.TutorialProgressResponse(**progress_dict))

    return result


# ============================================================================
# ADMIN ROUTES - Tutorial Management
# ============================================================================

@router.post("/admin/tutorials", response_model=schemas.TutorialDetailResponse, dependencies=[Depends(require_admin)])
async def create_tutorial(
    tutorial: schemas.TutorialCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Create new tutorial (admin only)"""
    # Check for duplicate slug
    existing = crud.get_tutorial_by_slug(db, tutorial.slug)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Tutorial with slug '{tutorial.slug}' already exists"
        )

    new_tutorial = crud.create_tutorial(db, tutorial, author_id=current_user.id)
    return new_tutorial


@router.get("/admin/tutorials", response_model=List[schemas.TutorialListResponse], dependencies=[Depends(require_admin)])
async def get_all_tutorials_admin(
    category_id: Optional[int] = None,
    difficulty: Optional[str] = None,
    is_published: Optional[bool] = None,
    search: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """Get all tutorials including unpublished (admin only)"""
    tutorials = crud.get_tutorials(
        db,
        category_id=category_id,
        difficulty=difficulty,
        is_published=is_published,  # Can see unpublished
        search=search,
        skip=skip,
        limit=limit
    )
    return tutorials


@router.put("/admin/tutorials/{tutorial_id}", response_model=schemas.TutorialDetailResponse, dependencies=[Depends(require_admin)])
async def update_tutorial(
    tutorial_id: int,
    tutorial_update: schemas.TutorialUpdate,
    db: Session = Depends(get_db)
):
    """Update tutorial (admin only)"""
    updated_tutorial = crud.update_tutorial(db, tutorial_id, tutorial_update)
    if not updated_tutorial:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tutorial not found"
        )
    return updated_tutorial


@router.delete("/admin/tutorials/{tutorial_id}", dependencies=[Depends(require_admin)])
async def delete_tutorial(
    tutorial_id: int,
    db: Session = Depends(get_db)
):
    """Delete tutorial (admin only)"""
    success = crud.delete_tutorial(db, tutorial_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tutorial not found"
        )
    return {"message": "Tutorial deleted successfully"}


# ============================================================================
# ADMIN ROUTES - Tutorial Steps Management
# ============================================================================

@router.post("/admin/tutorials/{tutorial_id}/steps", response_model=schemas.TutorialStepResponse, dependencies=[Depends(require_admin)])
async def create_tutorial_step(
    tutorial_id: int,
    step: schemas.TutorialStepCreate,
    db: Session = Depends(get_db)
):
    """Create new tutorial step (admin only)"""
    # Verify tutorial exists
    tutorial = crud.get_tutorial(db, tutorial_id)
    if not tutorial:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tutorial not found"
        )

    new_step = crud.create_tutorial_step(db, tutorial_id, step)
    return new_step


@router.put("/admin/tutorials/{tutorial_id}/steps/{step_id}", response_model=schemas.TutorialStepResponse, dependencies=[Depends(require_admin)])
async def update_tutorial_step(
    tutorial_id: int,
    step_id: int,
    step_update: schemas.TutorialStepUpdate,
    db: Session = Depends(get_db)
):
    """Update tutorial step (admin only)"""
    # Verify step belongs to tutorial
    step = crud.get_tutorial_step(db, step_id)
    if not step or step.tutorial_id != tutorial_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tutorial step not found"
        )

    updated_step = crud.update_tutorial_step(db, step_id, step_update)
    return updated_step


@router.delete("/admin/tutorials/{tutorial_id}/steps/{step_id}", dependencies=[Depends(require_admin)])
async def delete_tutorial_step(
    tutorial_id: int,
    step_id: int,
    db: Session = Depends(get_db)
):
    """Delete tutorial step (admin only)"""
    # Verify step belongs to tutorial
    step = crud.get_tutorial_step(db, step_id)
    if not step or step.tutorial_id != tutorial_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tutorial step not found"
        )

    success = crud.delete_tutorial_step(db, step_id)
    return {"message": "Tutorial step deleted successfully"}


# ============================================================================
# ADMIN ROUTES - Categories Management
# ============================================================================

@router.post("/admin/categories", response_model=schemas.TutorialCategoryResponse, dependencies=[Depends(require_admin)])
async def create_tutorial_category(
    category: schemas.TutorialCategoryCreate,
    db: Session = Depends(get_db)
):
    """Create new tutorial category (admin only)"""
    # Check for duplicate slug
    existing = crud.get_tutorial_category_by_slug(db, category.slug)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Category with slug '{category.slug}' already exists"
        )

    new_category = crud.create_tutorial_category(db, category)
    return new_category


@router.put("/admin/categories/{category_id}", response_model=schemas.TutorialCategoryResponse, dependencies=[Depends(require_admin)])
async def update_tutorial_category(
    category_id: int,
    category_update: schemas.TutorialCategoryUpdate,
    db: Session = Depends(get_db)
):
    """Update tutorial category (admin only)"""
    updated_category = crud.update_tutorial_category(db, category_id, category_update)
    if not updated_category:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Category not found"
        )
    return updated_category


@router.delete("/admin/categories/{category_id}", dependencies=[Depends(require_admin)])
async def delete_tutorial_category(
    category_id: int,
    db: Session = Depends(get_db)
):
    """Delete tutorial category (admin only)"""
    success = crud.delete_tutorial_category(db, category_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Category not found"
        )
    return {"message": "Category deleted successfully"}


# ============================================================================
# ADMIN ROUTES - Analytics
# ============================================================================

@router.get("/admin/tutorials/{tutorial_id}/analytics", response_model=schemas.TutorialAnalyticsResponse, dependencies=[Depends(require_admin)])
async def get_tutorial_analytics(
    tutorial_id: int,
    db: Session = Depends(get_db)
):
    """Get tutorial analytics (admin only)"""
    tutorial = crud.get_tutorial(db, tutorial_id)
    if not tutorial:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tutorial not found"
        )

    # Get completion rate and average time
    completion_rate = crud.get_tutorial_completion_rate(db, tutorial_id)
    average_time = crud.get_tutorial_average_time(db, tutorial_id)

    # Get total starts (users who have progress records)
    total_starts = db.query(TutorialProgress).filter(
        TutorialProgress.tutorial_id == tutorial_id
    ).count()

    # Calculate step dropoff rates
    # TODO: Implement step-by-step dropoff analysis

    return schemas.TutorialAnalyticsResponse(
        tutorial_id=tutorial_id,
        title=tutorial.title,
        total_views=tutorial.view_count,
        total_starts=total_starts,
        total_completions=tutorial.completion_count,
        completion_rate=completion_rate,
        average_time_minutes=average_time,
        step_dropoff_rates=[]  # TODO: Implement
    )
