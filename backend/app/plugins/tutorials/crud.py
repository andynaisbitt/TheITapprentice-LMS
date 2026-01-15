# backend/app/plugins/tutorials/crud.py
"""
Tutorial CRUD operations for FastReactCMS LMS Edition
Database operations for tutorials, steps, categories, and progress tracking
"""
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from typing import List, Optional
from datetime import datetime

from .models import Tutorial, TutorialStep, TutorialCategory, TutorialProgress
from .schemas import (
    TutorialCreate,
    TutorialUpdate,
    TutorialStepCreate,
    TutorialStepUpdate,
    TutorialCategoryCreate,
    TutorialCategoryUpdate
)


# ============================================================================
# Tutorial Category CRUD
# ============================================================================

def get_tutorial_category(db: Session, category_id: int) -> Optional[TutorialCategory]:
    """Get category by ID"""
    return db.query(TutorialCategory).filter(TutorialCategory.id == category_id).first()


def get_tutorial_category_by_slug(db: Session, slug: str) -> Optional[TutorialCategory]:
    """Get category by slug"""
    return db.query(TutorialCategory).filter(TutorialCategory.slug == slug).first()


def get_tutorial_categories(db: Session, skip: int = 0, limit: int = 100) -> List[TutorialCategory]:
    """Get all categories"""
    return db.query(TutorialCategory).order_by(TutorialCategory.display_order).offset(skip).limit(limit).all()


def create_tutorial_category(db: Session, category: TutorialCategoryCreate) -> TutorialCategory:
    """Create new category"""
    db_category = TutorialCategory(**category.model_dump())
    db.add(db_category)
    db.commit()
    db.refresh(db_category)
    return db_category


def update_tutorial_category(
    db: Session,
    category_id: int,
    category_update: TutorialCategoryUpdate
) -> Optional[TutorialCategory]:
    """Update category"""
    category = get_tutorial_category(db, category_id)
    if not category:
        return None

    update_data = category_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(category, field, value)

    category.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(category)
    return category


def delete_tutorial_category(db: Session, category_id: int) -> bool:
    """Delete category"""
    category = get_tutorial_category(db, category_id)
    if not category:
        return False

    db.delete(category)
    db.commit()
    return True


# ============================================================================
# Tutorial CRUD
# ============================================================================

def get_tutorial(db: Session, tutorial_id: int) -> Optional[Tutorial]:
    """Get tutorial by ID"""
    return db.query(Tutorial).filter(Tutorial.id == tutorial_id).first()


def get_tutorial_by_slug(db: Session, slug: str) -> Optional[Tutorial]:
    """Get tutorial by slug"""
    return db.query(Tutorial).filter(Tutorial.slug == slug).first()


def get_tutorials(
    db: Session,
    category_id: Optional[int] = None,
    difficulty: Optional[str] = None,
    is_published: Optional[bool] = True,
    is_featured: Optional[bool] = None,
    search: Optional[str] = None,
    skip: int = 0,
    limit: int = 100
) -> List[Tutorial]:
    """Get all tutorials with filtering"""
    query = db.query(Tutorial)

    # Filters
    if is_published is not None:
        query = query.filter(Tutorial.is_published == is_published)

    if category_id:
        query = query.filter(Tutorial.category_id == category_id)

    if difficulty:
        query = query.filter(Tutorial.difficulty == difficulty)

    if is_featured is not None:
        query = query.filter(Tutorial.is_featured == is_featured)

    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (Tutorial.title.ilike(search_term)) |
            (Tutorial.description.ilike(search_term))
        )

    # Order by featured first, then by creation date
    return query.order_by(
        desc(Tutorial.is_featured),
        desc(Tutorial.created_at)
    ).offset(skip).limit(limit).all()


def create_tutorial(
    db: Session,
    tutorial: TutorialCreate,
    author_id: int
) -> Tutorial:
    """Create new tutorial with steps"""

    # Create tutorial
    tutorial_data = tutorial.model_dump(exclude={"steps"})
    db_tutorial = Tutorial(
        author_id=author_id,
        **tutorial_data
    )
    db.add(db_tutorial)
    db.flush()  # Get tutorial ID

    # Create steps
    for step_data in tutorial.steps:
        db_step = TutorialStep(
            tutorial_id=db_tutorial.id,
            **step_data.model_dump()
        )
        db.add(db_step)

    db.commit()
    db.refresh(db_tutorial)
    return db_tutorial


def update_tutorial(
    db: Session,
    tutorial_id: int,
    tutorial_update: TutorialUpdate
) -> Optional[Tutorial]:
    """Update tutorial"""
    tutorial = get_tutorial(db, tutorial_id)
    if not tutorial:
        return None

    update_data = tutorial_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(tutorial, field, value)

    tutorial.updated_at = datetime.utcnow()

    # Set published_at if being published for first time
    if tutorial_update.is_published and not tutorial.published_at:
        tutorial.published_at = datetime.utcnow()

    db.commit()
    db.refresh(tutorial)
    return tutorial


def delete_tutorial(db: Session, tutorial_id: int) -> bool:
    """Delete tutorial"""
    tutorial = get_tutorial(db, tutorial_id)
    if not tutorial:
        return False

    db.delete(tutorial)
    db.commit()
    return True


def increment_tutorial_views(db: Session, tutorial_id: int) -> None:
    """Increment tutorial view count"""
    tutorial = get_tutorial(db, tutorial_id)
    if tutorial:
        tutorial.view_count += 1
        db.commit()


# ============================================================================
# Tutorial Step CRUD
# ============================================================================

def get_tutorial_step(db: Session, step_id: int) -> Optional[TutorialStep]:
    """Get step by ID"""
    return db.query(TutorialStep).filter(TutorialStep.id == step_id).first()


def get_tutorial_steps(db: Session, tutorial_id: int) -> List[TutorialStep]:
    """Get all steps for a tutorial"""
    return db.query(TutorialStep).filter(
        TutorialStep.tutorial_id == tutorial_id
    ).order_by(TutorialStep.step_order).all()


def create_tutorial_step(
    db: Session,
    tutorial_id: int,
    step: TutorialStepCreate
) -> TutorialStep:
    """Create new tutorial step"""
    db_step = TutorialStep(
        tutorial_id=tutorial_id,
        **step.model_dump()
    )
    db.add(db_step)
    db.commit()
    db.refresh(db_step)
    return db_step


def update_tutorial_step(
    db: Session,
    step_id: int,
    step_update: TutorialStepUpdate
) -> Optional[TutorialStep]:
    """Update tutorial step"""
    step = get_tutorial_step(db, step_id)
    if not step:
        return None

    update_data = step_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(step, field, value)

    step.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(step)
    return step


def delete_tutorial_step(db: Session, step_id: int) -> bool:
    """Delete tutorial step"""
    step = get_tutorial_step(db, step_id)
    if not step:
        return False

    db.delete(step)
    db.commit()
    return True


def reorder_tutorial_steps(db: Session, tutorial_id: int, step_orders: dict) -> bool:
    """Reorder tutorial steps

    Args:
        step_orders: {step_id: new_order, ...}
    """
    for step_id, new_order in step_orders.items():
        step = get_tutorial_step(db, step_id)
        if step and step.tutorial_id == tutorial_id:
            step.step_order = new_order

    db.commit()
    return True


# ============================================================================
# Tutorial Progress CRUD
# ============================================================================

def get_tutorial_progress(
    db: Session,
    user_id: int,
    tutorial_id: int
) -> Optional[TutorialProgress]:
    """Get user's progress on a tutorial"""
    return db.query(TutorialProgress).filter(
        TutorialProgress.user_id == user_id,
        TutorialProgress.tutorial_id == tutorial_id
    ).first()


def get_user_tutorial_progress_all(
    db: Session,
    user_id: int,
    status: Optional[str] = None
) -> List[TutorialProgress]:
    """Get all tutorial progress for a user"""
    query = db.query(TutorialProgress).filter(TutorialProgress.user_id == user_id)

    if status:
        query = query.filter(TutorialProgress.status == status)

    return query.order_by(desc(TutorialProgress.last_accessed_at)).all()


def start_tutorial(
    db: Session,
    user_id: int,
    tutorial_id: int
) -> TutorialProgress:
    """Start a tutorial (or return existing progress)"""

    # Check if already started
    existing = get_tutorial_progress(db, user_id, tutorial_id)
    if existing:
        existing.last_accessed_at = datetime.utcnow()
        db.commit()
        db.refresh(existing)
        return existing

    # Get first step
    first_step = db.query(TutorialStep).filter(
        TutorialStep.tutorial_id == tutorial_id
    ).order_by(TutorialStep.step_order).first()

    # Create new progress
    progress = TutorialProgress(
        user_id=user_id,
        tutorial_id=tutorial_id,
        current_step_id=first_step.id if first_step else None,
        status="in_progress"
    )
    db.add(progress)
    db.commit()
    db.refresh(progress)
    return progress


def complete_tutorial_step(
    db: Session,
    user_id: int,
    tutorial_id: int,
    step_id: int
) -> Optional[TutorialProgress]:
    """Mark a tutorial step as complete"""

    # Get or create progress
    progress = get_tutorial_progress(db, user_id, tutorial_id)
    if not progress:
        progress = start_tutorial(db, user_id, tutorial_id)

    # Add step to completed list if not already there
    if step_id not in progress.completed_step_ids:
        completed_steps = progress.completed_step_ids.copy()
        completed_steps.append(step_id)
        progress.completed_step_ids = completed_steps

    # Update last accessed
    progress.last_accessed_at = datetime.utcnow()

    # Check if tutorial is complete
    total_steps = db.query(func.count(TutorialStep.id)).filter(
        TutorialStep.tutorial_id == tutorial_id
    ).scalar()

    if len(progress.completed_step_ids) >= total_steps:
        progress.status = "completed"
        progress.completed_at = datetime.utcnow()

        # Increment tutorial completion count
        tutorial = get_tutorial(db, tutorial_id)
        if tutorial:
            tutorial.completion_count += 1

    db.commit()
    db.refresh(progress)
    return progress


def update_tutorial_progress_time(
    db: Session,
    user_id: int,
    tutorial_id: int,
    minutes: int
) -> Optional[TutorialProgress]:
    """Update time spent on tutorial"""
    progress = get_tutorial_progress(db, user_id, tutorial_id)
    if not progress:
        return None

    progress.time_spent_minutes += minutes
    progress.last_accessed_at = datetime.utcnow()
    db.commit()
    db.refresh(progress)
    return progress


# ============================================================================
# Analytics
# ============================================================================

def get_tutorial_completion_rate(db: Session, tutorial_id: int) -> float:
    """Get completion rate for a tutorial"""
    total_started = db.query(func.count(TutorialProgress.id)).filter(
        TutorialProgress.tutorial_id == tutorial_id
    ).scalar()

    if total_started == 0:
        return 0.0

    total_completed = db.query(func.count(TutorialProgress.id)).filter(
        TutorialProgress.tutorial_id == tutorial_id,
        TutorialProgress.status == "completed"
    ).scalar()

    return (total_completed / total_started) * 100


def get_tutorial_average_time(db: Session, tutorial_id: int) -> Optional[float]:
    """Get average completion time for a tutorial"""
    avg_time = db.query(func.avg(TutorialProgress.time_spent_minutes)).filter(
        TutorialProgress.tutorial_id == tutorial_id,
        TutorialProgress.status == "completed"
    ).scalar()

    return float(avg_time) if avg_time else None


def get_popular_tutorials(db: Session, limit: int = 10) -> List[Tutorial]:
    """Get most popular tutorials by view count"""
    return db.query(Tutorial).filter(
        Tutorial.is_published == True
    ).order_by(desc(Tutorial.view_count)).limit(limit).all()


def get_featured_tutorials(db: Session, limit: int = 5) -> List[Tutorial]:
    """Get featured tutorials"""
    return db.query(Tutorial).filter(
        Tutorial.is_published == True,
        Tutorial.is_featured == True
    ).order_by(desc(Tutorial.created_at)).limit(limit).all()
