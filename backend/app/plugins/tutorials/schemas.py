# backend/app/plugins/tutorials/schemas.py
"""
Tutorial Pydantic schemas for FastReactCMS LMS Edition
Request/response models for tutorial API endpoints
"""
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


# ============================================================================
# Tutorial Category Schemas
# ============================================================================

class TutorialCategoryBase(BaseModel):
    name: str
    slug: str
    description: Optional[str] = None
    icon: Optional[str] = None
    color: Optional[str] = None


class TutorialCategoryCreate(TutorialCategoryBase):
    pass


class TutorialCategoryUpdate(BaseModel):
    name: Optional[str] = None
    slug: Optional[str] = None
    description: Optional[str] = None
    icon: Optional[str] = None
    color: Optional[str] = None
    display_order: Optional[int] = None


class TutorialCategoryResponse(TutorialCategoryBase):
    id: int
    display_order: int
    created_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# Tutorial Step Schemas
# ============================================================================

class TutorialStepBase(BaseModel):
    step_order: int
    title: str
    content: Optional[str] = None
    code_example: Optional[str] = None
    code_language: Optional[str] = None
    hints: List[str] = []


class TutorialStepCreate(TutorialStepBase):
    pass


class TutorialStepUpdate(BaseModel):
    step_order: Optional[int] = None
    title: Optional[str] = None
    content: Optional[str] = None
    code_example: Optional[str] = None
    code_language: Optional[str] = None
    hints: Optional[List[str]] = None


class TutorialStepResponse(TutorialStepBase):
    id: int
    tutorial_id: int
    created_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# Tutorial Schemas
# ============================================================================

class TutorialBase(BaseModel):
    title: str
    slug: str
    description: Optional[str] = None
    difficulty: str = "beginner"  # beginner, intermediate, advanced
    estimated_time_minutes: Optional[int] = None
    category_id: Optional[int] = None
    thumbnail_url: Optional[str] = None
    xp_reward: int = 50
    related_skills: List[str] = []


class TutorialCreate(TutorialBase):
    is_published: bool = False
    is_featured: bool = False
    steps: List[TutorialStepCreate] = []


class TutorialUpdate(BaseModel):
    title: Optional[str] = None
    slug: Optional[str] = None
    description: Optional[str] = None
    difficulty: Optional[str] = None
    estimated_time_minutes: Optional[int] = None
    category_id: Optional[int] = None
    thumbnail_url: Optional[str] = None
    is_published: Optional[bool] = None
    is_featured: Optional[bool] = None
    xp_reward: Optional[int] = None
    related_skills: Optional[List[str]] = None


class TutorialListResponse(BaseModel):
    """Tutorial list item for browse/search pages"""
    id: int
    title: str
    slug: str
    description: Optional[str]
    difficulty: str
    estimated_time_minutes: Optional[int]
    category_id: Optional[int]
    category: Optional[TutorialCategoryResponse] = None
    thumbnail_url: Optional[str]
    xp_reward: int
    related_skills: List[str]
    view_count: int
    completion_count: int
    created_at: datetime

    # User progress (if authenticated)
    user_progress_percentage: Optional[int] = None
    user_completed: Optional[bool] = None

    class Config:
        from_attributes = True


class TutorialDetailResponse(TutorialBase):
    """Complete tutorial with steps (for viewing)"""
    id: int
    author_id: int
    is_published: bool
    is_featured: bool
    view_count: int
    completion_count: int
    created_at: datetime
    updated_at: datetime
    published_at: Optional[datetime]

    # Relationships
    category: Optional[TutorialCategoryResponse] = None
    steps: List[TutorialStepResponse] = []

    # User progress (if authenticated)
    user_progress: Optional[dict] = None

    class Config:
        from_attributes = True


# ============================================================================
# Tutorial Progress Schemas
# ============================================================================

class TutorialProgressResponse(BaseModel):
    """User progress through a tutorial"""
    id: int
    user_id: int
    tutorial_id: int
    current_step_id: Optional[int]
    completed_step_ids: List[int]
    status: str  # in_progress, completed
    time_spent_minutes: int
    started_at: datetime
    last_accessed_at: datetime
    completed_at: Optional[datetime]

    # Computed fields
    progress_percentage: Optional[int] = None
    total_steps: Optional[int] = None

    class Config:
        from_attributes = True


class CompleteStepRequest(BaseModel):
    """Request to mark a step as complete"""
    step_id: int


class CompleteStepResponse(BaseModel):
    """Response after completing a step"""
    message: str
    progress_percentage: int
    tutorial_completed: bool
    xp_awarded: Optional[int] = None
    next_step_id: Optional[int] = None


class CompleteTutorialResponse(BaseModel):
    """Response after completing entire tutorial"""
    message: str
    tutorial_id: int
    completed_at: datetime
    total_time_minutes: int
    xp_awarded: int


# ============================================================================
# Admin Schemas
# ============================================================================

class TutorialWithStepsCreate(BaseModel):
    """Create tutorial with steps in one request"""
    tutorial: TutorialCreate
    steps: List[TutorialStepCreate]


class TutorialAnalyticsResponse(BaseModel):
    """Analytics data for a tutorial"""
    tutorial_id: int
    title: str
    total_views: int
    total_starts: int
    total_completions: int
    completion_rate: float
    average_time_minutes: Optional[float]
    step_dropoff_rates: List[dict]  # [{step_id, step_title, completions, dropoff_rate}]


class BulkTutorialUpdate(BaseModel):
    """Bulk update tutorials"""
    tutorial_ids: List[int]
    is_published: Optional[bool] = None
    is_featured: Optional[bool] = None
    category_id: Optional[int] = None


# ============================================================================
# Search & Filter Schemas
# ============================================================================

class TutorialFilters(BaseModel):
    """Filter parameters for tutorial search"""
    category_id: Optional[int] = None
    difficulty: Optional[str] = None  # beginner, intermediate, advanced
    search: Optional[str] = None
    is_published: Optional[bool] = True
    is_featured: Optional[bool] = None
    page: int = 1
    page_size: int = 20
