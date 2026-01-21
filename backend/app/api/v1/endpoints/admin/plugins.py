# Backend\app\api\v1\endpoints\admin\plugins.py
"""
Admin Plugin Management Endpoints
Allows admins to view and toggle plugin status
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

from app.core.database import get_db
from app.core.config import settings
from app.auth.dependencies import require_admin
from app.users.models import User

router = APIRouter(prefix="/admin/plugins", tags=["Admin - Plugins"])


# ============== Schemas ==============

class PluginStatus(BaseModel):
    id: str
    name: str
    description: str
    version: str
    enabled: bool
    status: str  # 'active', 'inactive', 'error'
    has_admin_ui: bool = False
    admin_route: Optional[str] = None
    public_routes: List[str] = []
    stats: Optional[dict] = None


class PluginListResponse(BaseModel):
    plugins: List[PluginStatus]
    total_enabled: int
    total_available: int


class PluginToggleRequest(BaseModel):
    enabled: bool


class PluginToggleResponse(BaseModel):
    success: bool
    plugin_id: str
    new_status: bool
    message: str
    requires_restart: bool = True


# ============== Plugin Registry ==============

PLUGIN_REGISTRY = {
    "tutorials": {
        "name": "Tutorials",
        "description": "LMS Tutorial system with step-by-step learning, progress tracking, and XP rewards",
        "version": "1.7.1",
        "has_admin_ui": True,
        "admin_route": "/admin/tutorials",
        "public_routes": ["/tutorials", "/my-tutorials"],
    },
    "courses": {
        "name": "Courses",
        "description": "Full course management with modules, content blocks, and enrollments",
        "version": "1.8.0",
        "has_admin_ui": True,
        "admin_route": "/admin/courses",
        "public_routes": ["/courses", "/my-courses"],
    },
    "typing_game": {
        "name": "Typing Games",
        "description": "Typing practice with word lists, challenges, PVP battles, and leaderboards",
        "version": "1.9.0",
        "has_admin_ui": True,
        "admin_route": "/admin/games/word-lists",
        "public_routes": ["/games/typing", "/games/typing/play", "/games/typing/leaderboard"],
    },
    "quizzes": {
        "name": "Quizzes",
        "description": "Standalone quiz system with 6 question types, attempt tracking, and XP rewards",
        "version": "2.1.0",
        "has_admin_ui": True,
        "admin_route": "/admin/quizzes",
        "public_routes": ["/quizzes"],
    },
}


# ============== Helper Functions ==============

def get_plugins_enabled_from_db(db: Session) -> dict:
    """
    Get plugin enabled settings from database.
    Falls back to config.py defaults if not set in DB.
    """
    from app.api.v1.services.site_settings.models import SiteSettings

    site_settings = db.query(SiteSettings).first()

    # If DB has plugin settings, use them
    if site_settings and site_settings.plugins_enabled:
        return site_settings.plugins_enabled

    # Fall back to config defaults
    return dict(settings.PLUGINS_ENABLED)


def save_plugins_enabled_to_db(db: Session, plugins_enabled: dict) -> None:
    """Save plugin enabled settings to database."""
    from app.api.v1.services.site_settings.models import SiteSettings

    site_settings = db.query(SiteSettings).first()

    if not site_settings:
        site_settings = SiteSettings(id=1)
        db.add(site_settings)

    site_settings.plugins_enabled = plugins_enabled
    db.commit()


def get_plugin_stats(db: Session, plugin_id: str) -> Optional[dict]:
    """Get stats for a specific plugin"""
    stats = {}

    if plugin_id == "tutorials":
        from app.plugins.tutorials.models import Tutorial, TutorialProgress
        stats["total_tutorials"] = db.query(Tutorial).count()
        stats["published"] = db.query(Tutorial).filter(Tutorial.is_published == True).count()
        stats["total_completions"] = db.query(TutorialProgress).filter(
            TutorialProgress.status == "completed"
        ).count()

    elif plugin_id == "courses":
        from app.plugins.courses.models import Course, CourseEnrollment
        stats["total_courses"] = db.query(Course).count()
        stats["published"] = db.query(Course).filter(
            text("status = 'published'")
        ).count()
        stats["total_enrollments"] = db.query(CourseEnrollment).count()

    elif plugin_id == "typing_game":
        from app.plugins.typing_game.models import TypingWordList, TypingGameSession
        stats["word_lists"] = db.query(TypingWordList).count()
        stats["games_played"] = db.query(TypingGameSession).filter(
            TypingGameSession.is_completed == True
        ).count()

    elif plugin_id == "quizzes":
        try:
            from app.plugins.quizzes.models import Quiz, QuizAttempt
            stats["total_quizzes"] = db.query(Quiz).count()
            stats["published"] = db.query(Quiz).filter(Quiz.status == "published").count()
            stats["total_attempts"] = db.query(QuizAttempt).filter(
                QuizAttempt.is_complete == True
            ).count()
        except Exception:
            # Plugin may not be imported if disabled
            pass

    return stats if stats else None


# ============== Routes ==============

@router.get("", response_model=PluginListResponse)
async def get_all_plugins(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Get list of all plugins with their current status
    Requires ADMIN role
    """
    plugins = []
    enabled_count = 0

    # Get plugin settings from database (with fallback to config defaults)
    plugins_enabled = get_plugins_enabled_from_db(db)

    for plugin_id, info in PLUGIN_REGISTRY.items():
        is_enabled = plugins_enabled.get(plugin_id, False)

        if is_enabled:
            enabled_count += 1
            status = "active"
            # Get stats for enabled plugins
            stats = get_plugin_stats(db, plugin_id)
        else:
            status = "inactive"
            stats = None

        plugins.append(PluginStatus(
            id=plugin_id,
            name=info["name"],
            description=info["description"],
            version=info["version"],
            enabled=is_enabled,
            status=status,
            has_admin_ui=info["has_admin_ui"],
            admin_route=info["admin_route"],
            public_routes=info["public_routes"],
            stats=stats
        ))

    return PluginListResponse(
        plugins=plugins,
        total_enabled=enabled_count,
        total_available=len(PLUGIN_REGISTRY)
    )


@router.get("/{plugin_id}", response_model=PluginStatus)
async def get_plugin(
    plugin_id: str,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Get single plugin details
    Requires ADMIN role
    """
    if plugin_id not in PLUGIN_REGISTRY:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Plugin not found"
        )

    info = PLUGIN_REGISTRY[plugin_id]
    plugins_enabled = get_plugins_enabled_from_db(db)
    is_enabled = plugins_enabled.get(plugin_id, False)

    return PluginStatus(
        id=plugin_id,
        name=info["name"],
        description=info["description"],
        version=info["version"],
        enabled=is_enabled,
        status="active" if is_enabled else "inactive",
        has_admin_ui=info["has_admin_ui"],
        admin_route=info["admin_route"],
        public_routes=info["public_routes"],
        stats=get_plugin_stats(db, plugin_id) if is_enabled else None
    )


@router.put("/{plugin_id}/toggle", response_model=PluginToggleResponse)
async def toggle_plugin(
    plugin_id: str,
    request: PluginToggleRequest,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Toggle plugin enabled/disabled state
    Requires ADMIN role

    Changes are persisted to database and require a server restart to take effect.
    """
    if plugin_id not in PLUGIN_REGISTRY:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Plugin not found"
        )

    # Get current plugin settings from DB
    plugins_enabled = get_plugins_enabled_from_db(db)

    # Update the specific plugin
    plugins_enabled[plugin_id] = request.enabled

    # Persist to database
    save_plugins_enabled_to_db(db, plugins_enabled)

    # Also update in-memory settings for immediate API responses
    settings.PLUGINS_ENABLED[plugin_id] = request.enabled

    action = "enabled" if request.enabled else "disabled"

    return PluginToggleResponse(
        success=True,
        plugin_id=plugin_id,
        new_status=request.enabled,
        message=f"Plugin '{PLUGIN_REGISTRY[plugin_id]['name']}' has been {action}. Server restart required for routes to update.",
        requires_restart=True
    )


@router.get("/{plugin_id}/stats")
async def get_plugin_stats_endpoint(
    plugin_id: str,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Get detailed stats for a specific plugin
    Requires ADMIN role
    """
    if plugin_id not in PLUGIN_REGISTRY:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Plugin not found"
        )

    plugins_enabled = get_plugins_enabled_from_db(db)
    if not plugins_enabled.get(plugin_id, False):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Plugin is not enabled"
        )

    stats = get_plugin_stats(db, plugin_id)

    return {
        "plugin_id": plugin_id,
        "stats": stats
    }
