# Backend\app\api\v1\endpoints\admin\system.py
"""
Admin System Health & Monitoring Endpoints
Shows API, database, and plugin status
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime
import time
import sys
import os

from app.core.database import get_db
from app.core.config import settings
from app.auth.dependencies import require_admin
from app.users.models import User

router = APIRouter(prefix="/admin/system", tags=["Admin - System"])


# ============== Schemas ==============

class HealthCheckResult(BaseModel):
    id: str
    name: str
    status: str  # 'healthy', 'warning', 'error'
    message: str
    response_time_ms: Optional[int] = None
    details: Optional[dict] = None
    last_checked: datetime


class SystemHealthResponse(BaseModel):
    overall_status: str  # 'healthy', 'warning', 'error'
    checks: List[HealthCheckResult]
    system_info: dict
    last_checked: datetime


class SystemInfoResponse(BaseModel):
    python_version: str
    environment: str
    debug_mode: bool
    uptime: Optional[str] = None
    plugins_enabled: dict
    database_type: str


# ============== Health Check Functions ==============

def check_api_health() -> HealthCheckResult:
    """Check API server health"""
    start = time.time()

    try:
        # Simple check - if we're here, API is working
        response_time = int((time.time() - start) * 1000)

        return HealthCheckResult(
            id="api",
            name="API Server",
            status="healthy",
            message="All endpoints responding",
            response_time_ms=response_time,
            details={
                "version": "2.0.0",
                "environment": settings.ENVIRONMENT
            },
            last_checked=datetime.utcnow()
        )
    except Exception as e:
        return HealthCheckResult(
            id="api",
            name="API Server",
            status="error",
            message=str(e),
            last_checked=datetime.utcnow()
        )


def check_database_health(db: Session) -> HealthCheckResult:
    """Check database connection health"""
    start = time.time()

    try:
        # Execute simple query
        result = db.execute(text("SELECT 1"))
        result.fetchone()

        response_time = int((time.time() - start) * 1000)

        # Get database info
        db_url = settings.DATABASE_URL
        db_type = "PostgreSQL" if "postgresql" in db_url else "SQLite" if "sqlite" in db_url else "Unknown"

        return HealthCheckResult(
            id="database",
            name="Database",
            status="healthy",
            message=f"{db_type} connected",
            response_time_ms=response_time,
            details={
                "type": db_type,
                "response_time": f"{response_time}ms"
            },
            last_checked=datetime.utcnow()
        )
    except Exception as e:
        return HealthCheckResult(
            id="database",
            name="Database",
            status="error",
            message=f"Database connection failed: {str(e)}",
            last_checked=datetime.utcnow()
        )


def check_plugins_health() -> HealthCheckResult:
    """Check plugins system health"""
    try:
        enabled_plugins = [k for k, v in settings.PLUGINS_ENABLED.items() if v]
        total_plugins = len(settings.PLUGINS_ENABLED)
        enabled_count = len(enabled_plugins)

        return HealthCheckResult(
            id="plugins",
            name="Plugins",
            status="healthy",
            message=f"{enabled_count} of {total_plugins} plugins active",
            details={
                "enabled": enabled_plugins,
                "disabled": [k for k, v in settings.PLUGINS_ENABLED.items() if not v]
            },
            last_checked=datetime.utcnow()
        )
    except Exception as e:
        return HealthCheckResult(
            id="plugins",
            name="Plugins",
            status="error",
            message=str(e),
            last_checked=datetime.utcnow()
        )


def check_external_services() -> HealthCheckResult:
    """Check external service connectivity"""
    services = []
    warnings = []

    # Check email service
    if settings.SENDGRID_API_KEY:
        services.append("SendGrid Email")
    elif settings.SMTP_HOST:
        services.append("SMTP Email")
    else:
        warnings.append("No email service configured")

    # Check OAuth
    if settings.GOOGLE_CLIENT_ID:
        services.append("Google OAuth")

    status = "healthy" if not warnings else "warning"
    message = ", ".join(services) + " OK" if services else "No external services configured"
    if warnings:
        message = warnings[0]

    return HealthCheckResult(
        id="external",
        name="External Services",
        status=status,
        message=message,
        details={
            "configured": services,
            "warnings": warnings
        },
        last_checked=datetime.utcnow()
    )


# ============== Routes ==============

@router.get("/health", response_model=SystemHealthResponse)
async def get_system_health(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Get comprehensive system health status
    Requires ADMIN role
    """
    checks = [
        check_api_health(),
        check_database_health(db),
        check_plugins_health(),
        check_external_services()
    ]

    # Determine overall status
    if any(c.status == "error" for c in checks):
        overall = "error"
    elif any(c.status == "warning" for c in checks):
        overall = "warning"
    else:
        overall = "healthy"

    # Get system info
    system_info = {
        "python_version": sys.version.split()[0],
        "environment": settings.ENVIRONMENT,
        "debug_mode": settings.DEBUG,
        "platform": sys.platform
    }

    return SystemHealthResponse(
        overall_status=overall,
        checks=checks,
        system_info=system_info,
        last_checked=datetime.utcnow()
    )


@router.get("/info", response_model=SystemInfoResponse)
async def get_system_info(
    current_user: User = Depends(require_admin)
):
    """
    Get system information
    Requires ADMIN role
    """
    db_url = settings.DATABASE_URL
    db_type = "PostgreSQL" if "postgresql" in db_url else "SQLite" if "sqlite" in db_url else "Unknown"

    return SystemInfoResponse(
        python_version=sys.version.split()[0],
        environment=settings.ENVIRONMENT,
        debug_mode=settings.DEBUG,
        plugins_enabled=settings.PLUGINS_ENABLED,
        database_type=db_type
    )


@router.get("/stats")
async def get_system_stats(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Get system-wide statistics
    Requires ADMIN role
    """
    from sqlalchemy import func
    from app.users.models import User

    # User stats
    total_users = db.query(func.count(User.id)).scalar()
    active_users = db.query(func.count(User.id)).filter(User.is_active == True).scalar()
    admin_users = db.query(func.count(User.id)).filter(User.is_admin == True).scalar()

    stats = {
        "users": {
            "total": total_users,
            "active": active_users,
            "admins": admin_users
        }
    }

    # Plugin stats (if enabled)
    if settings.PLUGINS_ENABLED.get("tutorials", False):
        from app.plugins.tutorials.models import Tutorial, TutorialProgress
        stats["tutorials"] = {
            "total": db.query(Tutorial).count(),
            "published": db.query(Tutorial).filter(Tutorial.is_published == True).count(),
            "completions": db.query(TutorialProgress).filter(TutorialProgress.status == "completed").count()
        }

    if settings.PLUGINS_ENABLED.get("courses", False):
        from app.plugins.courses.models import Course, CourseEnrollment
        stats["courses"] = {
            "total": db.query(Course).count(),
            "published": db.query(Course).filter(text("status = 'published'")).count(),
            "enrollments": db.query(CourseEnrollment).count()
        }

    if settings.PLUGINS_ENABLED.get("typing_game", False):
        from app.plugins.typing_game.models import TypingGameSession, TypingWordList
        stats["typing_game"] = {
            "word_lists": db.query(TypingWordList).count(),
            "games_played": db.query(TypingGameSession).filter(TypingGameSession.is_completed == True).count()
        }

    return stats


@router.get("/scheduler")
async def get_scheduler_status(
    current_user: User = Depends(require_admin)
):
    """
    Get background scheduler status and job information.
    Shows scheduled jobs including daily challenge generation.
    Requires ADMIN role.
    """
    from app.core.scheduler import get_scheduler_status
    return get_scheduler_status()


@router.post("/scheduler/trigger-challenges")
async def trigger_challenge_generation(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Manually trigger daily challenge generation.
    Useful for testing or if the scheduled job failed.
    Requires ADMIN role.
    """
    from app.plugins.shared.challenge_service import challenge_service

    challenges = challenge_service.generate_daily_challenges(db)

    return {
        "success": True,
        "generated_count": len(challenges),
        "challenges": [
            {
                "id": c.id,
                "title": c.title,
                "difficulty": c.difficulty.value,
                "xp_reward": c.xp_reward,
            }
            for c in challenges
        ]
    }
