# Backend\app\api\v1\endpoints\admin\stats.py
"""
Admin Stats API
Aggregated statistics for the admin dashboard
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional, List

from app.core.database import get_db
from app.core.config import settings
from app.auth.dependencies import require_admin
from app.users.models import User

router = APIRouter(prefix="/admin/stats", tags=["Admin - Stats"])


# ============== Schemas ==============

class DashboardStats(BaseModel):
    total_posts: int
    total_categories: int
    total_tags: int
    total_views: int
    draft_posts: int
    total_users: int
    active_users: int
    new_users_this_month: int
    total_tutorials: int
    tutorials_published: int
    total_courses: int
    courses_published: int
    total_enrollments: int
    typing_games_played: int
    total_xp_awarded: int


class TrendData(BaseModel):
    label: str
    value: int
    change: Optional[float] = None
    change_label: Optional[str] = None


class ActivityItem(BaseModel):
    id: str
    type: str
    title: str
    description: str
    timestamp: datetime
    user_name: Optional[str] = None


class AttentionItem(BaseModel):
    id: str
    type: str
    title: str
    count: int
    description: str
    link: str
    priority: str  # low, medium, high


class SystemStatusItem(BaseModel):
    id: str
    name: str
    status: str  # healthy, warning, error
    message: Optional[str] = None


class DashboardResponse(BaseModel):
    stats: DashboardStats
    trends: List[TrendData]
    recent_activities: List[ActivityItem]
    attention_items: List[AttentionItem]
    system_status: List[SystemStatusItem]
    last_updated: datetime


# ============== Routes ==============

@router.get("/dashboard", response_model=DashboardResponse)
async def get_dashboard_stats(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Get aggregated stats for admin dashboard
    Requires ADMIN role
    """
    from app.api.v1.services.blog.models import BlogPost, BlogCategory, BlogTag

    now = datetime.utcnow()
    thirty_days_ago = now - timedelta(days=30)
    seven_days_ago = now - timedelta(days=7)

    # Blog stats
    total_posts = db.query(BlogPost).count()
    draft_posts = db.query(BlogPost).filter(BlogPost.published == False).count()
    total_categories = db.query(BlogCategory).count()
    total_tags = db.query(BlogTag).count()
    total_views = db.query(func.sum(BlogPost.view_count)).scalar() or 0

    # User stats
    total_users = db.query(User).count()
    active_users = db.query(User).filter(User.is_active == True).count()
    new_users_this_month = db.query(User).filter(
        User.created_at >= thirty_days_ago
    ).count()

    # Initialize plugin stats
    total_tutorials = 0
    tutorials_published = 0
    total_courses = 0
    courses_published = 0
    total_enrollments = 0
    typing_games_played = 0
    total_xp_awarded = 0

    # Tutorial stats
    if settings.PLUGINS_ENABLED.get("tutorials", False):
        from app.plugins.tutorials.models import Tutorial
        total_tutorials = db.query(Tutorial).count()
        tutorials_published = db.query(Tutorial).filter(Tutorial.is_published == True).count()

    # Course stats
    if settings.PLUGINS_ENABLED.get("courses", False):
        from app.plugins.courses.models import Course, CourseStatus, CourseEnrollment
        total_courses = db.query(Course).count()
        courses_published = db.query(Course).filter(
            Course.status == CourseStatus.PUBLISHED
        ).count()
        total_enrollments = db.query(CourseEnrollment).count()

    # Typing game stats
    if settings.PLUGINS_ENABLED.get("typing_game", False):
        from app.plugins.typing_game.models import TypingGameSession
        typing_games_played = db.query(TypingGameSession).filter(
            TypingGameSession.is_completed == True
        ).count()

    # XP stats
    total_xp_awarded = db.query(func.sum(User.total_points)).scalar() or 0

    stats = DashboardStats(
        total_posts=total_posts,
        total_categories=total_categories,
        total_tags=total_tags,
        total_views=total_views,
        draft_posts=draft_posts,
        total_users=total_users,
        active_users=active_users,
        new_users_this_month=new_users_this_month,
        total_tutorials=total_tutorials,
        tutorials_published=tutorials_published,
        total_courses=total_courses,
        courses_published=courses_published,
        total_enrollments=total_enrollments,
        typing_games_played=typing_games_played,
        total_xp_awarded=total_xp_awarded
    )

    # Calculate trends (compare to previous period)
    trends = []

    # Users trend
    previous_month_users = db.query(User).filter(
        User.created_at >= (thirty_days_ago - timedelta(days=30)),
        User.created_at < thirty_days_ago
    ).count()
    user_change = ((new_users_this_month - previous_month_users) / max(previous_month_users, 1)) * 100

    trends.append(TrendData(
        label="New Users",
        value=new_users_this_month,
        change=round(user_change, 1),
        change_label="vs last month"
    ))

    # Posts trend (this week)
    posts_this_week = db.query(BlogPost).filter(
        BlogPost.created_at >= seven_days_ago
    ).count()
    trends.append(TrendData(
        label="Posts This Week",
        value=posts_this_week,
        change_label="last 7 days"
    ))

    # Get recent activities
    recent_activities = []
    try:
        from app.plugins.shared.models import UserActivity
        activities = db.query(UserActivity).order_by(
            UserActivity.created_at.desc()
        ).limit(10).all()

        for idx, activity in enumerate(activities):
            activity_user = db.query(User).filter(User.id == activity.user_id).first()
            recent_activities.append(ActivityItem(
                id=str(activity.id),
                type=activity.activity_type.value if activity.activity_type else "unknown",
                title=activity.title or "Activity",
                description=activity.activity_data.get("description", "") if activity.activity_data else "",
                timestamp=activity.created_at,
                user_name=activity_user.username if activity_user else None
            ))
    except Exception as e:
        # If activity logging isn't set up, return empty
        pass

    # Get attention items (real data)
    attention_items = []

    # Draft posts needing attention
    if draft_posts > 0:
        attention_items.append(AttentionItem(
            id="draft_posts",
            type="draft_posts",
            title="Draft Posts",
            count=draft_posts,
            description="Posts awaiting publication",
            link="/admin/posts?status=draft",
            priority="medium" if draft_posts < 5 else "high"
        ))

    # Unverified users
    unverified_users = db.query(User).filter(
        User.is_active == True,
        User.email_verified == False
    ).count() if hasattr(User, 'email_verified') else 0

    if unverified_users > 0:
        attention_items.append(AttentionItem(
            id="unverified_users",
            type="pending_users",
            title="Unverified Users",
            count=unverified_users,
            description="Users pending email verification",
            link="/admin/users?verified=false",
            priority="low"
        ))

    # System status
    system_status = [
        SystemStatusItem(id="api", name="API Server", status="healthy"),
        SystemStatusItem(id="database", name="Database", status="healthy"),
    ]

    # Plugin status
    enabled_plugins = sum(1 for v in settings.PLUGINS_ENABLED.values() if v)
    total_plugins = len(settings.PLUGINS_ENABLED)
    system_status.append(SystemStatusItem(
        id="plugins",
        name="Plugins",
        status="healthy" if enabled_plugins > 0 else "warning",
        message=f"{enabled_plugins}/{total_plugins} active"
    ))

    return DashboardResponse(
        stats=stats,
        trends=trends,
        recent_activities=recent_activities,
        attention_items=attention_items,
        system_status=system_status,
        last_updated=now
    )


@router.get("/lms/progress")
async def get_lms_progress_stats(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Get LMS progress statistics across all students
    Requires ADMIN role
    """
    # Get all users with LMS activity
    students = []

    query = db.query(User).filter(User.is_active == True)

    for user in query.all():
        student_data = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "total_xp": user.total_points or 0,
            "level": user.level or 1,
            "current_streak": user.current_streak or 0,
            "tutorials_completed": 0,
            "courses_completed": 0,
            "games_played": 0,
            "achievements_unlocked": 0,
            "last_active": user.last_login.isoformat() if user.last_login else None
        }

        # Get tutorial completions
        if settings.PLUGINS_ENABLED.get("tutorials", False):
            from app.plugins.tutorials.models import TutorialProgress
            student_data["tutorials_completed"] = db.query(TutorialProgress).filter(
                TutorialProgress.user_id == user.id,
                TutorialProgress.status == "completed"
            ).count()

        # Get typing game stats
        if settings.PLUGINS_ENABLED.get("typing_game", False):
            from app.plugins.typing_game.models import UserTypingStats
            typing_stats = db.query(UserTypingStats).filter(
                UserTypingStats.user_id == user.id
            ).first()
            if typing_stats:
                student_data["games_played"] = typing_stats.total_games_completed or 0

        # Get achievements
        from app.plugins.shared.models import UserAchievement
        student_data["achievements_unlocked"] = db.query(UserAchievement).filter(
            UserAchievement.user_id == user.id,
            UserAchievement.unlocked_at.isnot(None)
        ).count()

        # Only include users with some activity
        if (student_data["tutorials_completed"] > 0 or
            student_data["games_played"] > 0 or
            student_data["total_xp"] > 0):
            students.append(student_data)

    # Sort by XP
    students.sort(key=lambda x: x["total_xp"], reverse=True)

    # Calculate totals
    totals = {
        "total_students": len(students),
        "total_xp_earned": sum(s["total_xp"] for s in students),
        "total_tutorials_completed": sum(s["tutorials_completed"] for s in students),
        "total_games_played": sum(s["games_played"] for s in students),
        "total_achievements_unlocked": sum(s["achievements_unlocked"] for s in students)
    }

    return {
        "students": students[:100],  # Limit to top 100
        "totals": totals
    }


@router.get("/content")
async def get_content_stats(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Get content statistics (posts, pages, tutorials, courses)
    Requires ADMIN role
    """
    from app.api.v1.services.blog.models import BlogPost, BlogCategory
    from app.api.v1.services.pages.models import Page

    stats = {
        "blog": {
            "total_posts": db.query(BlogPost).count(),
            "published": db.query(BlogPost).filter(BlogPost.published == True).count(),
            "drafts": db.query(BlogPost).filter(BlogPost.published == False).count(),
            "total_views": db.query(func.sum(BlogPost.view_count)).scalar() or 0,
            "categories": db.query(BlogCategory).count()
        },
        "pages": {
            "total": db.query(Page).count(),
            "published": db.query(Page).filter(Page.is_published == True).count()
        }
    }

    if settings.PLUGINS_ENABLED.get("tutorials", False):
        from app.plugins.tutorials.models import Tutorial, TutorialCategory
        stats["tutorials"] = {
            "total": db.query(Tutorial).count(),
            "published": db.query(Tutorial).filter(Tutorial.is_published == True).count(),
            "categories": db.query(TutorialCategory).count(),
            "total_views": db.query(func.sum(Tutorial.view_count)).scalar() or 0
        }

    if settings.PLUGINS_ENABLED.get("courses", False):
        from app.plugins.courses.models import Course, CourseStatus
        stats["courses"] = {
            "total": db.query(Course).count(),
            "published": db.query(Course).filter(Course.status == CourseStatus.PUBLISHED).count(),
            "draft": db.query(Course).filter(Course.status == CourseStatus.DRAFT).count()
        }

    return stats
