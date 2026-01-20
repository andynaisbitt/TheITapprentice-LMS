# Backend\app\api\v1\endpoints\admin\activities.py
"""
Admin Activity Log Endpoints
Site-wide activity viewing for admins
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime, timedelta

from app.core.database import get_db
from app.auth.dependencies import require_admin
from app.users.models import User
from app.plugins.shared.models import UserActivity, ActivityType

router = APIRouter(prefix="/admin/activities", tags=["Admin - Activities"])


# ============== Schemas ==============

class ActivityUserInfo(BaseModel):
    id: int
    username: str
    avatar: Optional[str] = None

    class Config:
        from_attributes = True


class ActivityLogItem(BaseModel):
    id: int
    type: str
    title: Optional[str]
    description: Optional[str] = None
    user: ActivityUserInfo
    timestamp: datetime
    xp_earned: Optional[int] = None
    reference_type: Optional[str] = None
    reference_id: Optional[str] = None
    metadata: Optional[dict] = None

    class Config:
        from_attributes = True


class ActivityListResponse(BaseModel):
    activities: List[ActivityLogItem]
    total: int
    page: int
    page_size: int
    total_pages: int


class ActivityStatsResponse(BaseModel):
    total_activities: int
    activities_today: int
    activities_this_week: int
    most_active_users: List[dict]
    activity_by_type: dict


# ============== Routes ==============

@router.get("", response_model=ActivityListResponse)
async def get_all_activities(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    activity_type: Optional[str] = None,
    user_id: Optional[int] = None,
    search: Optional[str] = None,
    from_date: Optional[datetime] = None,
    to_date: Optional[datetime] = None,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Get all activities with filtering and pagination
    Requires ADMIN role
    """
    # Base query with user join
    query = db.query(UserActivity).join(User, User.id == UserActivity.user_id)

    # Apply filters
    if activity_type and activity_type != "all":
        try:
            query = query.filter(UserActivity.activity_type == ActivityType(activity_type))
        except ValueError:
            pass  # Invalid type, ignore

    if user_id:
        query = query.filter(UserActivity.user_id == user_id)

    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (UserActivity.title.ilike(search_term)) |
            (User.username.ilike(search_term))
        )

    if from_date:
        query = query.filter(UserActivity.created_at >= from_date)

    if to_date:
        query = query.filter(UserActivity.created_at <= to_date)

    # Get total count
    total = query.count()

    # Calculate pagination
    total_pages = (total + page_size - 1) // page_size
    skip = (page - 1) * page_size

    # Get activities with user data
    activities = query.order_by(desc(UserActivity.created_at)).offset(skip).limit(page_size).all()

    # Build response
    result = []
    for activity in activities:
        user = db.query(User).filter(User.id == activity.user_id).first()

        result.append(ActivityLogItem(
            id=activity.id,
            type=activity.activity_type.value if activity.activity_type else "unknown",
            title=activity.title,
            description=None,  # Could extract from activity_data
            user=ActivityUserInfo(
                id=user.id,
                username=user.username,
                avatar=user.avatar_url if hasattr(user, 'avatar_url') else None
            ),
            timestamp=activity.created_at,
            xp_earned=activity.xp_earned,
            reference_type=activity.reference_type,
            reference_id=activity.reference_id,
            metadata=activity.activity_data
        ))

    return ActivityListResponse(
        activities=result,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages
    )


@router.get("/stats", response_model=ActivityStatsResponse)
async def get_activity_stats(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Get activity statistics
    Requires ADMIN role
    """
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = today_start - timedelta(days=7)

    # Total activities
    total = db.query(UserActivity).count()

    # Activities today
    today_count = db.query(UserActivity).filter(
        UserActivity.created_at >= today_start
    ).count()

    # Activities this week
    week_count = db.query(UserActivity).filter(
        UserActivity.created_at >= week_start
    ).count()

    # Most active users (last 7 days)
    most_active = db.query(
        User.id,
        User.username,
        func.count(UserActivity.id).label('activity_count')
    ).join(UserActivity, User.id == UserActivity.user_id).filter(
        UserActivity.created_at >= week_start
    ).group_by(User.id, User.username).order_by(
        desc('activity_count')
    ).limit(10).all()

    most_active_users = [
        {"user_id": u[0], "username": u[1], "activity_count": u[2]}
        for u in most_active
    ]

    # Activity by type
    type_counts = db.query(
        UserActivity.activity_type,
        func.count(UserActivity.id)
    ).group_by(UserActivity.activity_type).all()

    activity_by_type = {
        t[0].value if t[0] else "unknown": t[1]
        for t in type_counts
    }

    return ActivityStatsResponse(
        total_activities=total,
        activities_today=today_count,
        activities_this_week=week_count,
        most_active_users=most_active_users,
        activity_by_type=activity_by_type
    )


@router.get("/recent")
async def get_recent_activities(
    limit: int = Query(10, ge=1, le=50),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Get most recent activities (for dashboard)
    Requires ADMIN role
    """
    activities = db.query(UserActivity).order_by(
        desc(UserActivity.created_at)
    ).limit(limit).all()

    result = []
    for activity in activities:
        user = db.query(User).filter(User.id == activity.user_id).first()

        result.append({
            "id": activity.id,
            "type": activity.activity_type.value if activity.activity_type else "unknown",
            "title": activity.title,
            "user": {
                "id": user.id if user else None,
                "username": user.username if user else "Unknown"
            },
            "timestamp": activity.created_at.isoformat(),
            "xp_earned": activity.xp_earned
        })

    return result


@router.get("/types")
async def get_activity_types(
    current_user: User = Depends(require_admin)
):
    """
    Get list of all activity types
    Requires ADMIN role
    """
    return [
        {"value": at.value, "label": at.value.replace("_", " ").title()}
        for at in ActivityType
    ]
