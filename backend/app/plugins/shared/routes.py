# backend/app/plugins/shared/routes.py
"""
API routes for XP, Achievements, and Activity systems.
"""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.auth.dependencies import get_current_user, get_current_admin_user
from app.users.models import User

from .models import Achievement, AchievementCategory, AchievementRarity
from .schemas import (
    AchievementCreate, AchievementUpdate, AchievementResponse,
    AchievementProgressResponse, AchievementStatsResponse,
    LevelProgressResponse, XPLeaderboardEntry, XPStatsResponse,
    ActivityResponse, ActivityTimelineResponse,
    UserStatsResponse, DashboardResponse,
    LevelConfigCreate, LevelConfigUpdate, LevelConfigResponse
)
from .xp_service import xp_service
from .achievement_service import achievement_service

router = APIRouter(prefix="/progress", tags=["progress"])


# ============== XP Routes ==============

@router.get("/xp/me", response_model=LevelProgressResponse)
async def get_my_xp_progress(
    current_user: User = Depends(get_current_user)
):
    """Get current user's XP and level progress"""
    return xp_service.get_level_progress(current_user.total_points)


@router.get("/xp/leaderboard", response_model=List[XPLeaderboardEntry])
async def get_xp_leaderboard(
    limit: int = Query(10, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Get XP leaderboard"""
    return xp_service.get_xp_leaderboard(db, limit=limit, offset=offset)


@router.get("/xp/user/{user_id}", response_model=LevelProgressResponse)
async def get_user_xp_progress(
    user_id: int,
    db: Session = Depends(get_db)
):
    """Get a user's XP and level progress"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return xp_service.get_level_progress(user.total_points)


# ============== Achievement Routes ==============

@router.get("/achievements", response_model=List[AchievementProgressResponse])
async def get_my_achievements(
    category: Optional[AchievementCategory] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get current user's achievements with progress"""
    achievements = achievement_service.get_user_achievements(db, current_user.id)

    if category:
        achievements = [a for a in achievements if a["category"] == category]

    return achievements


@router.get("/achievements/all", response_model=List[AchievementResponse])
async def get_all_achievements(
    category: Optional[AchievementCategory] = None,
    include_inactive: bool = False,
    db: Session = Depends(get_db)
):
    """Get all available achievements"""
    achievements = achievement_service.get_all_achievements(
        db,
        category=category.value if category else None,
        active_only=not include_inactive
    )

    return achievements


@router.get("/achievements/user/{user_id}", response_model=List[AchievementProgressResponse])
async def get_user_achievements(
    user_id: int,
    db: Session = Depends(get_db)
):
    """Get a user's achievements (public profile)"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return achievement_service.get_user_achievements(db, user_id)


# ============== Activity Routes ==============

@router.get("/activities/me", response_model=ActivityTimelineResponse)
async def get_my_activities(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get current user's activity timeline"""
    return achievement_service.get_user_activities(
        db, current_user.id, limit=limit, offset=offset
    )


@router.get("/activities/user/{user_id}", response_model=ActivityTimelineResponse)
async def get_user_activities(
    user_id: int,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Get a user's activity timeline (public profile)"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return achievement_service.get_user_activities(
        db, user_id, limit=limit, offset=offset
    )


# ============== Dashboard Routes ==============

@router.get("/dashboard/me", response_model=DashboardResponse)
async def get_my_dashboard(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get current user's learning dashboard data"""
    from app.plugins.tutorials.models import TutorialProgress
    from app.plugins.typing_game.models import UserTypingStats

    # Get level progress
    level_progress = xp_service.get_level_progress(current_user.total_points)

    # Get tutorial count
    tutorials_completed = db.query(TutorialProgress).filter(
        TutorialProgress.user_id == current_user.id,
        TutorialProgress.is_completed == True
    ).count()

    # Get typing stats
    typing_stats = db.query(UserTypingStats).filter(
        UserTypingStats.user_id == current_user.id
    ).first()

    # Get achievements count
    from .models import UserAchievement
    achievements_count = db.query(UserAchievement).filter(
        UserAchievement.user_id == current_user.id,
        UserAchievement.unlocked_at.isnot(None)
    ).count()

    # Build stats
    stats = UserStatsResponse(
        total_xp=current_user.total_points,
        level=current_user.level,
        level_progress=level_progress,
        current_streak=current_user.current_streak,
        tutorials_completed=tutorials_completed,
        courses_completed=0,  # TODO: Implement when courses have progress
        typing_games_played=typing_stats.total_games_completed if typing_stats else 0,
        achievements_unlocked=achievements_count,
        best_wpm=typing_stats.best_wpm if typing_stats else None,
        avg_accuracy=typing_stats.avg_accuracy if typing_stats else None
    )

    # Get recent achievements
    recent_achievements = db.query(UserAchievement).filter(
        UserAchievement.user_id == current_user.id,
        UserAchievement.unlocked_at.isnot(None)
    ).order_by(UserAchievement.unlocked_at.desc()).limit(3).all()

    achievement_list = []
    for ua in recent_achievements:
        achievement = ua.achievement
        achievement_list.append({
            "achievement_id": achievement.id,
            "name": achievement.name,
            "description": achievement.description,
            "icon": achievement.icon,
            "rarity": achievement.rarity,
            "xp_reward": achievement.xp_reward,
            "unlocked_at": ua.unlocked_at,
            "is_new": False
        })

    # Get recent activities
    activities_result = achievement_service.get_user_activities(
        db, current_user.id, limit=5
    )

    # Get in-progress content
    in_progress = []

    # In-progress tutorials
    tutorial_progress = db.query(TutorialProgress).filter(
        TutorialProgress.user_id == current_user.id,
        TutorialProgress.is_completed == False
    ).limit(3).all()

    for tp in tutorial_progress:
        in_progress.append({
            "type": "tutorial",
            "id": tp.tutorial_id,
            "title": "Tutorial",  # Would need join to get actual title
            "progress_percent": tp.progress_percent,
            "last_accessed": tp.updated_at
        })

    return DashboardResponse(
        stats=stats,
        recent_achievements=achievement_list,
        recent_activities=activities_result["activities"],
        in_progress=in_progress,
        suggested_content=[]  # TODO: Implement content suggestions
    )


# ============== Admin Routes ==============

@router.get("/admin/achievements", response_model=List[AchievementResponse])
async def admin_get_all_achievements(
    category: Optional[AchievementCategory] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Admin: Get all achievements including inactive"""
    return achievement_service.get_all_achievements(
        db,
        category=category.value if category else None,
        active_only=False
    )


@router.post("/admin/achievements", response_model=AchievementResponse)
async def admin_create_achievement(
    achievement_data: AchievementCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Admin: Create new achievement"""
    existing = achievement_service.get_achievement(db, achievement_data.id)
    if existing:
        raise HTTPException(status_code=400, detail="Achievement ID already exists")

    return achievement_service.create_achievement(db, achievement_data.dict())


@router.put("/admin/achievements/{achievement_id}", response_model=AchievementResponse)
async def admin_update_achievement(
    achievement_id: str,
    update_data: AchievementUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Admin: Update achievement"""
    achievement = achievement_service.update_achievement(
        db, achievement_id, update_data.dict(exclude_unset=True)
    )

    if not achievement:
        raise HTTPException(status_code=404, detail="Achievement not found")

    return achievement


@router.delete("/admin/achievements/{achievement_id}")
async def admin_delete_achievement(
    achievement_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Admin: Delete achievement"""
    success = achievement_service.delete_achievement(db, achievement_id)

    if not success:
        raise HTTPException(status_code=404, detail="Achievement not found")

    return {"success": True, "message": "Achievement deleted"}


@router.get("/admin/achievements/stats", response_model=AchievementStatsResponse)
async def admin_get_achievement_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Admin: Get achievement statistics"""
    return achievement_service.get_achievement_stats(db)


@router.post("/admin/xp/award")
async def admin_award_xp(
    user_id: int,
    amount: int,
    reason: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Admin: Manually award XP to a user"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    old_level = user.level
    user.total_points += amount
    user.level = xp_service.calculate_level(user.total_points)
    db.commit()

    return {
        "success": True,
        "user_id": user_id,
        "xp_awarded": amount,
        "new_total": user.total_points,
        "old_level": old_level,
        "new_level": user.level,
        "reason": reason
    }
