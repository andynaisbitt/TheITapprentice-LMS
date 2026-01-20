# backend/app/plugins/shared/achievement_service.py
"""
Achievement Service

Handles achievement checking, unlocking, and progress tracking.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from sqlalchemy.orm import Session
from sqlalchemy import func
import logging

from .models import Achievement, UserAchievement, UserActivity, ActivityType
from .xp_service import xp_service
from app.users.models import User

logger = logging.getLogger(__name__)


class AchievementService:
    """Service for managing achievements"""

    def get_achievement(self, db: Session, achievement_id: str) -> Optional[Achievement]:
        """Get achievement by ID"""
        return db.query(Achievement).filter(Achievement.id == achievement_id).first()

    def get_all_achievements(
        self,
        db: Session,
        category: Optional[str] = None,
        active_only: bool = True
    ) -> List[Achievement]:
        """Get all achievements, optionally filtered"""
        query = db.query(Achievement)

        if active_only:
            query = query.filter(Achievement.is_active == True)

        if category:
            query = query.filter(Achievement.category == category)

        return query.order_by(Achievement.sort_order, Achievement.id).all()

    def get_user_achievements(
        self,
        db: Session,
        user_id: int,
        include_progress: bool = True
    ) -> List[Dict]:
        """Get user's achievements with unlock status"""
        achievements = self.get_all_achievements(db)
        user_achievements = db.query(UserAchievement).filter(
            UserAchievement.user_id == user_id
        ).all()

        # Create lookup for user achievements
        user_achievement_map = {
            ua.achievement_id: ua for ua in user_achievements
        }

        result = []
        for achievement in achievements:
            ua = user_achievement_map.get(achievement.id)
            is_unlocked = ua is not None

            # Skip hidden achievements that aren't unlocked
            if achievement.is_hidden and not is_unlocked:
                continue

            progress = ua.progress if ua else 0
            progress_max = self._get_progress_max(achievement.unlock_condition)

            result.append({
                "achievement_id": achievement.id,
                "name": achievement.name,
                "description": achievement.description,
                "icon": achievement.icon,
                "category": achievement.category,
                "rarity": achievement.rarity,
                "xp_reward": achievement.xp_reward,
                "is_unlocked": is_unlocked,
                "unlocked_at": ua.unlocked_at if ua else None,
                "progress": progress,
                "progress_max": progress_max,
                "progress_percent": int((progress / progress_max) * 100) if progress_max > 0 else 0
            })

        return result

    def _get_progress_max(self, condition: Dict) -> int:
        """Get max progress value from unlock condition"""
        condition_type = condition.get("type", "")

        if condition_type == "count":
            return condition.get("count", 1)
        elif condition_type == "streak":
            return condition.get("days", 1)
        else:
            return 1

    def check_and_unlock_achievements(
        self,
        db: Session,
        user_id: int,
        action: str,
        context: Optional[Dict] = None
    ) -> List[Dict]:
        """
        Check if any achievements should be unlocked based on action.

        Args:
            db: Database session
            user_id: User ID
            action: Action that was performed (e.g., "tutorial_complete")
            context: Additional context (e.g., {"wpm": 85, "accuracy": 98})

        Returns:
            List of newly unlocked achievements
        """
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return []

        unlocked = []

        # Get achievements that match this action
        achievements = db.query(Achievement).filter(
            Achievement.is_active == True
        ).all()

        for achievement in achievements:
            # Skip if already unlocked
            existing = db.query(UserAchievement).filter(
                UserAchievement.user_id == user_id,
                UserAchievement.achievement_id == achievement.id
            ).first()

            if existing and existing.progress >= self._get_progress_max(achievement.unlock_condition):
                continue

            # Check if this achievement applies to the action
            condition = achievement.unlock_condition
            condition_action = condition.get("action", "")

            if condition.get("type") == "count" and condition_action == action:
                # Increment progress
                if existing:
                    existing.progress += 1
                    progress = existing.progress
                else:
                    existing = UserAchievement(
                        user_id=user_id,
                        achievement_id=achievement.id,
                        progress=1,
                        progress_max=condition.get("count", 1)
                    )
                    db.add(existing)
                    progress = 1

                # Check if unlocked
                if progress >= condition.get("count", 1):
                    existing.unlocked_at = datetime.utcnow()
                    existing.unlock_context = context

                    # Award XP
                    xp_service.award_xp(
                        db, user_id,
                        action="achievement_unlock",
                        reason=f"Achievement: {achievement.name}"
                    )

                    unlocked.append({
                        "achievement_id": achievement.id,
                        "name": achievement.name,
                        "description": achievement.description,
                        "icon": achievement.icon,
                        "rarity": achievement.rarity,
                        "xp_reward": achievement.xp_reward,
                        "unlocked_at": existing.unlocked_at,
                        "is_new": True
                    })

                    # Log activity
                    self._log_activity(
                        db, user_id,
                        ActivityType.ACHIEVEMENT_UNLOCK,
                        f"Unlocked: {achievement.name}",
                        reference_type="achievement",
                        reference_id=achievement.id,
                        xp_earned=achievement.xp_reward
                    )

                    logger.info(f"User {user_id} unlocked achievement: {achievement.id}")

            elif condition.get("type") == "value":
                # Check value-based achievements (e.g., WPM >= 100)
                metric = condition.get("metric", "")
                operator = condition.get("operator", ">=")
                target_value = condition.get("value", 0)

                current_value = context.get(metric) if context else None
                if current_value is None:
                    continue

                should_unlock = False
                if operator == ">=" and current_value >= target_value:
                    should_unlock = True
                elif operator == ">" and current_value > target_value:
                    should_unlock = True
                elif operator == "==" and current_value == target_value:
                    should_unlock = True

                if should_unlock:
                    if existing:
                        existing.progress = 1
                        existing.unlocked_at = datetime.utcnow()
                        existing.unlock_context = context
                    else:
                        existing = UserAchievement(
                            user_id=user_id,
                            achievement_id=achievement.id,
                            progress=1,
                            progress_max=1,
                            unlocked_at=datetime.utcnow(),
                            unlock_context=context
                        )
                        db.add(existing)

                    # Award XP
                    xp_service.award_xp(
                        db, user_id,
                        action="achievement_unlock",
                        reason=f"Achievement: {achievement.name}"
                    )

                    unlocked.append({
                        "achievement_id": achievement.id,
                        "name": achievement.name,
                        "description": achievement.description,
                        "icon": achievement.icon,
                        "rarity": achievement.rarity,
                        "xp_reward": achievement.xp_reward,
                        "unlocked_at": existing.unlocked_at,
                        "is_new": True
                    })

                    logger.info(f"User {user_id} unlocked value achievement: {achievement.id}")

            elif condition.get("type") == "streak" and action == "daily_login":
                # Check streak-based achievements
                target_days = condition.get("days", 1)

                if user.current_streak >= target_days:
                    if existing:
                        existing.progress = user.current_streak
                        if not existing.unlocked_at:
                            existing.unlocked_at = datetime.utcnow()
                            existing.unlock_context = {"streak": user.current_streak}

                            unlocked.append({
                                "achievement_id": achievement.id,
                                "name": achievement.name,
                                "description": achievement.description,
                                "icon": achievement.icon,
                                "rarity": achievement.rarity,
                                "xp_reward": achievement.xp_reward,
                                "unlocked_at": existing.unlocked_at,
                                "is_new": True
                            })
                    else:
                        existing = UserAchievement(
                            user_id=user_id,
                            achievement_id=achievement.id,
                            progress=user.current_streak,
                            progress_max=target_days,
                            unlocked_at=datetime.utcnow(),
                            unlock_context={"streak": user.current_streak}
                        )
                        db.add(existing)

                        # Award XP
                        xp_service.award_xp(
                            db, user_id,
                            action="achievement_unlock",
                            reason=f"Achievement: {achievement.name}"
                        )

                        unlocked.append({
                            "achievement_id": achievement.id,
                            "name": achievement.name,
                            "description": achievement.description,
                            "icon": achievement.icon,
                            "rarity": achievement.rarity,
                            "xp_reward": achievement.xp_reward,
                            "unlocked_at": existing.unlocked_at,
                            "is_new": True
                        })

                        logger.info(f"User {user_id} unlocked streak achievement: {achievement.id}")

        db.commit()
        return unlocked

    def _log_activity(
        self,
        db: Session,
        user_id: int,
        activity_type: ActivityType,
        title: str,
        reference_type: Optional[str] = None,
        reference_id: Optional[str] = None,
        activity_data: Optional[Dict] = None,
        xp_earned: int = 0
    ):
        """Log user activity"""
        activity = UserActivity(
            user_id=user_id,
            activity_type=activity_type,
            title=title,
            reference_type=reference_type,
            reference_id=reference_id,
            activity_data=activity_data,
            xp_earned=xp_earned
        )
        db.add(activity)

    def get_user_activities(
        self,
        db: Session,
        user_id: int,
        limit: int = 20,
        offset: int = 0,
        activity_types: Optional[List[ActivityType]] = None
    ) -> Dict:
        """Get user's activity timeline"""
        query = db.query(UserActivity).filter(UserActivity.user_id == user_id)

        if activity_types:
            query = query.filter(UserActivity.activity_type.in_(activity_types))

        total = query.count()
        activities = query.order_by(UserActivity.created_at.desc()).offset(offset).limit(limit).all()

        return {
            "activities": activities,
            "total": total,
            "has_more": total > offset + limit
        }

    def log_activity(
        self,
        db: Session,
        user_id: int,
        activity_type: ActivityType,
        title: str,
        reference_type: Optional[str] = None,
        reference_id: Optional[str] = None,
        activity_data: Optional[Dict] = None,
        xp_earned: int = 0
    ) -> UserActivity:
        """Public method to log activity"""
        self._log_activity(
            db, user_id, activity_type, title,
            reference_type, reference_id, activity_data, xp_earned
        )
        db.commit()
        return db.query(UserActivity).filter(
            UserActivity.user_id == user_id
        ).order_by(UserActivity.created_at.desc()).first()

    def get_achievement_stats(self, db: Session) -> Dict:
        """Get admin stats for achievements"""
        total = db.query(Achievement).count()
        active = db.query(Achievement).filter(Achievement.is_active == True).count()
        total_unlocks = db.query(UserAchievement).filter(
            UserAchievement.unlocked_at.isnot(None)
        ).count()

        # Unlocks today
        today = datetime.utcnow().date()
        unlocks_today = db.query(UserAchievement).filter(
            func.date(UserAchievement.unlocked_at) == today
        ).count()

        # Most unlocked achievements
        most_unlocked = db.query(
            Achievement.id,
            Achievement.name,
            func.count(UserAchievement.id).label('unlock_count')
        ).join(
            UserAchievement, UserAchievement.achievement_id == Achievement.id
        ).filter(
            UserAchievement.unlocked_at.isnot(None)
        ).group_by(
            Achievement.id
        ).order_by(
            func.count(UserAchievement.id).desc()
        ).limit(5).all()

        # Rarest (least unlocked active achievements)
        rarest = db.query(
            Achievement.id,
            Achievement.name,
            Achievement.rarity,
            func.count(UserAchievement.id).label('unlock_count')
        ).outerjoin(
            UserAchievement, UserAchievement.achievement_id == Achievement.id
        ).filter(
            Achievement.is_active == True
        ).group_by(
            Achievement.id
        ).order_by(
            func.count(UserAchievement.id).asc()
        ).limit(5).all()

        return {
            "total_achievements": total,
            "active_achievements": active,
            "total_unlocks": total_unlocks,
            "unlocks_today": unlocks_today,
            "most_unlocked": [
                {"id": m[0], "name": m[1], "unlock_count": m[2]}
                for m in most_unlocked
            ],
            "rarest_unlocked": [
                {"id": r[0], "name": r[1], "rarity": r[2], "unlock_count": r[3]}
                for r in rarest
            ]
        }

    # CRUD operations for admin
    def create_achievement(self, db: Session, achievement_data: Dict) -> Achievement:
        """Create new achievement"""
        achievement = Achievement(**achievement_data)
        db.add(achievement)
        db.commit()
        db.refresh(achievement)
        return achievement

    def update_achievement(
        self,
        db: Session,
        achievement_id: str,
        update_data: Dict
    ) -> Optional[Achievement]:
        """Update achievement"""
        achievement = self.get_achievement(db, achievement_id)
        if not achievement:
            return None

        for key, value in update_data.items():
            if value is not None:
                setattr(achievement, key, value)

        db.commit()
        db.refresh(achievement)
        return achievement

    def delete_achievement(self, db: Session, achievement_id: str) -> bool:
        """Delete achievement"""
        achievement = self.get_achievement(db, achievement_id)
        if not achievement:
            return False

        db.delete(achievement)
        db.commit()
        return True


# Singleton instance
achievement_service = AchievementService()
