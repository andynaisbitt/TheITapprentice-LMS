# backend/app/plugins/shared/xp_service.py
"""
XP (Experience Points) Service

Handles XP awarding, level calculation, and streak tracking across all LMS plugins.
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple
from sqlalchemy.orm import Session
import logging

from app.users.models import User
from app.core.config import settings

logger = logging.getLogger(__name__)


class XPConfig:
    """XP configuration - can be overridden in settings"""

    # Level calculation: XP needed = BASE_XP * (level ^ LEVEL_EXPONENT)
    BASE_XP: int = 100
    LEVEL_EXPONENT: float = 1.5
    MAX_LEVEL: int = 100

    # XP rewards by action
    REWARDS: Dict[str, int] = {
        # Tutorial rewards
        "tutorial_step_complete": 10,
        "tutorial_complete": 100,
        "tutorial_first_completion": 50,  # Bonus for first time

        # Course rewards
        "lesson_complete": 15,
        "module_complete": 75,
        "course_complete": 250,
        "course_perfect_score": 100,  # All quizzes 100%

        # Typing game rewards
        "typing_game_complete": 20,
        "typing_game_wpm_50": 30,  # Bonus for 50+ WPM
        "typing_game_wpm_80": 60,  # Bonus for 80+ WPM
        "typing_game_wpm_100": 100,  # Bonus for 100+ WPM
        "typing_game_accuracy_95": 25,  # Bonus for 95%+ accuracy
        "typing_game_accuracy_100": 50,  # Bonus for 100% accuracy
        "typing_pvp_win": 40,
        "typing_pvp_perfect": 75,  # Win with 100% accuracy

        # Daily rewards
        "daily_login": 10,
        "daily_streak_3": 25,  # 3 day streak bonus
        "daily_streak_7": 50,  # 7 day streak bonus
        "daily_streak_30": 150,  # 30 day streak bonus

        # Social rewards
        "first_comment": 15,
        "helpful_comment": 10,

        # Challenge rewards (dynamic, but base for tracking)
        "typing_daily_challenge": 50,
        "typing_streak_bonus": 10,  # Per day in streak
    }

    # Streak configuration
    STREAK_RESET_HOURS: int = 48  # Reset after 48 hours of inactivity


class XPService:
    """Service for managing user XP and levels"""

    def __init__(self, config: Optional[XPConfig] = None):
        self.config = config or XPConfig()

    def calculate_level(self, total_xp: int) -> int:
        """
        Calculate user level from total XP.
        Uses formula: XP needed for level N = BASE_XP * (N ^ LEVEL_EXPONENT)
        """
        level = 1
        accumulated_xp = 0

        while level < self.config.MAX_LEVEL:
            xp_for_next_level = self._xp_for_level(level + 1)
            if accumulated_xp + xp_for_next_level > total_xp:
                break
            accumulated_xp += xp_for_next_level
            level += 1

        return level

    def _xp_for_level(self, level: int) -> int:
        """Calculate XP required to reach a specific level"""
        return int(self.config.BASE_XP * (level ** self.config.LEVEL_EXPONENT))

    def get_level_progress(self, total_xp: int) -> Dict:
        """
        Get detailed level progress information.

        Returns:
            {
                "level": current_level,
                "total_xp": total_xp,
                "xp_for_current_level": xp_needed_for_this_level,
                "xp_in_current_level": progress_in_this_level,
                "xp_for_next_level": xp_needed_for_next,
                "progress_percent": 0-100 progress to next level
            }
        """
        current_level = self.calculate_level(total_xp)

        # Calculate XP accumulated through all levels
        accumulated_xp = 0
        for lvl in range(1, current_level + 1):
            accumulated_xp += self._xp_for_level(lvl)

        # XP in current level
        xp_at_start_of_level = accumulated_xp - self._xp_for_level(current_level)
        xp_in_current_level = total_xp - xp_at_start_of_level

        # XP needed for next level
        xp_for_next = self._xp_for_level(current_level + 1)
        xp_for_current = self._xp_for_level(current_level)

        # Calculate progress percent
        progress_percent = min(100, int((xp_in_current_level / xp_for_next) * 100))

        return {
            "level": current_level,
            "total_xp": total_xp,
            "xp_for_current_level": xp_for_current,
            "xp_in_current_level": xp_in_current_level,
            "xp_for_next_level": xp_for_next,
            "progress_percent": progress_percent,
            "xp_to_next_level": max(0, xp_for_next - xp_in_current_level)
        }

    def award_xp(
        self,
        db: Session,
        user_id: int,
        action: str,
        multiplier: float = 1.0,
        reason: Optional[str] = None
    ) -> Dict:
        """
        Award XP to a user for completing an action.

        Args:
            db: Database session
            user_id: User ID
            action: Action key from REWARDS dict
            multiplier: XP multiplier (e.g., 1.5 for bonus events)
            reason: Optional description

        Returns:
            {
                "xp_awarded": int,
                "total_xp": int,
                "old_level": int,
                "new_level": int,
                "level_up": bool,
                "action": str,
                "reason": str
            }
        """
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            logger.error(f"Cannot award XP: User {user_id} not found")
            return {"error": "User not found"}

        # Get base XP for action
        base_xp = self.config.REWARDS.get(action, 0)
        if base_xp == 0:
            logger.warning(f"Unknown XP action: {action}")
            return {"error": f"Unknown action: {action}"}

        # Calculate final XP with multiplier
        xp_awarded = int(base_xp * multiplier)

        # Get old level before award
        old_level = self.calculate_level(user.total_points)

        # Award XP
        user.total_points += xp_awarded

        # Calculate new level
        new_level = self.calculate_level(user.total_points)
        user.level = new_level

        db.commit()

        level_up = new_level > old_level
        if level_up:
            logger.info(f"User {user_id} leveled up: {old_level} -> {new_level}")

        logger.info(f"Awarded {xp_awarded} XP to user {user_id} for {action} (reason: {reason})")

        return {
            "xp_awarded": xp_awarded,
            "total_xp": user.total_points,
            "old_level": old_level,
            "new_level": new_level,
            "level_up": level_up,
            "action": action,
            "reason": reason or action
        }

    def award_typing_game_xp(
        self,
        db: Session,
        user_id: int,
        wpm: float,
        accuracy: float,
        is_pvp_win: bool = False
    ) -> Dict:
        """
        Award XP for typing game completion with bonuses.

        Args:
            db: Database session
            user_id: User ID
            wpm: Words per minute achieved
            accuracy: Accuracy percentage (0-100)
            is_pvp_win: Whether this was a PVP victory
        """
        total_xp = 0
        actions_awarded = []

        # Base completion XP
        result = self.award_xp(db, user_id, "typing_game_complete", reason="Game completed")
        total_xp += result.get("xp_awarded", 0)
        actions_awarded.append("typing_game_complete")

        # WPM bonuses (only highest tier)
        if wpm >= 100:
            result = self.award_xp(db, user_id, "typing_game_wpm_100", reason=f"100+ WPM ({wpm:.1f})")
            total_xp += result.get("xp_awarded", 0)
            actions_awarded.append("typing_game_wpm_100")
        elif wpm >= 80:
            result = self.award_xp(db, user_id, "typing_game_wpm_80", reason=f"80+ WPM ({wpm:.1f})")
            total_xp += result.get("xp_awarded", 0)
            actions_awarded.append("typing_game_wpm_80")
        elif wpm >= 50:
            result = self.award_xp(db, user_id, "typing_game_wpm_50", reason=f"50+ WPM ({wpm:.1f})")
            total_xp += result.get("xp_awarded", 0)
            actions_awarded.append("typing_game_wpm_50")

        # Accuracy bonuses
        if accuracy >= 100:
            result = self.award_xp(db, user_id, "typing_game_accuracy_100", reason="Perfect accuracy")
            total_xp += result.get("xp_awarded", 0)
            actions_awarded.append("typing_game_accuracy_100")
        elif accuracy >= 95:
            result = self.award_xp(db, user_id, "typing_game_accuracy_95", reason=f"95%+ accuracy ({accuracy:.1f}%)")
            total_xp += result.get("xp_awarded", 0)
            actions_awarded.append("typing_game_accuracy_95")

        # PVP win bonus
        if is_pvp_win:
            if accuracy >= 100:
                result = self.award_xp(db, user_id, "typing_pvp_perfect", reason="Perfect PVP win")
                total_xp += result.get("xp_awarded", 0)
                actions_awarded.append("typing_pvp_perfect")
            else:
                result = self.award_xp(db, user_id, "typing_pvp_win", reason="PVP victory")
                total_xp += result.get("xp_awarded", 0)
                actions_awarded.append("typing_pvp_win")

        user = db.query(User).filter(User.id == user_id).first()

        return {
            "total_xp_awarded": total_xp,
            "actions": actions_awarded,
            "total_xp": user.total_points if user else 0,
            "level": user.level if user else 1
        }

    def check_and_update_streak(self, db: Session, user_id: int) -> Dict:
        """
        Check and update daily login streak.
        Should be called on user activity/login.

        Returns:
            {
                "streak": current_streak,
                "streak_xp_awarded": xp_from_streak,
                "streak_bonus": which_bonus_if_any
            }
        """
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return {"error": "User not found"}

        now = datetime.now(timezone.utc)
        last_activity = user.updated_at or user.created_at
        # Ensure last_activity is timezone-aware
        if last_activity.tzinfo is None:
            last_activity = last_activity.replace(tzinfo=timezone.utc)
        hours_since_activity = (now - last_activity).total_seconds() / 3600

        streak_xp = 0
        streak_bonus = None

        # Initialize streak for new users who've never had activity
        if user.current_streak == 0:
            user.current_streak = 1
            logger.info(f"User {user_id} streak initialized to 1 (first login)")
            # Award daily login XP for first login
            result = self.award_xp(db, user_id, "daily_login", reason="First login")
            streak_xp += result.get("xp_awarded", 0)
            streak_bonus = "first_login"
            db.commit()
            return {
                "streak": user.current_streak,
                "streak_xp_awarded": streak_xp,
                "streak_bonus": streak_bonus
            }

        # Check if streak should reset
        if hours_since_activity > self.config.STREAK_RESET_HOURS:
            if user.current_streak > 0:
                logger.info(f"User {user_id} streak reset from {user.current_streak}")
            user.current_streak = 1
            streak_bonus = "streak_reset"
        elif hours_since_activity >= 20:  # At least 20 hours = new day
            user.current_streak += 1

            # Award daily login XP
            result = self.award_xp(db, user_id, "daily_login", reason="Daily login")
            streak_xp += result.get("xp_awarded", 0)

            # Check for streak bonuses
            if user.current_streak == 3:
                result = self.award_xp(db, user_id, "daily_streak_3", reason="3 day streak!")
                streak_xp += result.get("xp_awarded", 0)
                streak_bonus = "daily_streak_3"
            elif user.current_streak == 7:
                result = self.award_xp(db, user_id, "daily_streak_7", reason="7 day streak!")
                streak_xp += result.get("xp_awarded", 0)
                streak_bonus = "daily_streak_7"
            elif user.current_streak == 30:
                result = self.award_xp(db, user_id, "daily_streak_30", reason="30 day streak!")
                streak_xp += result.get("xp_awarded", 0)
                streak_bonus = "daily_streak_30"
            elif user.current_streak % 30 == 0:  # Every 30 days after
                result = self.award_xp(db, user_id, "daily_streak_30", reason=f"{user.current_streak} day streak!")
                streak_xp += result.get("xp_awarded", 0)
                streak_bonus = f"streak_{user.current_streak}"

        db.commit()

        return {
            "streak": user.current_streak,
            "streak_xp_awarded": streak_xp,
            "streak_bonus": streak_bonus
        }

    def get_xp_leaderboard(
        self,
        db: Session,
        limit: int = 10,
        offset: int = 0
    ) -> list:
        """Get top users by XP/level"""
        users = db.query(User).filter(
            User.is_active == True
        ).order_by(
            User.total_points.desc()
        ).offset(offset).limit(limit).all()

        return [
            {
                "rank": offset + idx + 1,
                "user_id": user.id,
                "username": user.username,
                "display_name": user.display_name,
                "total_xp": user.total_points,
                "level": user.level,
                "streak": user.current_streak
            }
            for idx, user in enumerate(users)
        ]

    def award_challenge_xp(
        self,
        db: Session,
        user_id: int,
        xp_amount: int,
        challenge_type: str
    ) -> Dict:
        """
        Award XP for completing a daily challenge.

        Args:
            db: Database session
            user_id: User ID
            xp_amount: Amount of XP to award
            challenge_type: Type of challenge completed
        """
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            logger.error(f"Cannot award challenge XP: User {user_id} not found")
            return {"error": "User not found"}

        # Get old level before award
        old_level = self.calculate_level(user.total_points)

        # Award XP
        user.total_points += xp_amount

        # Calculate new level
        new_level = self.calculate_level(user.total_points)
        user.level = new_level

        db.commit()

        level_up = new_level > old_level
        if level_up:
            logger.info(f"User {user_id} leveled up from challenge: {old_level} -> {new_level}")

        logger.info(f"Awarded {xp_amount} XP to user {user_id} for challenge: {challenge_type}")

        return {
            "xp_awarded": xp_amount,
            "total_xp": user.total_points,
            "old_level": old_level,
            "new_level": new_level,
            "level_up": level_up,
            "challenge_type": challenge_type
        }

    def award_streak_bonus_xp(
        self,
        db: Session,
        user_id: int,
        streak_days: int
    ) -> Dict:
        """
        Award XP bonus for maintaining a typing streak.

        Args:
            db: Database session
            user_id: User ID
            streak_days: Current streak length in days
        """
        # 10 XP per day, capped at 100 (10 days)
        xp_amount = min(streak_days * 10, 100)

        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return {"error": "User not found"}

        old_level = self.calculate_level(user.total_points)
        user.total_points += xp_amount
        new_level = self.calculate_level(user.total_points)
        user.level = new_level

        db.commit()

        logger.info(f"Awarded {xp_amount} XP streak bonus to user {user_id} ({streak_days} day streak)")

        return {
            "xp_awarded": xp_amount,
            "total_xp": user.total_points,
            "old_level": old_level,
            "new_level": new_level,
            "level_up": new_level > old_level,
            "streak_days": streak_days
        }


# Singleton instance
xp_service = XPService()
