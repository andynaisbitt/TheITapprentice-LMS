# backend/app/plugins/shared/challenge_service.py
"""
Daily Challenges Service

Handles challenge generation, progress tracking, and reward claiming.
"""

from datetime import datetime, timedelta, timezone, date
from typing import Dict, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func, and_
import uuid
import random
import logging

from app.plugins.shared.models import (
    DailyChallengeTemplate, DailyChallenge, UserChallengeProgress,
    UserChallengeStreak, ChallengeType, ChallengeDifficulty
)
from app.plugins.shared.xp_service import xp_service
from app.plugins.shared.achievement_service import achievement_service, ActivityType
from app.users.models import User

logger = logging.getLogger(__name__)


class ChallengeConfig:
    """Challenge system configuration"""

    # Number of challenges to generate per day (by difficulty)
    DAILY_CHALLENGE_COUNTS = {
        ChallengeDifficulty.EASY: 1,
        ChallengeDifficulty.MEDIUM: 1,
        ChallengeDifficulty.HARD: 1,
    }

    # Streak bonus tiers (days -> XP bonus percentage)
    STREAK_BONUS_TIERS = {
        0: 0,      # No streak: +0%
        3: 10,     # 3-day: +10%
        7: 20,     # 7-day: +20%
        30: 50,    # 30-day: +50%
        60: 75,    # 60-day: +75%
        90: 100,   # 90-day: +100% (DOUBLE XP!)
    }

    # Hours before challenge streak resets
    CHALLENGE_STREAK_RESET_HOURS = 48


class ChallengeService:
    """Service for managing daily challenges"""

    def __init__(self, config: Optional[ChallengeConfig] = None):
        self.config = config or ChallengeConfig()

    def get_streak_bonus(self, streak_days: int) -> int:
        """Get XP bonus percentage for a given streak"""
        bonus = 0
        for days, bonus_percent in sorted(self.config.STREAK_BONUS_TIERS.items()):
            if streak_days >= days:
                bonus = bonus_percent
            else:
                break
        return bonus

    def get_today_utc(self) -> date:
        """Get today's date in UTC"""
        return datetime.now(timezone.utc).date()

    def get_challenge_date_range(self, target_date: date) -> Tuple[datetime, datetime]:
        """Get start and end datetime for a challenge date"""
        start = datetime.combine(target_date, datetime.min.time()).replace(tzinfo=timezone.utc)
        end = datetime.combine(target_date + timedelta(days=1), datetime.min.time()).replace(tzinfo=timezone.utc)
        return start, end

    # ========================================================================
    # Challenge Generation
    # ========================================================================

    def generate_daily_challenges(self, db: Session, target_date: Optional[date] = None) -> List[DailyChallenge]:
        """
        Generate daily challenges for a given date.
        Should be called by cron job at midnight UTC.

        Args:
            db: Database session
            target_date: Date to generate challenges for (defaults to today UTC)

        Returns:
            List of generated DailyChallenge objects
        """
        if target_date is None:
            target_date = self.get_today_utc()

        start_dt, end_dt = self.get_challenge_date_range(target_date)

        # Check if challenges already exist for this date
        existing = db.query(DailyChallenge).filter(
            and_(
                DailyChallenge.challenge_date >= start_dt,
                DailyChallenge.challenge_date < end_dt
            )
        ).count()

        if existing > 0:
            logger.info(f"Challenges already exist for {target_date}, skipping generation")
            return []

        generated = []

        # Generate challenges for each difficulty
        for difficulty, count in self.config.DAILY_CHALLENGE_COUNTS.items():
            # Get active templates for this difficulty
            templates = db.query(DailyChallengeTemplate).filter(
                and_(
                    DailyChallengeTemplate.difficulty == difficulty,
                    DailyChallengeTemplate.is_active == True
                )
            ).all()

            if not templates:
                logger.warning(f"No active templates for difficulty {difficulty.value}")
                continue

            # Randomly select templates
            selected = random.sample(templates, min(count, len(templates)))

            for template in selected:
                challenge = DailyChallenge(
                    id=str(uuid.uuid4()),
                    template_id=template.id,
                    challenge_date=start_dt,
                    title=template.title,
                    description=template.description,
                    challenge_type=template.challenge_type,
                    difficulty=template.difficulty,
                    target_count=template.target_count,
                    xp_reward=template.base_xp_reward,
                    icon=template.icon,
                )
                db.add(challenge)
                generated.append(challenge)

        db.commit()
        logger.info(f"Generated {len(generated)} challenges for {target_date}")

        return generated

    # ========================================================================
    # Get Challenges
    # ========================================================================

    def get_todays_challenges(
        self,
        db: Session,
        user_id: int,
        target_date: Optional[date] = None
    ) -> List[Dict]:
        """
        Get today's challenges with user progress.

        Args:
            db: Database session
            user_id: User ID
            target_date: Date to get challenges for (defaults to today UTC)

        Returns:
            List of challenge dicts with progress
        """
        if target_date is None:
            target_date = self.get_today_utc()

        start_dt, end_dt = self.get_challenge_date_range(target_date)

        # Get challenges for today
        challenges = db.query(DailyChallenge).filter(
            and_(
                DailyChallenge.challenge_date >= start_dt,
                DailyChallenge.challenge_date < end_dt
            )
        ).order_by(DailyChallenge.difficulty).all()

        # If no challenges exist, try to generate them
        if not challenges:
            logger.info(f"No challenges found for {target_date}, generating...")
            challenges = self.generate_daily_challenges(db, target_date)

        # Get user's challenge streak info
        streak_info = self.get_user_streak(db, user_id)

        result = []
        for challenge in challenges:
            # Get or create user progress
            progress = db.query(UserChallengeProgress).filter(
                and_(
                    UserChallengeProgress.user_id == user_id,
                    UserChallengeProgress.challenge_id == challenge.id
                )
            ).first()

            if not progress:
                progress = UserChallengeProgress(
                    id=str(uuid.uuid4()),
                    user_id=user_id,
                    challenge_id=challenge.id,
                    current_progress=0,
                    is_completed=False,
                    is_claimed=False,
                )
                db.add(progress)
                db.commit()

            # Calculate progress percentage
            progress_percent = min(100, int((progress.current_progress / challenge.target_count) * 100)) if challenge.target_count > 0 else 0

            # Calculate potential XP with streak bonus
            streak_bonus = self.get_streak_bonus(streak_info.get("current_streak", 0))
            potential_xp = int(challenge.xp_reward * (1 + streak_bonus / 100))

            result.append({
                "id": challenge.id,
                "title": challenge.title,
                "description": challenge.description,
                "challenge_type": challenge.challenge_type.value,
                "difficulty": challenge.difficulty.value,
                "target_count": challenge.target_count,
                "base_xp_reward": challenge.xp_reward,
                "potential_xp": potential_xp,
                "streak_bonus_percent": streak_bonus,
                "icon": challenge.icon,
                "current_progress": progress.current_progress,
                "progress_percent": progress_percent,
                "is_completed": progress.is_completed,
                "is_claimed": progress.is_claimed,
                "completed_at": progress.completed_at.isoformat() if progress.completed_at else None,
                "claimed_at": progress.claimed_at.isoformat() if progress.claimed_at else None,
            })

        return result

    # ========================================================================
    # Progress Tracking
    # ========================================================================

    def increment_progress(
        self,
        db: Session,
        user_id: int,
        challenge_type: ChallengeType,
        amount: int = 1,
        value: Optional[int] = None
    ) -> List[Dict]:
        """
        Increment progress for matching daily challenges.

        This should be called when user completes relevant activities:
        - Tutorial step/complete -> ChallengeType.TUTORIAL
        - Quiz complete -> ChallengeType.QUIZ
        - Course section -> ChallengeType.COURSE_SECTION
        - Typing game -> ChallengeType.TYPING_GAME
        - Typing WPM -> ChallengeType.TYPING_WPM (value=wpm)
        - XP earned -> ChallengeType.XP_EARN (amount=xp_earned)

        Args:
            db: Database session
            user_id: User ID
            challenge_type: Type of challenge to update
            amount: Amount to increment (default 1)
            value: For value-based challenges (e.g., WPM achieved)

        Returns:
            List of challenges that were updated or completed
        """
        today = self.get_today_utc()
        start_dt, end_dt = self.get_challenge_date_range(today)

        # Get today's challenges of this type
        challenges = db.query(DailyChallenge).filter(
            and_(
                DailyChallenge.challenge_date >= start_dt,
                DailyChallenge.challenge_date < end_dt,
                DailyChallenge.challenge_type == challenge_type
            )
        ).all()

        updated = []

        for challenge in challenges:
            # Get user progress
            progress = db.query(UserChallengeProgress).filter(
                and_(
                    UserChallengeProgress.user_id == user_id,
                    UserChallengeProgress.challenge_id == challenge.id
                )
            ).first()

            if not progress:
                progress = UserChallengeProgress(
                    id=str(uuid.uuid4()),
                    user_id=user_id,
                    challenge_id=challenge.id,
                    current_progress=0,
                )
                db.add(progress)

            # Skip if already completed
            if progress.is_completed:
                continue

            # Update progress
            if challenge_type in [ChallengeType.TYPING_WPM]:
                # Value-based: check if value meets target
                if value and value >= challenge.target_count:
                    progress.current_progress = challenge.target_count
            else:
                # Count-based: increment progress
                progress.current_progress = min(
                    progress.current_progress + amount,
                    challenge.target_count
                )

            # Check if completed
            if progress.current_progress >= challenge.target_count:
                progress.is_completed = True
                progress.completed_at = datetime.now(timezone.utc)
                logger.info(f"User {user_id} completed challenge: {challenge.title}")

            db.commit()

            updated.append({
                "challenge_id": challenge.id,
                "title": challenge.title,
                "current_progress": progress.current_progress,
                "target_count": challenge.target_count,
                "is_completed": progress.is_completed,
                "newly_completed": progress.is_completed and progress.completed_at == datetime.now(timezone.utc)
            })

        return updated

    # ========================================================================
    # Reward Claiming
    # ========================================================================

    def claim_reward(self, db: Session, user_id: int, challenge_id: str) -> Dict:
        """
        Claim reward for a completed challenge.

        Args:
            db: Database session
            user_id: User ID
            challenge_id: Challenge ID to claim

        Returns:
            Result dict with XP awarded and other info
        """
        # Get challenge and progress
        challenge = db.query(DailyChallenge).filter(DailyChallenge.id == challenge_id).first()
        if not challenge:
            return {"error": "Challenge not found"}

        progress = db.query(UserChallengeProgress).filter(
            and_(
                UserChallengeProgress.user_id == user_id,
                UserChallengeProgress.challenge_id == challenge_id
            )
        ).first()

        if not progress:
            return {"error": "No progress found for this challenge"}

        if not progress.is_completed:
            return {"error": "Challenge not completed yet"}

        if progress.is_claimed:
            return {"error": "Reward already claimed"}

        # Get streak bonus
        streak_info = self.get_user_streak(db, user_id)
        streak_bonus = self.get_streak_bonus(streak_info.get("current_streak", 0))

        # Calculate final XP
        base_xp = challenge.xp_reward
        bonus_xp = int(base_xp * streak_bonus / 100)
        total_xp = base_xp + bonus_xp

        # Award XP using a custom action
        user = db.query(User).filter(User.id == user_id).first()
        old_level = user.level if user else 1
        old_xp = user.total_points if user else 0

        if user:
            user.total_points += total_xp
            from app.plugins.shared.xp_service import xp_service
            user.level = xp_service.calculate_level(user.total_points)

        # Update progress record
        progress.is_claimed = True
        progress.claimed_at = datetime.now(timezone.utc)
        progress.xp_earned = total_xp
        progress.streak_bonus_percent = streak_bonus

        db.commit()

        # Log activity
        achievement_service.log_activity(
            db=db,
            user_id=user_id,
            activity_type=ActivityType.ACHIEVEMENT_UNLOCK,  # Reuse for now
            title=f"Completed challenge: {challenge.title}",
            reference_type="challenge",
            reference_id=challenge_id,
            activity_data={
                "challenge_type": challenge.challenge_type.value,
                "difficulty": challenge.difficulty.value,
                "base_xp": base_xp,
                "streak_bonus": bonus_xp,
            },
            xp_earned=total_xp
        )

        # Check if all today's challenges are completed and claimed
        self._check_daily_completion(db, user_id)

        return {
            "success": True,
            "challenge_id": challenge_id,
            "base_xp": base_xp,
            "streak_bonus_percent": streak_bonus,
            "bonus_xp": bonus_xp,
            "total_xp": total_xp,
            "new_total_xp": user.total_points if user else 0,
            "level_up": user.level > old_level if user else False,
            "new_level": user.level if user else 1,
        }

    def _check_daily_completion(self, db: Session, user_id: int) -> bool:
        """Check if user completed all challenges today and update streak"""
        today = self.get_today_utc()
        start_dt, end_dt = self.get_challenge_date_range(today)

        # Get today's challenges
        challenges = db.query(DailyChallenge).filter(
            and_(
                DailyChallenge.challenge_date >= start_dt,
                DailyChallenge.challenge_date < end_dt
            )
        ).all()

        if not challenges:
            return False

        # Check if all are completed and claimed
        all_complete = True
        for challenge in challenges:
            progress = db.query(UserChallengeProgress).filter(
                and_(
                    UserChallengeProgress.user_id == user_id,
                    UserChallengeProgress.challenge_id == challenge.id
                )
            ).first()

            if not progress or not progress.is_completed or not progress.is_claimed:
                all_complete = False
                break

        if all_complete:
            self._update_challenge_streak(db, user_id)
            return True

        return False

    # ========================================================================
    # Streak Management
    # ========================================================================

    def get_user_streak(self, db: Session, user_id: int) -> Dict:
        """Get user's challenge streak info"""
        streak = db.query(UserChallengeStreak).filter(
            UserChallengeStreak.user_id == user_id
        ).first()

        if not streak:
            streak = UserChallengeStreak(
                user_id=user_id,
                current_streak=0,
                longest_streak=0,
                freeze_tokens=2,
            )
            db.add(streak)
            db.commit()

        # Check if streak is at risk
        streak_at_risk = False
        hours_remaining = None

        if streak.last_completion_date:
            last_completion = streak.last_completion_date
            if last_completion.tzinfo is None:
                last_completion = last_completion.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            hours_since = (now - last_completion).total_seconds() / 3600

            if hours_since > 24 and hours_since < self.config.CHALLENGE_STREAK_RESET_HOURS:
                streak_at_risk = True
                hours_remaining = self.config.CHALLENGE_STREAK_RESET_HOURS - hours_since

        return {
            "current_streak": streak.current_streak,
            "longest_streak": streak.longest_streak,
            "last_completion_date": streak.last_completion_date.isoformat() if streak.last_completion_date else None,
            "freeze_tokens": streak.freeze_tokens,
            "freeze_tokens_used": streak.freeze_tokens_used,
            "streak_protected_until": streak.streak_protected_until.isoformat() if streak.streak_protected_until else None,
            "streak_at_risk": streak_at_risk,
            "hours_remaining": hours_remaining,
            "current_bonus_percent": self.get_streak_bonus(streak.current_streak),
            "next_bonus_at": self._get_next_bonus_tier(streak.current_streak),
        }

    def _get_next_bonus_tier(self, current_streak: int) -> Optional[Dict]:
        """Get info about the next streak bonus tier"""
        for days, bonus in sorted(self.config.STREAK_BONUS_TIERS.items()):
            if days > current_streak:
                return {
                    "days": days,
                    "bonus_percent": bonus,
                    "days_remaining": days - current_streak
                }
        return None

    def _update_challenge_streak(self, db: Session, user_id: int) -> None:
        """Update user's challenge streak after completing all daily challenges"""
        streak = db.query(UserChallengeStreak).filter(
            UserChallengeStreak.user_id == user_id
        ).first()

        if not streak:
            streak = UserChallengeStreak(
                user_id=user_id,
                current_streak=0,
                longest_streak=0,
                freeze_tokens=2,
            )
            db.add(streak)

        now = datetime.now(timezone.utc)
        today = now.date()

        # Check if this is a continuation of streak
        if streak.last_completion_date:
            last_date = streak.last_completion_date.date() if isinstance(streak.last_completion_date, datetime) else streak.last_completion_date
            days_diff = (today - last_date).days

            if days_diff == 0:
                # Already completed today
                return
            elif days_diff == 1:
                # Consecutive day
                streak.current_streak += 1
            elif days_diff <= 2 and streak.streak_protected_until and streak.streak_protected_until > now:
                # Protected by freeze token
                streak.current_streak += 1
            else:
                # Streak broken
                streak.current_streak = 1
        else:
            streak.current_streak = 1

        # Update longest streak
        if streak.current_streak > streak.longest_streak:
            streak.longest_streak = streak.current_streak

        streak.last_completion_date = now
        streak.streak_protected_until = None  # Clear protection

        db.commit()
        logger.info(f"User {user_id} challenge streak updated to {streak.current_streak}")

    def use_freeze_token(self, db: Session, user_id: int) -> Dict:
        """Use a freeze token to protect the streak"""
        streak = db.query(UserChallengeStreak).filter(
            UserChallengeStreak.user_id == user_id
        ).first()

        if not streak:
            return {"error": "No streak data found"}

        if streak.freeze_tokens <= 0:
            return {"error": "No freeze tokens available"}

        # Check if already protected
        now = datetime.now(timezone.utc)
        if streak.streak_protected_until and streak.streak_protected_until > now:
            return {"error": "Streak already protected"}

        # Use freeze token
        streak.freeze_tokens -= 1
        streak.freeze_tokens_used += 1
        streak.last_freeze_used = now
        streak.streak_protected_until = now + timedelta(hours=24)

        db.commit()

        return {
            "success": True,
            "freeze_tokens_remaining": streak.freeze_tokens,
            "protected_until": streak.streak_protected_until.isoformat(),
            "current_streak": streak.current_streak,
        }

    # ========================================================================
    # Admin Functions
    # ========================================================================

    def get_all_templates(self, db: Session, include_inactive: bool = False) -> List[DailyChallengeTemplate]:
        """Get all challenge templates"""
        query = db.query(DailyChallengeTemplate)
        if not include_inactive:
            query = query.filter(DailyChallengeTemplate.is_active == True)
        return query.order_by(DailyChallengeTemplate.difficulty, DailyChallengeTemplate.title).all()

    def create_template(self, db: Session, data: Dict) -> DailyChallengeTemplate:
        """Create a new challenge template"""
        template = DailyChallengeTemplate(
            id=str(uuid.uuid4()),
            title=data["title"],
            description=data.get("description"),
            challenge_type=ChallengeType(data["challenge_type"]),
            difficulty=ChallengeDifficulty(data["difficulty"]),
            target_count=data["target_count"],
            base_xp_reward=data["base_xp_reward"],
            icon=data.get("icon", "target"),
            is_active=data.get("is_active", True),
        )
        db.add(template)
        db.commit()
        return template

    def update_template(self, db: Session, template_id: str, data: Dict) -> Optional[DailyChallengeTemplate]:
        """Update a challenge template"""
        template = db.query(DailyChallengeTemplate).filter(
            DailyChallengeTemplate.id == template_id
        ).first()

        if not template:
            return None

        for key, value in data.items():
            if hasattr(template, key):
                if key == "challenge_type":
                    value = ChallengeType(value)
                elif key == "difficulty":
                    value = ChallengeDifficulty(value)
                setattr(template, key, value)

        template.updated_at = datetime.now(timezone.utc)
        db.commit()
        return template

    def delete_template(self, db: Session, template_id: str) -> bool:
        """Delete a challenge template"""
        template = db.query(DailyChallengeTemplate).filter(
            DailyChallengeTemplate.id == template_id
        ).first()

        if not template:
            return False

        db.delete(template)
        db.commit()
        return True

    def get_challenge_stats(self, db: Session) -> Dict:
        """Get challenge system statistics for admin dashboard"""
        today = self.get_today_utc()
        start_dt, end_dt = self.get_challenge_date_range(today)

        # Today's challenges
        todays_challenges = db.query(DailyChallenge).filter(
            and_(
                DailyChallenge.challenge_date >= start_dt,
                DailyChallenge.challenge_date < end_dt
            )
        ).count()

        # Completions today
        completions_today = db.query(UserChallengeProgress).filter(
            and_(
                UserChallengeProgress.is_completed == True,
                UserChallengeProgress.completed_at >= start_dt,
                UserChallengeProgress.completed_at < end_dt
            )
        ).count()

        # Active templates
        active_templates = db.query(DailyChallengeTemplate).filter(
            DailyChallengeTemplate.is_active == True
        ).count()

        # Users with active streaks
        users_with_streaks = db.query(UserChallengeStreak).filter(
            UserChallengeStreak.current_streak > 0
        ).count()

        # Longest current streak
        longest_streak = db.query(func.max(UserChallengeStreak.current_streak)).scalar() or 0

        return {
            "todays_challenges": todays_challenges,
            "completions_today": completions_today,
            "active_templates": active_templates,
            "users_with_streaks": users_with_streaks,
            "longest_current_streak": longest_streak,
        }


# Singleton instance
challenge_service = ChallengeService()
