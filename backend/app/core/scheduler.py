# backend/app/core/scheduler.py
"""
Background Task Scheduler

Uses APScheduler to run periodic tasks like daily challenge generation.
"""

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy.orm import Session
import logging
from datetime import datetime, timezone

from app.core.database import SessionLocal
from app.plugins.shared.challenge_service import challenge_service

logger = logging.getLogger(__name__)

# Global scheduler instance
scheduler = AsyncIOScheduler()


def get_db():
    """Get database session for scheduled tasks"""
    db = SessionLocal()
    try:
        return db
    except Exception:
        db.close()
        raise


async def generate_daily_challenges_task():
    """
    Scheduled task to generate daily challenges at midnight UTC.
    This runs automatically every day at 00:00 UTC.
    """
    logger.info(f"[Scheduler] Starting daily challenge generation at {datetime.now(timezone.utc)}")

    db = None
    try:
        db = get_db()
        challenges = challenge_service.generate_daily_challenges(db)

        if challenges:
            logger.info(f"[Scheduler] Generated {len(challenges)} daily challenges:")
            for c in challenges:
                logger.info(f"  - {c.title} ({c.difficulty.value}): {c.xp_reward} XP")
        else:
            logger.info("[Scheduler] No new challenges generated (may already exist for today)")

    except Exception as e:
        logger.error(f"[Scheduler] Failed to generate daily challenges: {e}")
        raise
    finally:
        if db:
            db.close()


async def check_streak_expirations_task():
    """
    Scheduled task to check and handle streak expirations.
    Runs every hour to check if any streaks should be reset.
    """
    logger.debug(f"[Scheduler] Checking streak expirations at {datetime.now(timezone.utc)}")

    db = None
    try:
        db = get_db()
        # The challenge service handles streak checking during user activity
        # This is a backup to ensure streaks are properly maintained
        # Could be extended to send notifications about expiring streaks

    except Exception as e:
        logger.error(f"[Scheduler] Failed to check streak expirations: {e}")
    finally:
        if db:
            db.close()


def init_scheduler():
    """
    Initialize and configure the background scheduler.
    Should be called during app startup.
    """
    # Daily challenge generation - runs at midnight UTC
    scheduler.add_job(
        generate_daily_challenges_task,
        CronTrigger(hour=0, minute=0, timezone='UTC'),
        id='generate_daily_challenges',
        name='Generate Daily Challenges',
        replace_existing=True,
        misfire_grace_time=3600,  # Allow 1 hour grace period if missed
    )

    # Also run immediately on startup to ensure today's challenges exist
    scheduler.add_job(
        generate_daily_challenges_task,
        'date',  # Run once immediately
        id='generate_daily_challenges_startup',
        name='Generate Daily Challenges (Startup)',
        replace_existing=True,
    )

    logger.info("[Scheduler] Background scheduler initialized")
    logger.info("[Scheduler] Jobs scheduled:")
    logger.info("  - Daily challenge generation: 00:00 UTC daily")
    logger.info("  - Startup challenge check: immediately")


def start_scheduler():
    """Start the background scheduler"""
    if not scheduler.running:
        scheduler.start()
        logger.info("[Scheduler] Background scheduler started")


def shutdown_scheduler():
    """Shutdown the background scheduler gracefully"""
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("[Scheduler] Background scheduler stopped")


def get_scheduler_status():
    """Get current scheduler status and job information"""
    jobs = []
    for job in scheduler.get_jobs():
        jobs.append({
            'id': job.id,
            'name': job.name,
            'next_run_time': job.next_run_time.isoformat() if job.next_run_time else None,
            'trigger': str(job.trigger),
        })

    return {
        'running': scheduler.running,
        'jobs': jobs,
    }
