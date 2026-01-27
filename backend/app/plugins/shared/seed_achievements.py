# backend/app/plugins/shared/seed_achievements.py
"""
Achievement Seed Data Script
Creates beginner-friendly achievement definitions for TheITApprentice platform.
Run with: python -m app.plugins.shared.seed_achievements
"""
import sys
from pathlib import Path
from sqlalchemy.orm import Session

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent.parent.parent))

from app.core.database import SessionLocal
from app.plugins.shared.models import (
    Achievement,
    AchievementCategory,
    AchievementRarity
)


# Achievement definitions organized by category
ACHIEVEMENTS = [
    # =========================================================================
    # TUTORIALS CATEGORY (3 achievements)
    # =========================================================================
    {
        "id": "first-tutorial-complete",
        "name": "First Steps",
        "description": "Complete your first tutorial. Every expert was once a beginner!",
        "icon": "book-open",
        "category": AchievementCategory.TUTORIALS,
        "rarity": AchievementRarity.COMMON,
        "xp_reward": 25,
        "unlock_condition": {
            "type": "count",
            "action": "tutorial_complete",
            "count": 1
        },
        "is_hidden": False,
        "is_active": True,
        "sort_order": 1
    },
    {
        "id": "five-tutorials-complete",
        "name": "Eager Learner",
        "description": "Complete 5 tutorials. You're building a strong foundation!",
        "icon": "book-marked",
        "category": AchievementCategory.TUTORIALS,
        "rarity": AchievementRarity.UNCOMMON,
        "xp_reward": 75,
        "unlock_condition": {
            "type": "count",
            "action": "tutorial_complete",
            "count": 5
        },
        "is_hidden": False,
        "is_active": True,
        "sort_order": 2
    },
    {
        "id": "ten-tutorials-complete",
        "name": "Knowledge Seeker",
        "description": "Complete 10 tutorials. Your dedication to learning is impressive!",
        "icon": "graduation-cap",
        "category": AchievementCategory.TUTORIALS,
        "rarity": AchievementRarity.RARE,
        "xp_reward": 150,
        "unlock_condition": {
            "type": "count",
            "action": "tutorial_complete",
            "count": 10
        },
        "is_hidden": False,
        "is_active": True,
        "sort_order": 3
    },

    # =========================================================================
    # COURSES CATEGORY (3 achievements)
    # =========================================================================
    {
        "id": "first-course-enroll",
        "name": "Student Enrolled",
        "description": "Enroll in your first course. The journey of a thousand miles begins with a single step!",
        "icon": "user-plus",
        "category": AchievementCategory.COURSES,
        "rarity": AchievementRarity.COMMON,
        "xp_reward": 15,
        "unlock_condition": {
            "type": "count",
            "action": "course_enroll",
            "count": 1
        },
        "is_hidden": False,
        "is_active": True,
        "sort_order": 10
    },
    {
        "id": "first-course-complete",
        "name": "Graduate",
        "description": "Complete your first course. You've mastered an entire subject!",
        "icon": "award",
        "category": AchievementCategory.COURSES,
        "rarity": AchievementRarity.UNCOMMON,
        "xp_reward": 100,
        "unlock_condition": {
            "type": "count",
            "action": "course_complete",
            "count": 1
        },
        "is_hidden": False,
        "is_active": True,
        "sort_order": 11
    },
    {
        "id": "three-courses-complete",
        "name": "Scholar",
        "description": "Complete 3 courses. You're becoming a well-rounded IT professional!",
        "icon": "trophy",
        "category": AchievementCategory.COURSES,
        "rarity": AchievementRarity.RARE,
        "xp_reward": 200,
        "unlock_condition": {
            "type": "count",
            "action": "course_complete",
            "count": 3
        },
        "is_hidden": False,
        "is_active": True,
        "sort_order": 12
    },

    # =========================================================================
    # TYPING CATEGORY (4 achievements)
    # =========================================================================
    {
        "id": "first-typing-game",
        "name": "Key Tapper",
        "description": "Complete your first typing game. Practice makes perfect!",
        "icon": "keyboard",
        "category": AchievementCategory.TYPING,
        "rarity": AchievementRarity.COMMON,
        "xp_reward": 15,
        "unlock_condition": {
            "type": "count",
            "action": "typing_game_complete",
            "count": 1
        },
        "is_hidden": False,
        "is_active": True,
        "sort_order": 20
    },
    {
        "id": "typing-50wpm",
        "name": "Speed Typist",
        "description": "Reach 50 words per minute. You're typing faster than average!",
        "icon": "zap",
        "category": AchievementCategory.TYPING,
        "rarity": AchievementRarity.UNCOMMON,
        "xp_reward": 50,
        "unlock_condition": {
            "type": "value",
            "metric": "typing_wpm",
            "operator": ">=",
            "value": 50
        },
        "is_hidden": False,
        "is_active": True,
        "sort_order": 21
    },
    {
        "id": "typing-100wpm",
        "name": "Lightning Fingers",
        "description": "Reach 100 words per minute. You're in the elite tier of typists!",
        "icon": "flame",
        "category": AchievementCategory.TYPING,
        "rarity": AchievementRarity.EPIC,
        "xp_reward": 200,
        "unlock_condition": {
            "type": "value",
            "metric": "typing_wpm",
            "operator": ">=",
            "value": 100
        },
        "is_hidden": False,
        "is_active": True,
        "sort_order": 22
    },
    {
        "id": "typing-10-games",
        "name": "Practice Makes Perfect",
        "description": "Play 10 typing games. Consistency is the key to improvement!",
        "icon": "repeat",
        "category": AchievementCategory.TYPING,
        "rarity": AchievementRarity.UNCOMMON,
        "xp_reward": 50,
        "unlock_condition": {
            "type": "count",
            "action": "typing_game_complete",
            "count": 10
        },
        "is_hidden": False,
        "is_active": True,
        "sort_order": 23
    },

    # =========================================================================
    # STREAK CATEGORY (3 achievements)
    # =========================================================================
    {
        "id": "streak-3-days",
        "name": "Getting Started",
        "description": "Maintain a 3-day learning streak. Consistency is building!",
        "icon": "calendar",
        "category": AchievementCategory.STREAK,
        "rarity": AchievementRarity.COMMON,
        "xp_reward": 25,
        "unlock_condition": {
            "type": "streak",
            "days": 3
        },
        "is_hidden": False,
        "is_active": True,
        "sort_order": 30
    },
    {
        "id": "streak-7-days",
        "name": "Dedicated Learner",
        "description": "Maintain a 7-day learning streak. A full week of dedication!",
        "icon": "calendar-check",
        "category": AchievementCategory.STREAK,
        "rarity": AchievementRarity.UNCOMMON,
        "xp_reward": 75,
        "unlock_condition": {
            "type": "streak",
            "days": 7
        },
        "is_hidden": False,
        "is_active": True,
        "sort_order": 31
    },
    {
        "id": "streak-30-days",
        "name": "Unstoppable",
        "description": "Maintain a 30-day learning streak. You're a learning machine!",
        "icon": "crown",
        "category": AchievementCategory.STREAK,
        "rarity": AchievementRarity.EPIC,
        "xp_reward": 300,
        "unlock_condition": {
            "type": "streak",
            "days": 30
        },
        "is_hidden": False,
        "is_active": True,
        "sort_order": 32
    },

    # =========================================================================
    # SPECIAL CATEGORY (3 achievements)
    # =========================================================================
    {
        "id": "first-quiz-pass",
        "name": "Quiz Whiz",
        "description": "Pass your first quiz. Testing your knowledge pays off!",
        "icon": "check-circle",
        "category": AchievementCategory.SPECIAL,
        "rarity": AchievementRarity.COMMON,
        "xp_reward": 25,
        "unlock_condition": {
            "type": "count",
            "action": "quiz_pass",
            "count": 1
        },
        "is_hidden": False,
        "is_active": True,
        "sort_order": 40
    },
    {
        "id": "perfect-quiz",
        "name": "Perfect Score",
        "description": "Score 100% on any quiz. Flawless knowledge demonstration!",
        "icon": "star",
        "category": AchievementCategory.SPECIAL,
        "rarity": AchievementRarity.RARE,
        "xp_reward": 150,
        "unlock_condition": {
            "type": "value",
            "metric": "quiz_score",
            "operator": "==",
            "value": 100
        },
        "is_hidden": False,
        "is_active": True,
        "sort_order": 41
    },
    {
        "id": "level-10",
        "name": "Rising Star",
        "description": "Reach level 10. You're making serious progress on your IT journey!",
        "icon": "rocket",
        "category": AchievementCategory.SPECIAL,
        "rarity": AchievementRarity.RARE,
        "xp_reward": 200,
        "unlock_condition": {
            "type": "value",
            "metric": "user_level",
            "operator": ">=",
            "value": 10
        },
        "is_hidden": False,
        "is_active": True,
        "sort_order": 42
    },
]


def seed_achievements(db: Session) -> dict:
    """
    Seed achievements into the database.
    Uses upsert pattern - updates existing achievements or creates new ones.

    Returns:
        dict with counts of created and updated achievements
    """
    created = 0
    updated = 0

    for achievement_data in ACHIEVEMENTS:
        achievement_id = achievement_data["id"]

        # Check if achievement exists
        existing = db.query(Achievement).filter(Achievement.id == achievement_id).first()

        if existing:
            # Update existing achievement
            for key, value in achievement_data.items():
                setattr(existing, key, value)
            updated += 1
            print(f"  Updated: {achievement_data['name']} ({achievement_data['category'].value})")
        else:
            # Create new achievement
            achievement = Achievement(**achievement_data)
            db.add(achievement)
            created += 1
            print(f"  Created: {achievement_data['name']} ({achievement_data['category'].value})")

    db.commit()

    # Summary by category
    categories = {}
    for a in ACHIEVEMENTS:
        cat = a["category"].value
        categories[cat] = categories.get(cat, 0) + 1

    return {
        "created": created,
        "updated": updated,
        "total": len(ACHIEVEMENTS),
        "by_category": categories
    }


def run_seed():
    """
    Run the achievement seed script.
    Usage: python -m app.plugins.shared.seed_achievements
    """
    db = SessionLocal()

    try:
        print("Seeding achievement definitions...")
        print("-" * 40)

        result = seed_achievements(db)

        print("-" * 40)
        print(f"\nSeed complete!")
        print(f"  Created: {result['created']} achievements")
        print(f"  Updated: {result['updated']} achievements")
        print(f"\nBy category:")
        for cat, count in result['by_category'].items():
            print(f"  - {cat}: {count}")

    except Exception as e:
        print(f"\nError seeding achievements: {e}")
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    run_seed()
