# backend/app/plugins/shared/seed_challenges.py
"""
Daily Challenge Templates Seed Data Script
Creates challenge templates for TheITApprentice platform.
Run with: python -m app.plugins.shared.seed_challenges
"""
import sys
import uuid
from pathlib import Path
from sqlalchemy.orm import Session

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent.parent.parent))

from app.core.database import SessionLocal
from app.plugins.shared.models import (
    DailyChallengeTemplate,
    ChallengeType,
    ChallengeDifficulty
)


# Challenge template definitions
CHALLENGE_TEMPLATES = [
    # =========================================================================
    # EASY CHALLENGES - Quick wins to encourage daily engagement
    # =========================================================================
    {
        "title": "Quick Learner",
        "description": "Complete 1 tutorial step to get started today",
        "challenge_type": ChallengeType.TUTORIAL,
        "difficulty": ChallengeDifficulty.EASY,
        "target_count": 1,
        "base_xp_reward": 25,
        "icon": "book-open",
        "is_active": True
    },
    {
        "title": "Warm Up Your Fingers",
        "description": "Play 1 typing game to practice your skills",
        "challenge_type": ChallengeType.TYPING_GAME,
        "difficulty": ChallengeDifficulty.EASY,
        "target_count": 1,
        "base_xp_reward": 20,
        "icon": "keyboard",
        "is_active": True
    },
    {
        "title": "Knowledge Check",
        "description": "Complete 1 quiz to test your understanding",
        "challenge_type": ChallengeType.QUIZ,
        "difficulty": ChallengeDifficulty.EASY,
        "target_count": 1,
        "base_xp_reward": 25,
        "icon": "help-circle",
        "is_active": True
    },
    {
        "title": "Daily XP Goal",
        "description": "Earn 50 XP through any learning activity",
        "challenge_type": ChallengeType.XP_EARN,
        "difficulty": ChallengeDifficulty.EASY,
        "target_count": 50,
        "base_xp_reward": 30,
        "icon": "sparkles",
        "is_active": True
    },

    # =========================================================================
    # MEDIUM CHALLENGES - Moderate effort, good rewards
    # =========================================================================
    {
        "title": "Tutorial Explorer",
        "description": "Complete 3 tutorial steps to deepen your knowledge",
        "challenge_type": ChallengeType.TUTORIAL,
        "difficulty": ChallengeDifficulty.MEDIUM,
        "target_count": 3,
        "base_xp_reward": 60,
        "icon": "book-marked",
        "is_active": True
    },
    {
        "title": "Typing Practice",
        "description": "Play 3 typing games to improve your speed",
        "challenge_type": ChallengeType.TYPING_GAME,
        "difficulty": ChallengeDifficulty.MEDIUM,
        "target_count": 3,
        "base_xp_reward": 50,
        "icon": "type",
        "is_active": True
    },
    {
        "title": "Quiz Master",
        "description": "Complete 2 quizzes to reinforce your learning",
        "challenge_type": ChallengeType.QUIZ,
        "difficulty": ChallengeDifficulty.MEDIUM,
        "target_count": 2,
        "base_xp_reward": 55,
        "icon": "check-circle",
        "is_active": True
    },
    {
        "title": "Course Progress",
        "description": "Complete 2 course sections",
        "challenge_type": ChallengeType.COURSE_SECTION,
        "difficulty": ChallengeDifficulty.MEDIUM,
        "target_count": 2,
        "base_xp_reward": 65,
        "icon": "graduation-cap",
        "is_active": True
    },
    {
        "title": "XP Hunter",
        "description": "Earn 150 XP through any learning activity",
        "challenge_type": ChallengeType.XP_EARN,
        "difficulty": ChallengeDifficulty.MEDIUM,
        "target_count": 150,
        "base_xp_reward": 60,
        "icon": "target",
        "is_active": True
    },

    # =========================================================================
    # HARD CHALLENGES - Significant effort, great rewards
    # =========================================================================
    {
        "title": "Tutorial Champion",
        "description": "Complete 5 tutorial steps - show your dedication!",
        "challenge_type": ChallengeType.TUTORIAL,
        "difficulty": ChallengeDifficulty.HARD,
        "target_count": 5,
        "base_xp_reward": 100,
        "icon": "trophy",
        "is_active": True
    },
    {
        "title": "Typing Marathon",
        "description": "Play 5 typing games to master your keyboard skills",
        "challenge_type": ChallengeType.TYPING_GAME,
        "difficulty": ChallengeDifficulty.HARD,
        "target_count": 5,
        "base_xp_reward": 85,
        "icon": "flame",
        "is_active": True
    },
    {
        "title": "Speed Demon",
        "description": "Achieve 60 WPM in a typing game",
        "challenge_type": ChallengeType.TYPING_WPM,
        "difficulty": ChallengeDifficulty.HARD,
        "target_count": 60,
        "base_xp_reward": 100,
        "icon": "zap",
        "is_active": True
    },
    {
        "title": "Quiz Conqueror",
        "description": "Complete 4 quizzes to prove your knowledge",
        "challenge_type": ChallengeType.QUIZ,
        "difficulty": ChallengeDifficulty.HARD,
        "target_count": 4,
        "base_xp_reward": 90,
        "icon": "award",
        "is_active": True
    },
    {
        "title": "Course Dedication",
        "description": "Complete 4 course sections in a single day",
        "challenge_type": ChallengeType.COURSE_SECTION,
        "difficulty": ChallengeDifficulty.HARD,
        "target_count": 4,
        "base_xp_reward": 110,
        "icon": "star",
        "is_active": True
    },
    {
        "title": "XP Legend",
        "description": "Earn 300 XP through any learning activity - impressive!",
        "challenge_type": ChallengeType.XP_EARN,
        "difficulty": ChallengeDifficulty.HARD,
        "target_count": 300,
        "base_xp_reward": 100,
        "icon": "crown",
        "is_active": True
    },
]


def seed_challenge_templates(db: Session) -> dict:
    """
    Seed challenge templates into the database.
    Uses upsert pattern - updates existing templates or creates new ones.

    Returns:
        dict with counts of created and updated templates
    """
    created = 0
    updated = 0

    for template_data in CHALLENGE_TEMPLATES:
        # Try to find existing template by title and type
        existing = db.query(DailyChallengeTemplate).filter(
            DailyChallengeTemplate.title == template_data["title"],
            DailyChallengeTemplate.challenge_type == template_data["challenge_type"]
        ).first()

        if existing:
            # Update existing template
            for key, value in template_data.items():
                setattr(existing, key, value)
            updated += 1
            print(f"  Updated: {template_data['title']} ({template_data['difficulty'].value})")
        else:
            # Create new template with UUID
            template = DailyChallengeTemplate(
                id=str(uuid.uuid4()),
                **template_data
            )
            db.add(template)
            created += 1
            print(f"  Created: {template_data['title']} ({template_data['difficulty'].value})")

    db.commit()

    # Summary by difficulty
    difficulties = {}
    for t in CHALLENGE_TEMPLATES:
        diff = t["difficulty"].value
        difficulties[diff] = difficulties.get(diff, 0) + 1

    return {
        "created": created,
        "updated": updated,
        "total": len(CHALLENGE_TEMPLATES),
        "by_difficulty": difficulties
    }


def run_seed():
    """
    Run the challenge template seed script.
    Usage: python -m app.plugins.shared.seed_challenges
    """
    db = SessionLocal()

    try:
        print("Seeding daily challenge templates...")
        print("-" * 40)

        result = seed_challenge_templates(db)

        print("-" * 40)
        print(f"\nSeed complete!")
        print(f"  Created: {result['created']} templates")
        print(f"  Updated: {result['updated']} templates")
        print(f"\nBy difficulty:")
        for diff, count in result['by_difficulty'].items():
            print(f"  - {diff}: {count}")

        print("\nNote: Run the challenge generation scheduler to create")
        print("today's challenges from these templates.")

    except Exception as e:
        print(f"\nError seeding challenge templates: {e}")
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    run_seed()
