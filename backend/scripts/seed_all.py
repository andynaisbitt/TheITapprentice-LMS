#!/usr/bin/env python3
"""
Master Seed Script for BlogCMS

Orchestrates all seed scripts to populate the database with initial data.
Run with: python scripts/seed_all.py [--all | --skills | --word-lists | --courses | --tutorials | --quizzes | --achievements]

Examples:
    python scripts/seed_all.py --all              # Run all seeds
    python scripts/seed_all.py --skills --courses # Run specific seeds
"""
import argparse
import sys
import logging
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from app.core.database import SessionLocal

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def seed_skills(db):
    """Seed 12 IT skills."""
    from app.plugins.skills.seed import seed_skills as _seed_skills
    result = _seed_skills(db)
    print(f"  Skills: {result['created']} created, {result['updated']} updated, {result['skipped']} skipped")
    return result


def seed_word_lists():
    """Seed 10 typing word lists. Uses its own session."""
    # This script manages its own session
    from scripts.seed_word_lists import seed_word_lists as _seed_word_lists
    _seed_word_lists()
    print("  Word lists seeded successfully")


def seed_courses(db):
    """Seed sample courses with modules and sections."""
    from app.plugins.courses.seed_data import create_sample_courses
    courses = create_sample_courses(db)
    print(f"  Courses: {len(courses)} courses created/updated")
    return courses


def seed_tutorials():
    """Seed tutorials with categories and steps. Uses its own session."""
    from app.plugins.tutorials.seed_data import main as _seed_tutorials
    _seed_tutorials()
    print("  Tutorials seeded successfully")


def seed_quizzes(db):
    """Seed beginner quizzes."""
    try:
        from app.plugins.quizzes.seed_data import seed_quizzes as _seed_quizzes
        result = _seed_quizzes(db)
        print(f"  Quizzes: {result.get('created', 0)} created, {result.get('updated', 0)} updated")
        return result
    except ImportError:
        print("  Quizzes: seed_data.py not found (Phase 2 not implemented yet)")
        return None


def seed_achievements(db):
    """Seed achievement definitions."""
    try:
        from app.plugins.shared.seed_achievements import seed_achievements as _seed_achievements
        result = _seed_achievements(db)
        print(f"  Achievements: {result.get('created', 0)} created, {result.get('updated', 0)} updated")
        return result
    except ImportError:
        print("  Achievements: seed_achievements.py not found (Phase 3 not implemented yet)")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Seed BlogCMS database with initial data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/seed_all.py --all                    # Run all seeds
  python scripts/seed_all.py --skills                 # Seed only skills
  python scripts/seed_all.py --skills --word-lists    # Seed skills and word lists
  python scripts/seed_all.py --courses --tutorials    # Seed courses and tutorials
        """
    )
    parser.add_argument("--all", action="store_true", help="Run all seed scripts")
    parser.add_argument("--skills", action="store_true", help="Seed 12 IT skills")
    parser.add_argument("--word-lists", action="store_true", help="Seed typing word lists")
    parser.add_argument("--courses", action="store_true", help="Seed sample courses")
    parser.add_argument("--tutorials", action="store_true", help="Seed tutorials and categories")
    parser.add_argument("--quizzes", action="store_true", help="Seed beginner quizzes")
    parser.add_argument("--achievements", action="store_true", help="Seed achievement definitions")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be seeded without making changes")

    args = parser.parse_args()

    # If no args provided, show help
    if not any([args.all, args.skills, args.word_lists, args.courses,
                args.tutorials, args.quizzes, args.achievements]):
        parser.print_help()
        print("\nNo seed options specified. Use --all to run all seeds.")
        return

    if args.dry_run:
        print("\n" + "=" * 50)
        print("DRY RUN - No changes will be made")
        print("=" * 50)
        if args.all or args.skills:
            print("Would seed: Skills (12 IT skills)")
        if args.all or args.word_lists:
            print("Would seed: Word Lists (10 typing word lists)")
        if args.all or args.courses:
            print("Would seed: Courses (2 sample courses)")
        if args.all or args.tutorials:
            print("Would seed: Tutorials (3 tutorials + 4 categories)")
        if args.all or args.quizzes:
            print("Would seed: Quizzes (5 beginner quizzes)")
        if args.all or args.achievements:
            print("Would seed: Achievements (16 achievement definitions)")
        return

    print("\n" + "=" * 50)
    print("BlogCMS Database Seeder")
    print("=" * 50 + "\n")

    db = SessionLocal()
    results = {"success": [], "failed": [], "skipped": []}

    try:
        # Skills - uses shared session
        if args.all or args.skills:
            print("[1/6] Seeding Skills...")
            try:
                seed_skills(db)
                db.commit()
                results["success"].append("skills")
            except Exception as e:
                db.rollback()
                print(f"  ERROR: {e}")
                results["failed"].append("skills")

        # Word Lists - uses its own session
        if args.all or args.word_lists:
            print("[2/6] Seeding Word Lists...")
            try:
                seed_word_lists()
                results["success"].append("word_lists")
            except Exception as e:
                print(f"  ERROR: {e}")
                results["failed"].append("word_lists")

        # Courses - uses shared session
        if args.all or args.courses:
            print("[3/6] Seeding Courses...")
            try:
                seed_courses(db)
                db.commit()
                results["success"].append("courses")
            except Exception as e:
                db.rollback()
                print(f"  ERROR: {e}")
                results["failed"].append("courses")

        # Tutorials - uses its own session
        if args.all or args.tutorials:
            print("[4/6] Seeding Tutorials...")
            try:
                seed_tutorials()
                results["success"].append("tutorials")
            except Exception as e:
                print(f"  ERROR: {e}")
                results["failed"].append("tutorials")

        # Quizzes - uses shared session (Phase 2)
        if args.all or args.quizzes:
            print("[5/6] Seeding Quizzes...")
            try:
                result = seed_quizzes(db)
                if result is not None:
                    db.commit()
                    results["success"].append("quizzes")
                else:
                    results["skipped"].append("quizzes")
            except Exception as e:
                db.rollback()
                print(f"  ERROR: {e}")
                results["failed"].append("quizzes")

        # Achievements - uses shared session (Phase 3)
        if args.all or args.achievements:
            print("[6/6] Seeding Achievements...")
            try:
                result = seed_achievements(db)
                if result is not None:
                    db.commit()
                    results["success"].append("achievements")
                else:
                    results["skipped"].append("achievements")
            except Exception as e:
                db.rollback()
                print(f"  ERROR: {e}")
                results["failed"].append("achievements")

    except Exception as e:
        db.rollback()
        print(f"\nDatabase error: {e}")
        logger.exception("Database error during seeding")
    finally:
        db.close()

    # Print summary
    print("\n" + "=" * 50)
    print("SEED SUMMARY")
    print("=" * 50)

    if results["success"]:
        print(f"SUCCESS: {', '.join(results['success'])}")
    if results["skipped"]:
        print(f"SKIPPED: {', '.join(results['skipped'])} (not yet implemented)")
    if results["failed"]:
        print(f"FAILED:  {', '.join(results['failed'])}")

    if not results["failed"]:
        print("\nAll seeds completed successfully!")
    else:
        print(f"\n{len(results['failed'])} seed(s) failed. Check logs for details.")
        sys.exit(1)


if __name__ == "__main__":
    main()
