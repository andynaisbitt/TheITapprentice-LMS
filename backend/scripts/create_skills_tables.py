"""
One-off script to create skills tables that were stamped but never actually created.
Run: python scripts/create_skills_tables.py
"""
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from app.core.database import SessionLocal
from sqlalchemy import text


def create_skills_tables():
    db = SessionLocal()

    # 1. Create enum
    try:
        db.execute(text("CREATE TYPE skillcategory AS ENUM ('technical', 'soft')"))
        db.commit()
        print("[OK] Created skillcategory enum")
    except Exception as e:
        db.rollback()
        if "already exists" in str(e):
            print("[SKIP] skillcategory enum already exists")
        else:
            print(f"[WARN] Enum: {e}")

    # 2. Create skills table
    try:
        db.execute(text("""
            CREATE TABLE skills (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL UNIQUE,
                slug VARCHAR(100) NOT NULL UNIQUE,
                description TEXT,
                icon VARCHAR(10),
                category skillcategory NOT NULL DEFAULT 'technical',
                display_order INTEGER NOT NULL DEFAULT 0,
                is_active BOOLEAN NOT NULL DEFAULT true,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """))
        db.execute(text("CREATE INDEX ix_skills_slug ON skills (slug)"))
        db.execute(text("CREATE INDEX ix_skills_category ON skills (category)"))
        db.execute(text("CREATE INDEX ix_skills_is_active ON skills (is_active)"))
        db.commit()
        print("[OK] Created skills table")
    except Exception as e:
        db.rollback()
        if "already exists" in str(e):
            print("[SKIP] skills table already exists")
        else:
            print(f"[ERROR] skills table: {e}")
            return

    # 3. Create user_skills table
    try:
        db.execute(text("""
            CREATE TABLE user_skills (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                skill_id INTEGER NOT NULL REFERENCES skills(id) ON DELETE CASCADE,
                current_xp INTEGER NOT NULL DEFAULT 0,
                current_level INTEGER NOT NULL DEFAULT 1,
                total_activities_completed INTEGER NOT NULL DEFAULT 0,
                last_activity_at TIMESTAMPTZ,
                level_10_achieved_at TIMESTAMPTZ,
                level_30_achieved_at TIMESTAMPTZ,
                level_50_achieved_at TIMESTAMPTZ,
                level_75_achieved_at TIMESTAMPTZ,
                level_99_achieved_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                CONSTRAINT uq_user_skill UNIQUE (user_id, skill_id)
            )
        """))
        db.execute(text("CREATE INDEX ix_user_skills_user_id ON user_skills (user_id)"))
        db.execute(text("CREATE INDEX ix_user_skills_skill_id ON user_skills (skill_id)"))
        db.execute(text("CREATE INDEX ix_user_skills_current_level ON user_skills (current_level)"))
        db.execute(text("CREATE INDEX ix_user_skills_current_xp ON user_skills (current_xp)"))
        db.commit()
        print("[OK] Created user_skills table")
    except Exception as e:
        db.rollback()
        if "already exists" in str(e):
            print("[SKIP] user_skills table already exists")
        else:
            print(f"[ERROR] user_skills table: {e}")

    # 4. Create skill_xp_logs table
    try:
        db.execute(text("""
            CREATE TABLE skill_xp_logs (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                skill_id INTEGER NOT NULL REFERENCES skills(id) ON DELETE CASCADE,
                xp_gained INTEGER NOT NULL,
                source_type VARCHAR(50) NOT NULL,
                source_id VARCHAR(100),
                source_metadata JSON,
                level_before INTEGER NOT NULL,
                level_after INTEGER NOT NULL,
                earned_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """))
        db.execute(text("CREATE INDEX ix_skill_xp_logs_user_id ON skill_xp_logs (user_id)"))
        db.execute(text("CREATE INDEX ix_skill_xp_logs_skill_id ON skill_xp_logs (skill_id)"))
        db.execute(text("CREATE INDEX ix_skill_xp_logs_source_type ON skill_xp_logs (source_type)"))
        db.execute(text("CREATE INDEX ix_skill_xp_logs_earned_at ON skill_xp_logs (earned_at)"))
        db.commit()
        print("[OK] Created skill_xp_logs table")
    except Exception as e:
        db.rollback()
        if "already exists" in str(e):
            print("[SKIP] skill_xp_logs table already exists")
        else:
            print(f"[ERROR] skill_xp_logs table: {e}")

    db.close()
    print("\nDone! Now run: python scripts/seed_all.py --skills --quizzes")


if __name__ == "__main__":
    create_skills_tables()
