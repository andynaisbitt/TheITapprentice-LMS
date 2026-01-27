"""
One-off script to fix related_skills column type from ARRAY to JSON.
The v2_10 migration incorrectly created it as ARRAY(String) but the model expects JSON.
Run: python scripts/fix_related_skills_column.py
"""
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from app.core.database import SessionLocal
from sqlalchemy import text


def fix_column():
    db = SessionLocal()
    try:
        db.execute(text("ALTER TABLE quizzes DROP COLUMN related_skills"))
        db.execute(text("ALTER TABLE quizzes ADD COLUMN related_skills JSON DEFAULT '[]'"))
        db.commit()
        print("[OK] Fixed: related_skills column changed from ARRAY to JSON")
    except Exception as e:
        db.rollback()
        print(f"[ERROR] {e}")
    finally:
        db.close()


if __name__ == "__main__":
    fix_column()
