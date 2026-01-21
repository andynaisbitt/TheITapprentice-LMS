#!/usr/bin/env python3
"""
Fix the courselevel PostgreSQL enum to use lowercase values.
Run: python scripts/fix_course_enum.py
"""
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from sqlalchemy import text
from app.core.database import engine

def fix_enum():
    """Fix courselevel and coursestatus enum values from uppercase to lowercase"""
    with engine.connect() as conn:
        # Fix courselevel enum
        result = conn.execute(text("""
            SELECT enumlabel FROM pg_enum
            WHERE enumtypid = (SELECT oid FROM pg_type WHERE typname = 'courselevel')
            ORDER BY enumsortorder;
        """))
        current_values = [row[0] for row in result]
        print(f"Current courselevel enum values: {current_values}")

        if 'BEGINNER' in current_values:
            print("Fixing courselevel enum values to lowercase...")
            conn.execute(text("ALTER TYPE courselevel RENAME VALUE 'BEGINNER' TO 'beginner';"))
            conn.execute(text("ALTER TYPE courselevel RENAME VALUE 'INTERMEDIATE' TO 'intermediate';"))
            conn.execute(text("ALTER TYPE courselevel RENAME VALUE 'ADVANCED' TO 'advanced';"))
            conn.commit()
            print("courselevel enum fixed!")
        else:
            print("courselevel enum already lowercase.")

        # Fix coursestatus enum
        result = conn.execute(text("""
            SELECT enumlabel FROM pg_enum
            WHERE enumtypid = (SELECT oid FROM pg_type WHERE typname = 'coursestatus')
            ORDER BY enumsortorder;
        """))
        current_values = [row[0] for row in result]
        print(f"Current coursestatus enum values: {current_values}")

        if 'DRAFT' in current_values:
            print("Fixing coursestatus enum values to lowercase...")
            conn.execute(text("ALTER TYPE coursestatus RENAME VALUE 'DRAFT' TO 'draft';"))
            conn.execute(text("ALTER TYPE coursestatus RENAME VALUE 'PUBLISHED' TO 'published';"))
            conn.execute(text("ALTER TYPE coursestatus RENAME VALUE 'ARCHIVED' TO 'archived';"))
            conn.commit()
            print("coursestatus enum fixed!")
        else:
            print("coursestatus enum already lowercase.")

        print("\nAll enums fixed!")

if __name__ == "__main__":
    fix_enum()
