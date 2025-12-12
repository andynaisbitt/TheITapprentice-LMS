#!/usr/bin/env python
"""Fix alembic migration issue"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from sqlalchemy import text
from app.core.database import SessionLocal

db = SessionLocal()
try:
    db.execute(text("DELETE FROM alembic_version WHERE version_num = '386e06c4ba47'"))
    db.commit()
    print("Successfully removed migration entry")
except Exception as e:
    print(f"Error: {e}")
    db.rollback()
finally:
    db.close()
