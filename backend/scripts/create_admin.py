"""
BlogCMS - Create Admin User Script
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from sqlalchemy.orm import Session
from app.core.database import engine, Base, SessionLocal
from app.core.security import get_password_hash
from app.core.config import settings
from app.users.models import User, UserRole

def create_admin_user():
    print("\n" + "="*60)
    print("BlogCMS - Admin User Creation Script")
    print("="*60 + "\n")

    Base.metadata.create_all(bind=engine)
    print("[OK] Database tables created!\n")

    db: Session = SessionLocal()

    try:
        admin_email = settings.ADMIN_EMAIL
        admin_password = settings.ADMIN_PASSWORD

        existing_admin = db.query(User).filter(User.email == admin_email).first()

        if existing_admin:
            # Update password if user exists
            existing_admin.hashed_password = get_password_hash(admin_password)
            db.commit()
            print(f"[OK] Admin user updated: {admin_email}")
            print(f"Password: {admin_password}")
            print("\n[WARNING] CHANGE THIS PASSWORD AFTER FIRST LOGIN!\n")
            return
        admin_user = User(
            email=admin_email,
            username="admin",
            hashed_password=get_password_hash(admin_password),
            first_name="Admin",
            last_name="User",
            role=UserRole.ADMIN,
            is_active=True,
            is_verified=True,
            can_write_blog=True
        )

        db.add(admin_user)
        db.commit()

        print("[SUCCESS] ADMIN USER CREATED!")
        print(f"Email: {admin_email}")
        print(f"Password: {admin_password}")
        print("\n[WARNING] CHANGE THIS PASSWORD AFTER FIRST LOGIN!\n")

    except Exception as e:
        print(f"[ERROR] {str(e)}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    create_admin_user()
