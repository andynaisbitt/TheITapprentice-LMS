"""Quick script to check users in database"""
from app.core.database import SessionLocal
from app.users.models import User
from app.auth.email_verification import EmailVerification  # Import to avoid relationship errors

db = SessionLocal()
try:
    users = db.query(User).all()
    print(f"Total users: {len(users)}")
    for user in users:
        print(f"- {user.email} (role={user.role}, is_admin={user.is_admin})")
finally:
    db.close()
