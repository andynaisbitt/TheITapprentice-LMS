"""
BlogCMS - Seed Default Categories
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from app.core.database import SessionLocal
from app.api.v1.services.blog.crud import create_category
from app.api.v1.services.blog.schemas import BlogCategoryCreate


def seed_categories():
    print("\n" + "="*60)
    print("BlogCMS - Seed Default Categories")
    print("="*60 + "\n")

    db = SessionLocal()

    categories = [
        {
            "name": "Technology",
            "description": "Tech news, trends, and insights",
            "color": "#3B82F6",  # Blue
            "icon": "💻"
        },
        {
            "name": "Programming",
            "description": "Coding tutorials, tips, and best practices",
            "color": "#8B5CF6",  # Purple
            "icon": "👨‍💻"
        },
        {
            "name": "Web Development",
            "description": "Frontend, backend, and full-stack development",
            "color": "#10B981",  # Green
            "icon": "🌐"
        },
        {
            "name": "Security",
            "description": "Cybersecurity, privacy, and best practices",
            "color": "#EF4444",  # Red
            "icon": "🔒"
        },
        {
            "name": "DevOps",
            "description": "CI/CD, deployment, and infrastructure",
            "color": "#F59E0B",  # Orange
            "icon": "⚙️"
        },
        {
            "name": "Tutorials",
            "description": "Step-by-step guides and how-tos",
            "color": "#06B6D4",  # Cyan
            "icon": "📚"
        },
        {
            "name": "News",
            "description": "Latest tech news and updates",
            "color": "#EC4899",  # Pink
            "icon": "📰"
        },
    ]

    try:
        for cat_data in categories:
            category = BlogCategoryCreate(**cat_data)
            db_category = create_category(db, category)
            print(f"[OK] Created category: {cat_data['name']} ({db_category.slug})")

        print(f"\n[SUCCESS] Created {len(categories)} categories!")

    except Exception as e:
        print(f"[ERROR] {str(e)}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    seed_categories()
