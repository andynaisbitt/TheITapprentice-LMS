# Backend/scripts/seed_navigation_theme.py
"""Seed navigation menu and theme settings"""
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from sqlalchemy.orm import Session
from app.core.database import SessionLocal
from app.api.v1.services.navigation.models import MenuItem
from app.api.v1.services.theme.models import ThemeSettings


def seed_navigation():
    """Create default navigation menu items"""
    db: Session = SessionLocal()

    try:
        # Check if menu items already exist
        existing_count = db.query(MenuItem).count()
        if existing_count > 0:
            print(f"Navigation items already exist ({existing_count} found). Skipping seed.")
            return

        menu_items = [
            # Header navigation
            {"label": "Home", "url": "/", "order": 1, "show_in_header": True, "show_in_footer": False, "visible": True},
            {"label": "Blog", "url": "/blog", "order": 2, "show_in_header": True, "show_in_footer": False, "visible": True},
            {"label": "About", "url": "/about", "order": 3, "show_in_header": True, "show_in_footer": True, "visible": True},
            {"label": "Contact", "url": "/contact", "order": 4, "show_in_header": True, "show_in_footer": True, "visible": True},

            # Footer only
            {"label": "Privacy Policy", "url": "/privacy", "order": 5, "show_in_header": False, "show_in_footer": True, "visible": True},
            {"label": "Terms of Service", "url": "/terms", "order": 6, "show_in_header": False, "show_in_footer": True, "visible": True},
        ]

        for item_data in menu_items:
            item = MenuItem(**item_data)
            db.add(item)

        db.commit()
        print(f"[SUCCESS] Successfully created {len(menu_items)} navigation items")
        for item in menu_items:
            print(f"   - {item['label']} ({item['url']})")

    except Exception as e:
        print(f"[ERROR] Error seeding navigation: {e}")
        db.rollback()
    finally:
        db.close()


def seed_theme():
    """Create default theme settings"""
    db: Session = SessionLocal()

    try:
        # Check if theme settings already exist
        existing = db.query(ThemeSettings).first()
        if existing:
            print("Theme settings already exist. Skipping seed.")
            return

        theme = ThemeSettings(
            id=1,  # Singleton
            site_name="BlogCMS",
            tagline="The blog platform that doesn't suck",
            primary_color="#3B82F6",  # Blue-500
            secondary_color="#8B5CF6",  # Purple-500
            accent_color="#EC4899",  # Pink-500
            background_light="#FFFFFF",
            background_dark="#111827",
            text_light="#111827",
            text_dark="#F9FAFB",
            font_family="Inter, system-ui, sans-serif",
            heading_font="Inter, system-ui, sans-serif",
            font_size_base="16px",
            container_width="1280px",
            border_radius="0.5rem",
        )

        db.add(theme)
        db.commit()
        print("[SUCCESS] Successfully created theme settings")
        print(f"   - Site: {theme.site_name}")
        print(f"   - Primary: {theme.primary_color}")
        print(f"   - Secondary: {theme.secondary_color}")

    except Exception as e:
        print(f"[ERROR] Error seeding theme: {e}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    print("Seeding navigation and theme settings...")
    print()
    seed_navigation()
    print()
    seed_theme()
