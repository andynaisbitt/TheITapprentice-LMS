# Backend/scripts/seed_pages.py
"""Seed essential dynamic pages"""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from sqlalchemy.orm import Session
from app.core.database import SessionLocal
from app.api.v1.services.pages.models import Page
from app.users.models import User  # Import User to resolve relationship


def seed_pages():
    """Create essential pages (About, Contact, Privacy, Terms)"""
    db: Session = SessionLocal()

    try:
        # Delete existing pages to allow re-seeding
        existing_count = db.query(Page).count()
        if existing_count > 0:
            print(f"Deleting {existing_count} existing pages...")
            db.query(Page).delete()
            db.commit()

        pages_data = [
            {
                "slug": "about",
                "title": "About",
                "meta_title": "About BlogCMS",
                "meta_description": "Learn about BlogCMS - the blog platform that doesn't suck",
                "published": True,
                "blocks": [
                    {
                        "type": "hero",
                        "data": {
                            "title": "BlogCMS",
                            "subtitle": "The blog platform that doesn't suck",
                            "badge": "Open Source • Developer First • Lightning Fast",
                            "gradientText": True,
                            "gradientBackground": True
                        }
                    },
                    {
                        "type": "text",
                        "data": {
                            "content": """Tired of WordPress bloat? Sick of fighting with page builders? **We feel you.**

BlogCMS is a modern, no-BS blog platform built for developers who want to ship fast without sacrificing control. React + FastAPI + PostgreSQL. That's it. No plugins, no marketplace chaos, no "premium" paywalls.""",
                            "alignment": "left",
                            "maxWidth": "lg"
                        }
                    },
                    {
                        "type": "featureGrid",
                        "data": {
                            "title": "Built Different",
                            "titleIcon": "⚡",
                            "columns": 3,
                            "features": [
                                {"icon": "🎨", "title": "Dynamic Pages", "description": "Modular block system for building custom pages without code"},
                                {"icon": "🚀", "title": "Lightning Fast", "description": "Vite builds, optimized queries, sub-second page loads"},
                                {"icon": "🔒", "title": "Actually Secure", "description": "JWT auth, CSRF protection, HTTP-only cookies by default"},
                                {"icon": "📱", "title": "Mobile First", "description": "Responsive design that works on every device"},
                                {"icon": "🌙", "title": "Dark Mode", "description": "Beautiful dark theme throughout the entire platform"},
                                {"icon": "📊", "title": "SEO Ready", "description": "Meta tags, RSS feeds, sitemaps - all built in"},
                                {"icon": "🖼️", "title": "Media Magic", "description": "Image upload, optimization, and management made easy"},
                                {"icon": "⚙️", "title": "Developer DX", "description": "TypeScript, type safety, clean architecture, easy to extend"},
                                {"icon": "🎯", "title": "No Bloat", "description": "Only what you need. Nothing you don't. Period."}
                            ]
                        }
                    },
                    {
                        "type": "techStack",
                        "data": {
                            "title": "The Stack",
                            "titleIcon": "🛠️",
                            "stacks": [
                                {
                                    "title": "Frontend",
                                    "icon": "⚛️",
                                    "color": "blue",
                                    "items": [
                                        {"icon": "•", "name": "React 18", "description": "+ TypeScript"},
                                        {"icon": "•", "name": "Vite", "description": "for dev & builds"},
                                        {"icon": "•", "name": "Tailwind CSS", "description": "for styling"},
                                        {"icon": "•", "name": "Framer Motion", "description": "for animations"}
                                    ]
                                },
                                {
                                    "title": "Backend",
                                    "icon": "🐍",
                                    "color": "green",
                                    "items": [
                                        {"icon": "•", "name": "FastAPI", "description": "Python framework"},
                                        {"icon": "•", "name": "PostgreSQL", "description": "database"},
                                        {"icon": "•", "name": "SQLAlchemy", "description": "ORM"},
                                        {"icon": "•", "name": "Alembic", "description": "migrations"}
                                    ]
                                }
                            ]
                        }
                    },
                    {
                        "type": "cta",
                        "data": {
                            "title": "Ready to ship?",
                            "description": "Fork it. Clone it. Make it yours. It's open source.",
                            "gradientColor": "blue-purple",
                            "primaryButton": {
                                "text": "Get In Touch",
                                "link": "/contact"
                            },
                            "secondaryButton": {
                                "text": "Try the Admin Panel",
                                "link": "/admin"
                            }
                        }
                    }
                ],
                "created_by": None
            },
            {
                "slug": "contact",
                "title": "Contact",
                "meta_title": "Contact Us",
                "meta_description": "Get in touch with us",
                "published": True,
                "blocks": [
                    {
                        "type": "hero",
                        "data": {
                            "title": "Get In Touch",
                            "subtitle": "We'd love to hear from you"
                        }
                    },
                    {
                        "type": "text",
                        "data": {
                            "content": """# Contact Us

Have questions, feedback, or want to contribute? We're here to help!

## Ways to Reach Us

- **Email**: contact@blogcms.dev
- **GitHub**: Open an issue or pull request
- **Twitter**: @blogcms

We typically respond within 24-48 hours.""",
                            "alignment": "left",
                            "maxWidth": "lg"
                        }
                    }
                ],
                "created_by": None
            },
            {
                "slug": "privacy",
                "title": "Privacy Policy",
                "meta_title": "Privacy Policy",
                "meta_description": "Our privacy policy and data handling practices",
                "published": True,
                "blocks": [
                    {
                        "type": "text",
                        "data": {
                            "content": """# Privacy Policy

Last updated: December 2024

## Information We Collect

We collect minimal information necessary to provide our services.

## How We Use Your Data

Your data is never sold or shared with third parties.

## Cookies

We use essential cookies for authentication and session management.

## Your Rights

You have the right to access, modify, or delete your data at any time.

## Contact

For privacy concerns, contact us at privacy@blogcms.dev""",
                            "alignment": "left",
                            "maxWidth": "lg"
                        }
                    }
                ],
                "created_by": None
            },
            {
                "slug": "terms",
                "title": "Terms of Service",
                "meta_title": "Terms of Service",
                "meta_description": "Terms and conditions for using BlogCMS",
                "published": True,
                "blocks": [
                    {
                        "type": "text",
                        "data": {
                            "content": """# Terms of Service

Last updated: December 2024

## Acceptance of Terms

By using BlogCMS, you agree to these terms.

## Use License

BlogCMS is open-source software licensed under MIT.

## User Conduct

Users must not abuse the platform or violate laws.

## Disclaimer

BlogCMS is provided "as is" without warranties.

## Changes to Terms

We may update these terms. Continued use constitutes acceptance.""",
                            "alignment": "left",
                            "maxWidth": "lg"
                        }
                    }
                ],
                "created_by": None
            }
        ]

        # Create pages
        for page_data in pages_data:
            page = Page(**page_data)
            db.add(page)

        db.commit()
        print(f"[SUCCESS] Successfully created {len(pages_data)} pages")
        print("   - about")
        print("   - contact")
        print("   - privacy")
        print("   - terms")

    except Exception as e:
        print(f"[ERROR] Error seeding pages: {e}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    print("Seeding essential pages...")
    seed_pages()
