#!/usr/bin/env python3
"""
Seed sample content for FastReactCMS
Creates a professional welcome blog post with proper formatting
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from sqlalchemy.orm import Session
from app.core.database import engine, SessionLocal
from app.api.v1.services.blog.models import BlogPost, BlogTag, BlogCategory
from app.users.models import User, UserRole
from datetime import datetime


def seed_sample_content():
    """Create sample welcome blog post"""
    db: Session = SessionLocal()

    try:
        # Get any admin user
        admin = db.query(User).filter(User.role == UserRole.ADMIN).first()
        if not admin:
            print("[ERROR] Admin user not found. Run create_admin.py first.")
            return

        print(f"[INFO] Using admin user: {admin.email}")

        # Delete existing test posts
        test_posts = db.query(BlogPost).filter(
            BlogPost.title.in_(["test", "test2", "test4", "treat", "t"])
        ).all()
        for post in test_posts:
            db.delete(post)

        print(f"[CLEANUP] Deleted {len(test_posts)} test blog posts")

        # Create or get "Getting Started" category
        category = db.query(BlogCategory).filter(BlogCategory.slug == "getting-started").first()
        if not category:
            category = BlogCategory(
                name="Getting Started",
                slug="getting-started",
                description="Everything you need to get started with FastReactCMS",
                color="#3B82F6",
                icon="🚀",
                display_order=1
            )
            db.add(category)
            db.flush()

        # Create or get tags
        tag_data = [
            {"name": "Tutorial", "slug": "tutorial", "color": "#10B981"},
            {"name": "Documentation", "slug": "documentation", "color": "#6366F1"},
            {"name": "FastAPI", "slug": "fastapi", "color": "#EF4444"},
            {"name": "React", "slug": "react", "color": "#06B6D4"},
        ]

        tags = []
        for tag_info in tag_data:
            tag = db.query(BlogTag).filter(BlogTag.slug == tag_info["slug"]).first()
            if not tag:
                tag = BlogTag(**tag_info)
                db.add(tag)
                db.flush()
            tags.append(tag)

        # Create welcome blog post
        welcome_post_content = """
# Welcome to FastReactCMS!

We're thrilled to have you here. FastReactCMS is a modern, open-source blog platform built for developers who want to ship fast without sacrificing control.

## What is FastReactCMS?

FastReactCMS is a production-ready blogging platform that combines the best of modern web development:

- **React 18 + TypeScript** for a lightning-fast, type-safe frontend
- **FastAPI** for a blazing-fast Python backend
- **PostgreSQL** for reliable, scalable data storage
- **Built-in SEO** with meta tags, RSS feeds, and sitemaps
- **Dynamic Pages** using a modular block system
- **Theme Customization** with real-time color and typography controls

## Why FastReactCMS?

### 🎯 Developer-First Design
No bloat. No plugins marketplace. No premium paywalls. Just clean, maintainable code that you can understand and extend.

### ⚡ Lightning Fast
Vite builds, optimized queries, and smart caching mean your blog loads in milliseconds, not seconds.

### 🔒 Security Built-In
JWT authentication, CSRF protection, HTTP-only cookies, and secure headers come standard—not as afterthoughts.

### 📱 Mobile-First
Beautiful, responsive design that works flawlessly on every device from day one.

### 🌙 Dark Mode Everywhere
A stunning dark theme that extends across the entire platform, including the admin panel.

### 🎨 Fully Customizable
Change colors, fonts, layouts, and navigation without touching code. Or dive in and make it truly yours.

## Quick Start

Getting started with FastReactCMS is simple:

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/fastreactcms.git
cd fastreactcms
```

### 2. Backend Setup
```bash
cd Backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\\Scripts\\activate
pip install -r requirements.txt
alembic upgrade head
python scripts/create_admin.py
python scripts/seed_sample_content.py
```

### 3. Frontend Setup
```bash
cd Frontend
npm install
npm run dev
```

### 4. Start Building!
Visit `http://localhost:5173` and log in with your admin credentials. Start creating content, customizing themes, and building your blog!

## Key Features

### 📝 Rich Blog Editor
A powerful, intuitive editor with markdown support, image uploads, and SEO optimization built-in.

### 🎨 Dynamic Page Builder
Build custom pages using modular content blocks—no code required.

### 🔍 SEO Optimized
Automatic sitemap generation, RSS feeds, meta tag management, and schema markup.

### 👤 User Management
Role-based access control with admin, author, and viewer permissions.

### 📊 Analytics Ready
Google Analytics and AdSense integration built-in.

### 🔗 Navigation Manager
Create multi-level dropdown menus with an easy-to-use interface.

## What's Next?

Explore the admin panel at `/admin` to:

- **Create your first blog post** with rich formatting and media
- **Customize your theme** with colors and typography
- **Build custom pages** using the dynamic page builder
- **Configure navigation** menus for your site
- **Set up SEO defaults** for better search rankings

## Documentation

Check out our comprehensive guides:

- [Installation Guide](/pages/installation) - Detailed setup instructions
- [User Guide](/pages/user-guide) - Learn how to use all features
- [Developer Guide](/pages/developer-guide) - Extend and customize
- [API Documentation](/docs) - FastAPI interactive docs

## Contributing

FastReactCMS is open source! We welcome contributions:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

See our [Contributing Guide](/pages/contributing) for details.

## Support

Need help? We've got you covered:

- **GitHub Issues** - Report bugs or request features
- **Discussions** - Ask questions and share ideas
- **Documentation** - Comprehensive guides and tutorials

## License

FastReactCMS is released under the MIT License. Use it for personal projects, commercial work, or anything in between.

---

**Ready to build something amazing?** Head to the [admin panel](/admin) and start creating!

Happy blogging!
"""

        welcome_post = BlogPost(
            title="Welcome to FastReactCMS",
            slug="welcome-to-fastreactcms",
            content=welcome_post_content,
            excerpt="Discover FastReactCMS: a modern, open-source blog platform built with React and FastAPI. Learn what makes it special and how to get started.",
            meta_title="FastReactCMS - Modern Blog Platform for Developers",
            meta_description="FastReactCMS is a production-ready blogging platform combining React 18, FastAPI, and PostgreSQL. Open source, lightning fast, and developer-friendly.",
            meta_keywords="fastreactcms, blog platform, react, fastapi, cms, open source, blog, content management",
            published=True,
            is_featured=True,
            allow_comments=True,
            author_id=admin.id,
            view_count=0,
            read_time_minutes=5,
            published_at=datetime.utcnow(),
            categories=[category],
            tags=tags
        )

        db.add(welcome_post)
        db.commit()
        db.refresh(welcome_post)

        print("[SUCCESS] Sample content created successfully!")
        print(f"[POST] Blog post: '{welcome_post.title}'")
        print(f"[CATEGORY] {category.name}")
        print(f"[TAGS] {', '.join([tag.name for tag in tags])}")
        print(f"\n[VIEW] http://localhost:5173/blog/{welcome_post.slug}")

    except Exception as e:
        print(f"[ERROR] Error seeding sample content: {str(e)}")
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    print("[START] Seeding sample content for FastReactCMS...")
    seed_sample_content()
