# Backend/app/api/v1/services/site_settings/models.py
"""Site settings model for SEO, analytics, and site configuration"""
from sqlalchemy import Column, Integer, String, DateTime, Boolean, JSON
from sqlalchemy.sql import func
from app.core.database import Base


class SiteSettings(Base):
    """
    Global site settings (singleton table - only 1 row)

    Stores SEO defaults, analytics IDs, social media links, and site metadata
    """
    __tablename__ = "site_settings"

    id = Column(Integer, primary_key=True, default=1)  # Singleton

    # Analytics & Ads
    google_analytics_id = Column(String(50), nullable=True)
    google_adsense_client_id = Column(String(50), nullable=True)

    # SEO Defaults
    site_title = Column(String(100), default="FastReactCMS")
    site_tagline = Column(String(200), nullable=True)
    site_url = Column(String(255), default="https://yourdomain.com")
    meta_description = Column(String(500), default="A modern blog platform")
    meta_keywords = Column(String(500), nullable=True)
    og_image = Column(String(255), nullable=True)  # Open Graph image for social sharing

    # Homepage Hero
    hero_title = Column(String(200), default="Share Your Story")
    hero_subtitle = Column(String(500), nullable=True)
    hero_badge_text = Column(String(50), default="Open Source")
    hero_cta_primary = Column(String(100), default="Explore Articles")
    hero_cta_secondary = Column(String(100), default="Learn More")

    # Homepage Stats (all optional - leave blank to hide)
    stats_articles = Column(String(20), nullable=True)
    stats_readers = Column(String(20), nullable=True)
    stats_free = Column(String(20), nullable=True)

    # Homepage Section Visibility
    show_hero = Column(Boolean, default=True, nullable=False)
    show_carousel = Column(Boolean, default=True, nullable=False)
    show_categories = Column(Boolean, default=True, nullable=False)
    show_recent_posts = Column(Boolean, default=True, nullable=False)

    # Homepage Content Limits
    carousel_limit = Column(Integer, default=5, nullable=False)
    categories_limit = Column(Integer, default=6, nullable=False)
    recent_posts_limit = Column(Integer, default=6, nullable=False)

    # CTA Button URLs
    cta_primary_url = Column(String(255), default='/blog', nullable=False)
    cta_secondary_url = Column(String(255), default='/about', nullable=False)

    # Carousel Settings
    carousel_autoplay = Column(Boolean, default=True, nullable=False)
    carousel_interval = Column(Integer, default=7000, nullable=False)
    carousel_transition = Column(String(20), default='crossfade', nullable=False)

    # Social Media
    twitter_handle = Column(String(100), nullable=True)
    facebook_url = Column(String(255), nullable=True)
    linkedin_url = Column(String(255), nullable=True)
    github_url = Column(String(255), nullable=True)

    # Contact
    contact_email = Column(String(255), nullable=True)
    support_email = Column(String(255), nullable=True)

    # Logo
    logo_url = Column(String(255), nullable=True)
    logo_dark_url = Column(String(255), nullable=True)

    # Favicon
    favicon_url = Column(String(255), nullable=True)
    favicon_dark_url = Column(String(255), nullable=True)

    # Branding
    show_powered_by = Column(Boolean, default=True, nullable=True)

    # Newsletter & Email
    newsletter_enabled = Column(Boolean, default=True, nullable=True)
    smtp_host = Column(String(255), nullable=True)
    smtp_port = Column(Integer, default=587, nullable=True)
    smtp_username = Column(String(255), nullable=True)
    smtp_password = Column(String(255), nullable=True)
    smtp_use_tls = Column(Boolean, default=True, nullable=True)
    smtp_from_email = Column(String(255), nullable=True)
    smtp_from_name = Column(String(255), nullable=True)

    # Plugin Settings (JSON: {"tutorials": true, "courses": true, ...})
    plugins_enabled = Column(JSON, nullable=True, default=None)

    # LMS Navigation Settings
    show_lms_navigation = Column(Boolean, default=True, nullable=False)

    # LMS Homepage Section Visibility
    show_featured_courses = Column(Boolean, default=True, nullable=False)
    show_typing_challenge = Column(Boolean, default=True, nullable=False)
    show_quick_quiz = Column(Boolean, default=True, nullable=False)
    show_tutorial_paths = Column(Boolean, default=True, nullable=False)
    show_leaderboard_preview = Column(Boolean, default=True, nullable=False)
    show_daily_challenge_banner = Column(Boolean, default=True, nullable=False)
    show_homepage_stats = Column(Boolean, default=True, nullable=False)

    # LMS Widget Customization - Featured Courses
    featured_courses_title = Column(String(200), default="Featured Courses", nullable=False)
    featured_courses_subtitle = Column(String(500), default="Start your learning journey", nullable=True)
    featured_courses_limit = Column(Integer, default=4, nullable=False)

    # LMS Widget Customization - Typing Challenge
    typing_challenge_title = Column(String(200), default="Test Your Typing Speed", nullable=False)
    typing_challenge_show_stats = Column(Boolean, default=True, nullable=False)
    typing_challenge_show_pvp = Column(Boolean, default=True, nullable=False)

    # LMS Widget Customization - Quick Quiz
    quick_quiz_title = Column(String(200), default="Quick Quiz", nullable=False)
    quick_quiz_subtitle = Column(String(500), default="Test your knowledge", nullable=True)
    quick_quiz_limit = Column(Integer, default=4, nullable=False)

    # LMS Widget Customization - Tutorial Paths
    tutorial_paths_title = Column(String(200), default="Learning Paths", nullable=False)
    tutorial_paths_subtitle = Column(String(500), default="Structured tutorials to guide your learning", nullable=True)
    tutorial_paths_categories_limit = Column(Integer, default=4, nullable=False)

    # LMS Widget Customization - Leaderboard
    leaderboard_title = Column(String(200), default="Top Learners", nullable=False)
    leaderboard_limit = Column(Integer, default=5, nullable=False)
    leaderboard_show_streak = Column(Boolean, default=True, nullable=False)

    # LMS Widget Customization - Daily Challenges
    daily_challenge_guest_message = Column(String(500), default="Sign up to track your progress and earn rewards!", nullable=True)
    daily_challenge_show_streak = Column(Boolean, default=True, nullable=False)

    # LMS Widget Customization - Homepage Stats
    homepage_stats_title = Column(String(200), default="Community Progress", nullable=False)
    homepage_stats_show_active_today = Column(Boolean, default=True, nullable=False)

    # Homepage Section Titles (for carousel, categories, recent posts)
    carousel_title = Column(String(200), default="Featured Articles", nullable=False)
    carousel_subtitle = Column(String(500), default="Hand-picked posts showcasing our best content", nullable=True)
    categories_title = Column(String(200), default="Explore by Category", nullable=False)
    categories_subtitle = Column(String(500), default="Dive into topics that interest you", nullable=True)
    recent_posts_title = Column(String(200), default="Latest Posts", nullable=False)
    recent_posts_subtitle = Column(String(500), default="Fresh content from our writers", nullable=True)

    # Homepage Section Order (JSON array of section IDs)
    homepage_section_order = Column(JSON, nullable=True, default=None)

    # Timestamps
    updated_at = Column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())

    def __repr__(self):
        return f"<SiteSettings {self.site_title}>"
