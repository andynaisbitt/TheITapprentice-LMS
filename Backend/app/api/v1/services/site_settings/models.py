# Backend/app/api/v1/services/site_settings/models.py
"""Site settings model for SEO, analytics, and site configuration"""
from sqlalchemy import Column, Integer, String, DateTime, Boolean
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

    # Homepage Hero
    hero_title = Column(String(200), default="Share Your Story")
    hero_subtitle = Column(String(500), nullable=True)
    hero_badge_text = Column(String(50), default="Open Source")
    hero_cta_primary = Column(String(100), default="Explore Articles")
    hero_cta_secondary = Column(String(100), default="Learn More")

    # Homepage Stats
    stats_articles = Column(String(20), nullable=True)
    stats_readers = Column(String(20), nullable=True)
    stats_free = Column(String(20), default="100% Free")

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

    # Branding
    show_powered_by = Column(Boolean, default=True, nullable=True)

    # Timestamps
    updated_at = Column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())

    def __repr__(self):
        return f"<SiteSettings {self.site_title}>"
