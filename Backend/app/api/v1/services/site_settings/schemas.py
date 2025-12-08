# Backend/app/api/v1/services/site_settings/schemas.py
"""Site settings schemas"""
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class SiteSettingsBase(BaseModel):
    """Base site settings schema"""
    # Analytics & Ads
    google_analytics_id: Optional[str] = Field(None, max_length=50)
    google_adsense_client_id: Optional[str] = Field(None, max_length=50)

    # SEO Defaults
    site_title: str = Field(default="FastReactCMS", max_length=100)
    site_tagline: Optional[str] = Field(None, max_length=200)
    site_url: str = Field(default="https://yourdomain.com", max_length=255)
    meta_description: str = Field(default="A modern blog platform", max_length=500)
    meta_keywords: Optional[str] = Field(None, max_length=500)

    # Homepage Hero
    hero_title: str = Field(default="Share Your Story", max_length=200)
    hero_subtitle: Optional[str] = Field(None, max_length=500)
    hero_badge_text: str = Field(default="Open Source", max_length=50)
    hero_cta_primary: str = Field(default="Explore Articles", max_length=100)
    hero_cta_secondary: str = Field(default="Learn More", max_length=100)

    # Homepage Stats
    stats_articles: Optional[str] = Field(None, max_length=20)
    stats_readers: Optional[str] = Field(None, max_length=20)
    stats_free: str = Field(default="100% Free", max_length=20)

    # Social Media
    twitter_handle: Optional[str] = Field(None, max_length=100)
    facebook_url: Optional[str] = Field(None, max_length=255)
    linkedin_url: Optional[str] = Field(None, max_length=255)
    github_url: Optional[str] = Field(None, max_length=255)

    # Contact
    contact_email: Optional[str] = Field(None, max_length=255)
    support_email: Optional[str] = Field(None, max_length=255)

    # Logo
    logo_url: Optional[str] = Field(None, max_length=255)
    logo_dark_url: Optional[str] = Field(None, max_length=255)

    # Branding
    show_powered_by: bool = Field(default=True)


class SiteSettingsUpdate(BaseModel):
    """Schema for updating site settings (all fields optional)"""
    # Analytics & Ads
    google_analytics_id: Optional[str] = Field(None, max_length=50)
    google_adsense_client_id: Optional[str] = Field(None, max_length=50)

    # SEO Defaults
    site_title: Optional[str] = Field(None, max_length=100)
    site_tagline: Optional[str] = Field(None, max_length=200)
    site_url: Optional[str] = Field(None, max_length=255)
    meta_description: Optional[str] = Field(None, max_length=500)
    meta_keywords: Optional[str] = Field(None, max_length=500)

    # Homepage Hero
    hero_title: Optional[str] = Field(None, max_length=200)
    hero_subtitle: Optional[str] = Field(None, max_length=500)
    hero_badge_text: Optional[str] = Field(None, max_length=50)
    hero_cta_primary: Optional[str] = Field(None, max_length=100)
    hero_cta_secondary: Optional[str] = Field(None, max_length=100)

    # Homepage Stats
    stats_articles: Optional[str] = Field(None, max_length=20)
    stats_readers: Optional[str] = Field(None, max_length=20)
    stats_free: Optional[str] = Field(None, max_length=20)

    # Social Media
    twitter_handle: Optional[str] = Field(None, max_length=100)
    facebook_url: Optional[str] = Field(None, max_length=255)
    linkedin_url: Optional[str] = Field(None, max_length=255)
    github_url: Optional[str] = Field(None, max_length=255)

    # Contact
    contact_email: Optional[str] = Field(None, max_length=255)
    support_email: Optional[str] = Field(None, max_length=255)

    # Logo
    logo_url: Optional[str] = Field(None, max_length=255)
    logo_dark_url: Optional[str] = Field(None, max_length=255)

    # Branding
    show_powered_by: Optional[bool] = Field(None)


class SiteSettingsResponse(SiteSettingsBase):
    """Schema for site settings response"""
    id: int
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True
