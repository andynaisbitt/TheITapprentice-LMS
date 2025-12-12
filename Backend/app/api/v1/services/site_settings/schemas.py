# Backend/app/api/v1/services/site_settings/schemas.py
"""Site settings schemas"""
from pydantic import BaseModel, Field, field_validator, ConfigDict
from pydantic.alias_generators import to_camel
from typing import Optional
from datetime import datetime


class SiteSettingsBase(BaseModel):
    """Base site settings schema"""
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,  # Accept both camelCase and snake_case
    )

    # Analytics & Ads
    google_analytics_id: Optional[str] = Field(None, max_length=50)
    google_adsense_client_id: Optional[str] = Field(None, max_length=50)

    # SEO Defaults
    site_title: str = Field(default="FastReactCMS", max_length=100)
    site_tagline: Optional[str] = Field(None, max_length=200)
    site_url: str = Field(default="https://yourdomain.com", max_length=255)
    meta_description: str = Field(default="A modern blog platform", max_length=500)
    meta_keywords: Optional[str] = Field(None, max_length=500)
    og_image: Optional[str] = Field(None, max_length=255)

    # Homepage Hero
    hero_title: str = Field(default="Share Your Story", max_length=200)
    hero_subtitle: Optional[str] = Field(None, max_length=500)
    hero_badge_text: str = Field(default="Open Source", max_length=50)
    hero_cta_primary: str = Field(default="Explore Articles", max_length=100)
    hero_cta_secondary: str = Field(default="Learn More", max_length=100)

    # Homepage Stats (all optional - leave blank to hide stats section)
    stats_articles: Optional[str] = Field(None, max_length=20)
    stats_readers: Optional[str] = Field(None, max_length=20)
    stats_free: Optional[str] = Field(None, max_length=20)

    # Homepage Section Visibility
    show_hero: bool = Field(default=True)
    show_carousel: bool = Field(default=True)
    show_categories: bool = Field(default=True)
    show_recent_posts: bool = Field(default=True)

    # Homepage Content Limits
    carousel_limit: int = Field(default=5, ge=1, le=20)
    categories_limit: int = Field(default=6, ge=1, le=20)
    recent_posts_limit: int = Field(default=6, ge=1, le=50)

    # CTA Button URLs
    cta_primary_url: str = Field(default='/blog', max_length=255)
    cta_secondary_url: str = Field(default='/about', max_length=255)

    # Carousel Settings
    carousel_autoplay: bool = Field(default=True)
    carousel_interval: int = Field(default=7000, ge=2000, le=30000)
    carousel_transition: str = Field(default='crossfade', max_length=20)

    @field_validator('carousel_transition')
    @classmethod
    def validate_transition(cls, v: str) -> str:
        allowed = ['crossfade', 'slide', 'none']
        if v not in allowed:
            raise ValueError(f'Must be one of: {", ".join(allowed)}')
        return v

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

    # Favicon
    favicon_url: Optional[str] = Field(None, max_length=255)
    favicon_dark_url: Optional[str] = Field(None, max_length=255)

    # Branding
    show_powered_by: bool = Field(default=True)

    # Newsletter & Email
    newsletter_enabled: bool = Field(default=True)
    smtp_host: Optional[str] = Field(None, max_length=255)
    smtp_port: int = Field(default=587)
    smtp_username: Optional[str] = Field(None, max_length=255)
    smtp_password: Optional[str] = Field(None, max_length=255)
    smtp_use_tls: bool = Field(default=True)
    smtp_from_email: Optional[str] = Field(None, max_length=255)
    smtp_from_name: Optional[str] = Field(None, max_length=255)


class SiteSettingsUpdate(BaseModel):
    """Schema for updating site settings (all fields optional)"""
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,  # Accept both camelCase and snake_case
    )

    # Analytics & Ads
    google_analytics_id: Optional[str] = Field(None, max_length=50)
    google_adsense_client_id: Optional[str] = Field(None, max_length=50)

    # SEO Defaults
    site_title: Optional[str] = Field(None, max_length=100)
    site_tagline: Optional[str] = Field(None, max_length=200)
    site_url: Optional[str] = Field(None, max_length=255)
    meta_description: Optional[str] = Field(None, max_length=500)
    meta_keywords: Optional[str] = Field(None, max_length=500)
    og_image: Optional[str] = Field(None, max_length=255)

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

    # Homepage Section Visibility
    show_hero: Optional[bool] = Field(None)
    show_carousel: Optional[bool] = Field(None)
    show_categories: Optional[bool] = Field(None)
    show_recent_posts: Optional[bool] = Field(None)

    # Homepage Content Limits
    carousel_limit: Optional[int] = Field(None, ge=1, le=20)
    categories_limit: Optional[int] = Field(None, ge=1, le=20)
    recent_posts_limit: Optional[int] = Field(None, ge=1, le=50)

    # CTA Button URLs
    cta_primary_url: Optional[str] = Field(None, max_length=255)
    cta_secondary_url: Optional[str] = Field(None, max_length=255)

    # Carousel Settings
    carousel_autoplay: Optional[bool] = Field(None)
    carousel_interval: Optional[int] = Field(None, ge=2000, le=30000)
    carousel_transition: Optional[str] = Field(None, max_length=20)

    @field_validator('carousel_transition')
    @classmethod
    def validate_transition(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        allowed = ['crossfade', 'slide', 'none']
        if v not in allowed:
            raise ValueError(f'Must be one of: {", ".join(allowed)}')
        return v

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

    # Favicon
    favicon_url: Optional[str] = Field(None, max_length=255)
    favicon_dark_url: Optional[str] = Field(None, max_length=255)

    # Branding
    show_powered_by: Optional[bool] = Field(None)

    # Newsletter & Email
    newsletter_enabled: Optional[bool] = Field(None)
    smtp_host: Optional[str] = Field(None, max_length=255)
    smtp_port: Optional[int] = Field(None)
    smtp_username: Optional[str] = Field(None, max_length=255)
    smtp_password: Optional[str] = Field(None, max_length=255)
    smtp_use_tls: Optional[bool] = Field(None)
    smtp_from_email: Optional[str] = Field(None, max_length=255)
    smtp_from_name: Optional[str] = Field(None, max_length=255)


class SiteSettingsResponse(SiteSettingsBase):
    """Schema for site settings response"""
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,  # Accept both camelCase and snake_case
        from_attributes=True,  # ORM mode (was orm_mode in Pydantic v1)
    )

    id: int
    updated_at: Optional[datetime] = None
