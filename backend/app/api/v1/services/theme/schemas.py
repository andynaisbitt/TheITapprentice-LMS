# Backend/app/api/v1/services/theme/schemas.py
"""Theme settings schemas"""
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime


class ThemeSettingsBase(BaseModel):
    """Base theme settings schema"""
    primary_color: str = Field(default="#3B82F6", pattern="^#[0-9A-Fa-f]{6}$")
    secondary_color: str = Field(default="#8B5CF6", pattern="^#[0-9A-Fa-f]{6}$")
    accent_color: str = Field(default="#EC4899", pattern="^#[0-9A-Fa-f]{6}$")
    background_light: str = Field(default="#FFFFFF", pattern="^#[0-9A-Fa-f]{6}$")
    background_dark: str = Field(default="#111827", pattern="^#[0-9A-Fa-f]{6}$")
    text_light: str = Field(default="#111827", pattern="^#[0-9A-Fa-f]{6}$")
    text_dark: str = Field(default="#F9FAFB", pattern="^#[0-9A-Fa-f]{6}$")
    font_family: str = Field(default="Inter, system-ui, sans-serif", max_length=100)
    heading_font: str = Field(default="Inter, system-ui, sans-serif", max_length=100)
    font_size_base: str = Field(default="16px", max_length=10)
    container_width: str = Field(default="1280px", max_length=10)
    border_radius: str = Field(default="0.5rem", max_length=10)
    custom_css: Optional[str] = Field(None, max_length=10000)
    logo_url: Optional[str] = Field(None, max_length=255)
    logo_dark_url: Optional[str] = Field(None, max_length=255)
    site_name: str = Field(default="BlogCMS", max_length=100)
    site_url: str = Field(default="https://yourdomain.com", max_length=255)
    site_description: str = Field(default="Latest blog posts", max_length=500)
    tagline: Optional[str] = Field(None, max_length=200)
    advanced_settings: Optional[Dict[str, Any]] = Field(default_factory=dict)


class ThemeSettingsUpdate(BaseModel):
    """Schema for updating theme settings (all fields optional)"""
    primary_color: Optional[str] = Field(None, pattern="^#[0-9A-Fa-f]{6}$")
    secondary_color: Optional[str] = Field(None, pattern="^#[0-9A-Fa-f]{6}$")
    accent_color: Optional[str] = Field(None, pattern="^#[0-9A-Fa-f]{6}$")
    background_light: Optional[str] = Field(None, pattern="^#[0-9A-Fa-f]{6}$")
    background_dark: Optional[str] = Field(None, pattern="^#[0-9A-Fa-f]{6}$")
    text_light: Optional[str] = Field(None, pattern="^#[0-9A-Fa-f]{6}$")
    text_dark: Optional[str] = Field(None, pattern="^#[0-9A-Fa-f]{6}$")
    font_family: Optional[str] = Field(None, max_length=100)
    heading_font: Optional[str] = Field(None, max_length=100)
    font_size_base: Optional[str] = Field(None, max_length=10)
    container_width: Optional[str] = Field(None, max_length=10)
    border_radius: Optional[str] = Field(None, max_length=10)
    custom_css: Optional[str] = Field(None, max_length=10000)
    logo_url: Optional[str] = Field(None, max_length=255)
    logo_dark_url: Optional[str] = Field(None, max_length=255)
    site_name: Optional[str] = Field(None, max_length=100)
    site_url: Optional[str] = Field(None, max_length=255)
    site_description: Optional[str] = Field(None, max_length=500)
    tagline: Optional[str] = Field(None, max_length=200)
    advanced_settings: Optional[Dict[str, Any]] = None


class ThemeSettingsResponse(ThemeSettingsBase):
    """Schema for theme settings response"""
    id: int
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True
