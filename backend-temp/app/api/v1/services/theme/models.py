# Backend/app/api/v1/services/theme/models.py
"""Theme customization models"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, JSON
from sqlalchemy.sql import func
from app.core.database import Base


class ThemeSettings(Base):
    """
    Global theme settings (singleton table - only 1 row)

    Stores colors, fonts, and styling preferences
    """
    __tablename__ = "theme_settings"

    id = Column(Integer, primary_key=True, default=1)  # Singleton

    # Colors
    primary_color = Column(String(7), default="#3B82F6")  # Blue-500
    secondary_color = Column(String(7), default="#8B5CF6")  # Purple-500
    accent_color = Column(String(7), default="#EC4899")  # Pink-500
    background_light = Column(String(7), default="#FFFFFF")
    background_dark = Column(String(7), default="#111827")  # Gray-900
    text_light = Column(String(7), default="#111827")
    text_dark = Column(String(7), default="#F9FAFB")

    # Typography
    font_family = Column(String(100), default="Inter, system-ui, sans-serif")
    heading_font = Column(String(100), default="Inter, system-ui, sans-serif")
    font_size_base = Column(String(10), default="16px")

    # Layout
    container_width = Column(String(10), default="1280px")  # max-w-7xl
    border_radius = Column(String(10), default="0.5rem")  # rounded-lg

    # Custom CSS
    custom_css = Column(String(10000), nullable=True)

    # Logo
    logo_url = Column(String(255), nullable=True)
    logo_dark_url = Column(String(255), nullable=True)

    # Site info
    site_name = Column(String(100), default="BlogCMS")
    site_url = Column(String(255), default="https://yourdomain.com")
    site_description = Column(String(500), default="Latest blog posts")
    tagline = Column(String(200), nullable=True)

    # Advanced settings (JSON)
    advanced_settings = Column(JSON, default={})

    # Timestamps
    updated_at = Column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())

    def __repr__(self):
        return f"<ThemeSettings {self.site_name}>"
