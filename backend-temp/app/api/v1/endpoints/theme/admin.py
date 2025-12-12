# Backend/app/api/v1/endpoints/theme/admin.py
"""Admin theme endpoints"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.auth.dependencies import require_admin
from app.api.v1.services.theme.models import ThemeSettings
from app.api.v1.services.theme.schemas import (
    ThemeSettingsResponse,
    ThemeSettingsUpdate
)

router = APIRouter()


@router.get("/admin/theme", response_model=ThemeSettingsResponse)
def get_theme_admin(
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """Get theme settings (admin endpoint)"""
    theme = db.query(ThemeSettings).first()

    if not theme:
        theme = ThemeSettings(id=1)
        db.add(theme)
        db.commit()
        db.refresh(theme)

    return theme


@router.put("/admin/theme", response_model=ThemeSettingsResponse)
def update_theme(
    theme_data: ThemeSettingsUpdate,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """Update theme settings"""
    theme = db.query(ThemeSettings).first()

    if not theme:
        # Create if doesn't exist
        theme = ThemeSettings(id=1)
        db.add(theme)

    # Update fields
    update_data = theme_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(theme, field, value)

    db.commit()
    db.refresh(theme)
    return theme


@router.post("/admin/theme/reset")
def reset_theme(
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """Reset theme to defaults"""
    theme = db.query(ThemeSettings).first()

    if theme:
        # Reset to defaults
        theme.primary_color = "#3B82F6"
        theme.secondary_color = "#8B5CF6"
        theme.accent_color = "#EC4899"
        theme.background_light = "#FFFFFF"
        theme.background_dark = "#111827"
        theme.text_light = "#111827"
        theme.text_dark = "#F9FAFB"
        theme.font_family = "Inter, system-ui, sans-serif"
        theme.heading_font = "Inter, system-ui, sans-serif"
        theme.font_size_base = "16px"
        theme.container_width = "1280px"
        theme.border_radius = "0.5rem"
        theme.custom_css = None
        theme.logo_url = None
        theme.logo_dark_url = None
        theme.site_name = "BlogCMS"
        theme.tagline = "The blog platform that doesn't suck"
        theme.advanced_settings = {}

        db.commit()
        db.refresh(theme)
        return theme
    else:
        raise HTTPException(status_code=404, detail="Theme not found")
