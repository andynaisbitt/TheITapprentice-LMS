# Backend/app/api/v1/endpoints/site_settings/admin.py
"""Admin site settings endpoints"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.auth.dependencies import require_admin
from app.api.v1.services.site_settings.models import SiteSettings
from app.api.v1.services.site_settings.schemas import (
    SiteSettingsResponse,
    SiteSettingsUpdate
)

router = APIRouter()


@router.get("/admin/site-settings", response_model=SiteSettingsResponse)
def get_site_settings_admin(
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """Get site settings (admin endpoint)"""
    settings = db.query(SiteSettings).first()

    if not settings:
        # Create default settings if they don't exist
        settings = SiteSettings(id=1)
        db.add(settings)
        db.commit()
        db.refresh(settings)

    return settings


@router.put("/admin/site-settings", response_model=SiteSettingsResponse)
def update_site_settings(
    settings_data: SiteSettingsUpdate,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    """Update site settings"""
    settings = db.query(SiteSettings).first()

    if not settings:
        # Create if doesn't exist
        settings = SiteSettings(id=1)
        db.add(settings)

    # Update fields
    update_data = settings_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(settings, field, value)

    db.commit()
    db.refresh(settings)
    return settings
