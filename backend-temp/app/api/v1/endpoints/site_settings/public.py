# Backend/app/api/v1/endpoints/site_settings/public.py
"""Public site settings endpoints (no authentication required)"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.api.v1.services.site_settings.models import SiteSettings
from app.api.v1.services.site_settings.schemas import SiteSettingsResponse

router = APIRouter()


@router.get("/site-settings", response_model=SiteSettingsResponse)
def get_public_site_settings(db: Session = Depends(get_db)):
    """
    Get public site settings (no authentication required)

    Used by frontend components to display site branding, hero content,
    social media links, and other public-facing configuration.
    """
    settings = db.query(SiteSettings).first()

    if not settings:
        # Return default settings if none exist
        settings = SiteSettings(id=1)
        db.add(settings)
        db.commit()
        db.refresh(settings)

    return settings
