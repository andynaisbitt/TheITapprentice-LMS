# Backend/app/api/v1/endpoints/theme/public.py
"""Public theme endpoints"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.api.v1.services.theme.models import ThemeSettings
from app.api.v1.services.theme.schemas import ThemeSettingsResponse

router = APIRouter()


@router.get("/theme", response_model=ThemeSettingsResponse)
def get_theme(db: Session = Depends(get_db)):
    """Get theme settings (public endpoint)"""
    theme = db.query(ThemeSettings).first()

    # If no theme exists, create default
    if not theme:
        theme = ThemeSettings(id=1)
        db.add(theme)
        db.commit()
        db.refresh(theme)

    return theme
