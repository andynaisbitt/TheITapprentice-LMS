# Backend/app/api/v1/endpoints/newsletter/public.py
"""Public newsletter endpoints"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.core.database import get_db
from app.api.v1.services.newsletter.models import NewsletterSubscriber
from app.api.v1.services.newsletter.schemas import NewsletterSubscribeRequest, NewsletterSubscribeResponse
from app.api.v1.services.newsletter.email_service import get_email_service_from_settings
from app.api.v1.services.site_settings.models import SiteSettings

router = APIRouter()


@router.post("/newsletter/subscribe", response_model=NewsletterSubscribeResponse)
async def subscribe_to_newsletter(
    request: NewsletterSubscribeRequest,
    db: Session = Depends(get_db)
):
    """
    Subscribe an email to the newsletter (public endpoint)
    """
    # Check if newsletter is enabled
    settings = db.query(SiteSettings).first()
    if not settings or not settings.newsletter_enabled:
        raise HTTPException(status_code=400, detail="Newsletter subscriptions are currently disabled")

    # Check if email already exists
    existing = db.query(NewsletterSubscriber).filter(
        NewsletterSubscriber.email == request.email
    ).first()

    if existing:
        if existing.is_active:
            return NewsletterSubscribeResponse(
                message="You're already subscribed to our newsletter!",
                email=request.email,
                success=True
            )
        else:
            # Reactivate subscription
            existing.is_active = True
            existing.unsubscribed_at = None
            db.commit()
            return NewsletterSubscribeResponse(
                message="Welcome back! Your subscription has been reactivated.",
                email=request.email,
                success=True
            )

    # Create new subscriber
    try:
        subscriber = NewsletterSubscriber(
            email=request.email,
            is_active=True,
            confirmed=True  # Auto-confirm for now (can add double opt-in later)
        )
        db.add(subscriber)
        db.commit()
        db.refresh(subscriber)

        # Send welcome email if SMTP is configured
        email_service = get_email_service_from_settings(settings)
        if email_service:
            try:
                email_service.send_welcome_email(
                    to_email=subscriber.email,
                    site_title=settings.site_title,
                    site_url=settings.site_url
                )
            except Exception as e:
                # Log error but don't fail the subscription
                print(f"Failed to send welcome email: {str(e)}")

        return NewsletterSubscribeResponse(
            message="Successfully subscribed! Check your email for confirmation.",
            email=request.email,
            success=True
        )

    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Email already subscribed")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Subscription failed: {str(e)}")


@router.get("/newsletter/unsubscribe/{email}")
async def unsubscribe_from_newsletter(
    email: str,
    db: Session = Depends(get_db)
):
    """
    Unsubscribe an email from the newsletter (public endpoint)
    """
    subscriber = db.query(NewsletterSubscriber).filter(
        NewsletterSubscriber.email == email,
        NewsletterSubscriber.is_active == True
    ).first()

    if not subscriber:
        raise HTTPException(status_code=404, detail="Email not found in subscriber list")

    subscriber.is_active = False
    from datetime import datetime
    subscriber.unsubscribed_at = datetime.now()
    db.commit()

    return {
        "message": "Successfully unsubscribed from newsletter",
        "email": email,
        "success": True
    }
