# Backend/app/api/v1/endpoints/newsletter/admin.py
"""Admin newsletter endpoints"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.core.database import get_db
from app.auth.dependencies import get_current_user
from app.api.v1.services.newsletter.models import NewsletterSubscriber
from app.api.v1.services.newsletter.schemas import NewsletterListResponse, NewsletterSubscriberResponse
from app.api.v1.services.newsletter.email_service import get_email_service_from_settings
from app.api.v1.services.site_settings.models import SiteSettings

router = APIRouter()


@router.get("/admin/newsletter/subscribers", response_model=NewsletterListResponse)
async def get_newsletter_subscribers(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get all newsletter subscribers (admin only)
    """
    # Get all subscribers
    subscribers = db.query(NewsletterSubscriber).order_by(
        NewsletterSubscriber.subscribed_at.desc()
    ).all()

    # Count active subscribers
    active_count = db.query(func.count(NewsletterSubscriber.id)).filter(
        NewsletterSubscriber.is_active == True
    ).scalar()

    return NewsletterListResponse(
        total=len(subscribers),
        active=active_count,
        subscribers=subscribers
    )


@router.delete("/admin/newsletter/subscribers/{subscriber_id}")
async def delete_newsletter_subscriber(
    subscriber_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Delete a newsletter subscriber (admin only)
    """
    subscriber = db.query(NewsletterSubscriber).filter(
        NewsletterSubscriber.id == subscriber_id
    ).first()

    if not subscriber:
        raise HTTPException(status_code=404, detail="Subscriber not found")

    db.delete(subscriber)
    db.commit()

    return {
        "message": "Subscriber deleted successfully",
        "success": True
    }


@router.post("/admin/newsletter/test-email")
async def send_test_email(
    test_email: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Send a test email to verify SMTP configuration (admin only)
    """
    settings = db.query(SiteSettings).first()
    if not settings:
        raise HTTPException(status_code=404, detail="Site settings not found")

    email_service = get_email_service_from_settings(settings)
    if not email_service:
        raise HTTPException(
            status_code=400,
            detail="SMTP not configured. Please configure SMTP settings in Site Settings."
        )

    try:
        success = email_service.send_email(
            to_email=test_email,
            subject=f"Test Email from {settings.site_title}",
            html_body=f"""
            <html>
                <body style="font-family: Arial, sans-serif; padding: 20px;">
                    <h2>Test Email Successful!</h2>
                    <p>This is a test email from your {settings.site_title} newsletter system.</p>
                    <p>Your SMTP configuration is working correctly.</p>
                    <p style="color: #666; font-size: 12px; margin-top: 30px;">
                        Sent from {settings.site_url}
                    </p>
                </body>
            </html>
            """,
            text_body=f"Test email from {settings.site_title}. Your SMTP configuration is working!"
        )

        if success:
            return {
                "message": f"Test email sent successfully to {test_email}",
                "success": True
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to send test email")

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Email send failed: {str(e)}")


@router.post("/admin/newsletter/send-to-all")
async def send_newsletter_to_all(
    subject: str,
    html_body: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Send a newsletter email to all active subscribers (admin only)
    """
    settings = db.query(SiteSettings).first()
    if not settings:
        raise HTTPException(status_code=404, detail="Site settings not found")

    email_service = get_email_service_from_settings(settings)
    if not email_service:
        raise HTTPException(
            status_code=400,
            detail="SMTP not configured. Please configure SMTP settings first."
        )

    # Get all active subscribers
    subscribers = db.query(NewsletterSubscriber).filter(
        NewsletterSubscriber.is_active == True,
        NewsletterSubscriber.confirmed == True
    ).all()

    if not subscribers:
        return {
            "message": "No active subscribers to send to",
            "sent": 0,
            "failed": 0
        }

    sent_count = 0
    failed_count = 0

    for subscriber in subscribers:
        try:
            success = email_service.send_email(
                to_email=subscriber.email,
                subject=subject,
                html_body=html_body
            )
            if success:
                sent_count += 1
            else:
                failed_count += 1
        except Exception as e:
            print(f"Failed to send to {subscriber.email}: {str(e)}")
            failed_count += 1

    return {
        "message": f"Newsletter sent to {sent_count} subscribers",
        "sent": sent_count,
        "failed": failed_count,
        "total": len(subscribers)
    }
