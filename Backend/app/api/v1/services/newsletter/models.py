# Backend/app/api/v1/services/newsletter/models.py
"""Newsletter subscriber model"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.sql import func
from app.core.database import Base


class NewsletterSubscriber(Base):
    """Newsletter subscriber model"""
    __tablename__ = "newsletter_subscribers"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    confirmed = Column(Boolean, default=False, nullable=False)
    confirmation_token = Column(String(255), nullable=True)
    subscribed_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    unsubscribed_at = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self):
        return f"<NewsletterSubscriber {self.email}>"
