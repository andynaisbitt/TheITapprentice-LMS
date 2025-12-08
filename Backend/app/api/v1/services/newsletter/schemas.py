# Backend/app/api/v1/services/newsletter/schemas.py
"""Newsletter schemas"""
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional


class NewsletterSubscribeRequest(BaseModel):
    """Schema for newsletter subscription request"""
    email: EmailStr = Field(..., description="Email address to subscribe")


class NewsletterSubscribeResponse(BaseModel):
    """Schema for newsletter subscription response"""
    message: str
    email: str
    success: bool


class NewsletterSubscriberResponse(BaseModel):
    """Schema for newsletter subscriber response"""
    id: int
    email: str
    is_active: bool
    confirmed: bool
    subscribed_at: datetime
    unsubscribed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class NewsletterListResponse(BaseModel):
    """Schema for newsletter subscribers list"""
    total: int
    active: int
    subscribers: list[NewsletterSubscriberResponse]
