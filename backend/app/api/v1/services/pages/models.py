# Backend\app\api\v1\services\pages\models.py
"""Dynamic pages models for editable static content"""
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class Page(Base):
    """
    Dynamic pages with JSON content blocks

    Examples: About, Contact, Terms, Privacy, Custom landing pages
    """
    __tablename__ = "pages"

    # Primary fields
    id = Column(Integer, primary_key=True, index=True)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    title = Column(String(200), nullable=False)

    # SEO
    meta_title = Column(String(60), nullable=True)
    meta_description = Column(String(160), nullable=True)
    meta_keywords = Column(String(255), nullable=True)
    canonical_url = Column(String(500), nullable=True)  # For duplicate content SEO

    # Content blocks (JSON array)
    # Format: [{"type": "hero", "data": {...}}, {"type": "text", "data": {...}}]
    blocks = Column(JSON, nullable=False, default=[])

    # Publishing
    published = Column(Boolean, default=False, index=True)

    # Author
    created_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    author = relationship("User")

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    def __repr__(self):
        return f"<Page {self.slug}>"
