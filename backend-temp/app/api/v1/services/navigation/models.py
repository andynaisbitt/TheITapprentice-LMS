# Backend/app/api/v1/services/navigation/models.py
"""Navigation menu models"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.sql import func
from app.core.database import Base


class MenuItem(Base):
    """
    Dynamic navigation menu items

    Examples: Home, About, Blog, Contact, Custom Pages
    """
    __tablename__ = "menu_items"

    # Primary fields
    id = Column(Integer, primary_key=True, index=True)
    label = Column(String(100), nullable=False)
    url = Column(String(255), nullable=False)

    # Ordering
    order = Column(Integer, default=0, index=True)

    # Parent (for dropdown menus)
    parent_id = Column(Integer, ForeignKey('menu_items.id', ondelete='CASCADE'), nullable=True)

    # Visibility
    visible = Column(Boolean, default=True, index=True)
    show_in_header = Column(Boolean, default=True)
    show_in_footer = Column(Boolean, default=False)

    # Open in new tab
    target_blank = Column(Boolean, default=False)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    def __repr__(self):
        return f"<MenuItem {self.label}>"
