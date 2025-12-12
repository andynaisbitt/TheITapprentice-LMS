# Backend/app/api/v1/services/navigation/schemas.py
"""Navigation menu schemas"""
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class MenuItemBase(BaseModel):
    """Base menu item schema"""
    label: str = Field(..., min_length=1, max_length=100)
    url: str = Field(..., min_length=1, max_length=255)
    order: int = Field(default=0)
    parent_id: Optional[int] = None
    visible: bool = True
    show_in_header: bool = True
    show_in_footer: bool = False
    target_blank: bool = False


class MenuItemCreate(MenuItemBase):
    """Schema for creating a menu item"""
    pass


class MenuItemUpdate(BaseModel):
    """Schema for updating a menu item (all fields optional)"""
    label: Optional[str] = Field(None, min_length=1, max_length=100)
    url: Optional[str] = Field(None, min_length=1, max_length=255)
    order: Optional[int] = None
    parent_id: Optional[int] = None
    visible: Optional[bool] = None
    show_in_header: Optional[bool] = None
    show_in_footer: Optional[bool] = None
    target_blank: Optional[bool] = None


class MenuItemResponse(MenuItemBase):
    """Schema for menu item response"""
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    children: list['MenuItemResponse'] = []

    class Config:
        from_attributes = True


# Update forward reference
MenuItemResponse.model_rebuild()


class NavigationResponse(BaseModel):
    """Schema for full navigation structure"""
    header_items: list[MenuItemResponse]
    footer_items: list[MenuItemResponse]
