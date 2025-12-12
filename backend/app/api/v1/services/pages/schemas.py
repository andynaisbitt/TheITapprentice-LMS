# Backend\app\api\v1\services\pages\schemas.py
"""Pydantic schemas for dynamic pages"""
from pydantic import BaseModel, Field, field_validator
from typing import List, Dict, Any, Optional
from datetime import datetime
import re


class ContentBlock(BaseModel):
    """Single content block"""
    type: str = Field(..., description="Block type (hero, text, stats, etc.)")
    data: Dict[str, Any] = Field(..., description="Block configuration data")

    @field_validator('type')
    @classmethod
    def validate_block_type(cls, v):
        allowed_types = [
            'hero', 'text', 'stats', 'cta', 'team',
            'features', 'faq', 'image', 'testimonials',
            'featureGrid', 'techStack'
        ]
        if v not in allowed_types:
            raise ValueError(f'Block type must be one of: {", ".join(allowed_types)}')
        return v


class PageBase(BaseModel):
    """Base page schema"""
    slug: str = Field(..., min_length=1, max_length=100)
    title: str = Field(..., min_length=1, max_length=200)
    meta_title: Optional[str] = Field(None, max_length=60)
    meta_description: Optional[str] = Field(None, max_length=160)
    meta_keywords: Optional[str] = Field(None, max_length=255)
    canonical_url: Optional[str] = Field(None, max_length=500)
    blocks: List[ContentBlock] = Field(default_factory=list)
    published: bool = False

    @field_validator('canonical_url')
    @classmethod
    def validate_canonical_url(cls, v):
        if v:
            # Basic URL validation
            url_pattern = r'^https?://.+$'
            if not re.match(url_pattern, v):
                raise ValueError('Canonical URL must be a valid HTTP/HTTPS URL')
        return v


class PageCreate(PageBase):
    """Schema for creating a page"""
    pass


class PageUpdate(BaseModel):
    """Schema for updating a page (all fields optional)"""
    slug: Optional[str] = Field(None, min_length=1, max_length=100)
    title: Optional[str] = Field(None, min_length=1, max_length=200)
    meta_title: Optional[str] = Field(None, max_length=60)
    meta_description: Optional[str] = Field(None, max_length=160)
    meta_keywords: Optional[str] = Field(None, max_length=255)
    canonical_url: Optional[str] = Field(None, max_length=500)
    blocks: Optional[List[ContentBlock]] = None
    published: Optional[bool] = None

    @field_validator('canonical_url')
    @classmethod
    def validate_canonical_url(cls, v):
        if v:
            # Basic URL validation
            url_pattern = r'^https?://.+$'
            if not re.match(url_pattern, v):
                raise ValueError('Canonical URL must be a valid HTTP/HTTPS URL')
        return v


class PageResponse(PageBase):
    """Schema for page response"""
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    created_by: Optional[int] = None

    class Config:
        from_attributes = True


class PageListResponse(BaseModel):
    """Schema for paginated page list"""
    pages: List[PageResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
