# Backend\app\api\v1\services\blog\schemas.py
"""Enhanced blog schemas with Categories and Media support"""
from pydantic import BaseModel, Field, field_validator
from typing import Optional, List
from datetime import datetime
import re


# ============================================================================
# CATEGORY SCHEMAS
# ============================================================================

class BlogCategoryBase(BaseModel):
    """Base schema for categories"""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    parent_id: Optional[int] = None
    color: str = Field(default="#3B82F6", pattern=r'^#[0-9A-Fa-f]{6}$')
    icon: Optional[str] = Field(None, max_length=50)
    meta_title: Optional[str] = Field(None, max_length=60)
    meta_description: Optional[str] = Field(None, max_length=160)


class BlogCategoryCreate(BlogCategoryBase):
    """Schema for creating categories"""
    pass


class BlogCategoryUpdate(BaseModel):
    """Schema for updating categories (all optional)"""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None
    parent_id: Optional[int] = None
    color: Optional[str] = Field(None, pattern=r'^#[0-9A-Fa-f]{6}$')
    icon: Optional[str] = Field(None, max_length=50)
    meta_title: Optional[str] = Field(None, max_length=60)
    meta_description: Optional[str] = Field(None, max_length=160)
    display_order: Optional[int] = None


class BlogCategoryResponse(BlogCategoryBase):
    """Schema for category responses"""
    id: int
    slug: str
    display_order: int
    created_at: datetime
    updated_at: Optional[datetime]
    post_count: Optional[int] = 0  # Computed field
    
    class Config:
        from_attributes = True


# ============================================================================
# TAG SCHEMAS
# ============================================================================

class BlogTagBase(BaseModel):
    """Base schema for tags"""
    name: str = Field(..., min_length=1, max_length=50)
    description: Optional[str] = Field(None, max_length=255)
    color: str = Field(default="#6B7280", pattern=r'^#[0-9A-Fa-f]{6}$')


class BlogTagCreate(BlogTagBase):
    """Schema for creating tags"""
    pass


class BlogTagUpdate(BaseModel):
    """Schema for updating tags"""
    name: Optional[str] = Field(None, min_length=1, max_length=50)
    description: Optional[str] = Field(None, max_length=255)
    color: Optional[str] = Field(None, pattern=r'^#[0-9A-Fa-f]{6}$')


class BlogTagResponse(BlogTagBase):
    """Schema for tag responses"""
    id: int
    slug: str
    created_at: datetime
    post_count: Optional[int] = 0  # Computed field
    
    class Config:
        from_attributes = True


# ============================================================================
# MEDIA SCHEMAS
# ============================================================================

class BlogMediaBase(BaseModel):
    """Base schema for media"""
    alt_text: Optional[str] = Field(None, max_length=125)
    caption: Optional[str] = Field(None, max_length=255)


class BlogMediaResponse(BlogMediaBase):
    """Schema for media responses"""
    id: int
    filename: str
    original_filename: str
    file_url: str
    file_size: int
    mime_type: str
    width: Optional[int]
    height: Optional[int]
    uploaded_by: Optional[int]
    created_at: datetime
    
    class Config:
        from_attributes = True


class BlogMediaUpdate(BaseModel):
    """Schema for updating media metadata"""
    alt_text: Optional[str] = Field(None, max_length=125)
    caption: Optional[str] = Field(None, max_length=255)


# ============================================================================
# POST SCHEMAS
# ============================================================================

class BlogPostBase(BaseModel):
    """Enhanced base schema for blog posts"""
    title: str = Field(..., min_length=3, max_length=200)
    excerpt: Optional[str] = Field(None, max_length=500)
    content: str = Field(..., min_length=10)
    
    # SEO fields
    meta_title: Optional[str] = Field(None, max_length=60, description="Optimal: 50-60 characters")
    meta_description: Optional[str] = Field(None, max_length=160, description="Optimal: 150-160 characters")
    meta_keywords: Optional[str] = Field(None, max_length=255)
    canonical_url: Optional[str] = Field(None, max_length=500)
    
    # Featured image
    featured_image: Optional[str] = Field(None, max_length=500)
    featured_image_alt: Optional[str] = Field(None, max_length=125)
    featured_image_caption: Optional[str] = Field(None, max_length=255)
    
    # Publishing
    published: bool = False
    scheduled_for: Optional[datetime] = None
    
    # Content flags
    is_featured: bool = False
    allow_comments: bool = True
    
    # Relationships
    tag_ids: Optional[List[int]] = []
    category_ids: Optional[List[int]] = []
    
    @field_validator('meta_title')
    @classmethod
    def validate_meta_title(cls, v):
        if v and len(v) > 60:
            raise ValueError('Meta title should be 60 characters or less for optimal SEO')
        return v
    
    @field_validator('meta_description')
    @classmethod
    def validate_meta_description(cls, v):
        if v and len(v) > 160:
            raise ValueError('Meta description should be 160 characters or less for optimal SEO')
        return v
    
    @field_validator('canonical_url')
    @classmethod
    def validate_canonical_url(cls, v):
        if v:
            # Basic URL validation
            url_pattern = r'^https?://.+$'
            if not re.match(url_pattern, v):
                raise ValueError('Canonical URL must be a valid HTTP/HTTPS URL')
        return v


class BlogPostCreate(BlogPostBase):
    """Schema for creating blog posts"""
    slug: Optional[str] = Field(None, max_length=250, description="Custom URL slug (auto-generated if empty)")
    
    @field_validator('slug')
    @classmethod
    def validate_slug(cls, v):
        if v:
            # Only allow lowercase letters, numbers, and hyphens
            if not re.match(r'^[a-z0-9-]+$', v):
                raise ValueError('Slug must contain only lowercase letters, numbers, and hyphens')
        return v


class BlogPostUpdate(BaseModel):
    """Schema for updating blog posts (all fields optional)"""
    title: Optional[str] = Field(None, min_length=3, max_length=200)
    slug: Optional[str] = Field(None, max_length=250)
    excerpt: Optional[str] = Field(None, max_length=500)
    content: Optional[str] = Field(None, min_length=10)
    meta_title: Optional[str] = Field(None, max_length=60)
    meta_description: Optional[str] = Field(None, max_length=160)
    meta_keywords: Optional[str] = Field(None, max_length=255)
    canonical_url: Optional[str] = Field(None, max_length=500)
    featured_image: Optional[str] = Field(None, max_length=500)
    featured_image_alt: Optional[str] = Field(None, max_length=125)
    featured_image_caption: Optional[str] = Field(None, max_length=255)
    published: Optional[bool] = None
    scheduled_for: Optional[datetime] = None
    is_featured: Optional[bool] = None
    allow_comments: Optional[bool] = None
    tag_ids: Optional[List[int]] = None
    category_ids: Optional[List[int]] = None
    
    @field_validator('slug')
    @classmethod
    def validate_slug(cls, v):
        if v:
            if not re.match(r'^[a-z0-9-]+$', v):
                raise ValueError('Slug must contain only lowercase letters, numbers, and hyphens')
        return v


class BlogPostResponse(BlogPostBase):
    """Schema for blog post responses"""
    id: int
    slug: str
    author_id: Optional[int]
    view_count: int
    read_time_minutes: Optional[int]
    published_at: Optional[datetime]
    created_at: datetime
    updated_at: Optional[datetime]
    tags: List[BlogTagResponse] = []
    categories: List[BlogCategoryResponse] = []
    
    class Config:
        from_attributes = True


class BlogPostListResponse(BaseModel):
    """Schema for paginated blog post list"""
    posts: List[BlogPostResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class BlogPostPublic(BaseModel):
    """Minimal schema for public blog listing (no content)"""
    id: int
    title: str
    slug: str
    excerpt: Optional[str]
    featured_image: Optional[str]
    featured_image_alt: Optional[str]
    featured_image_caption: Optional[str]
    published_at: Optional[datetime]
    read_time_minutes: Optional[int]
    view_count: int
    is_featured: bool
    tags: List[BlogTagResponse] = []
    categories: List[BlogCategoryResponse] = []
    
    class Config:
        from_attributes = True


class BlogPostPublicDetail(BlogPostPublic):
    """Full public schema with content"""
    content: str
    meta_title: Optional[str]
    meta_description: Optional[str]
    meta_keywords: Optional[str]
    canonical_url: Optional[str]
    allow_comments: bool


# ============================================================================
# FILTER & SEARCH SCHEMAS
# ============================================================================

class BlogPostFilters(BaseModel):
    """Schema for advanced post filtering"""
    page: int = Field(1, ge=1)
    page_size: int = Field(10, ge=1, le=100)
    search: Optional[str] = None
    category_id: Optional[int] = None
    tag_id: Optional[int] = None
    published: Optional[bool] = None
    is_featured: Optional[bool] = None
    author_id: Optional[int] = None
    sort_by: str = Field("created_at", pattern="^(created_at|published_at|view_count|title)$")
    sort_order: str = Field("desc", pattern="^(asc|desc)$")


# ============================================================================
# BULK OPERATIONS
# ============================================================================

class BulkPostUpdate(BaseModel):
    """Schema for bulk post updates"""
    post_ids: List[int] = Field(..., min_length=1)
    published: Optional[bool] = None
    is_featured: Optional[bool] = None
    category_ids: Optional[List[int]] = None
    tag_ids: Optional[List[int]] = None


class BulkDeleteResponse(BaseModel):
    """Response for bulk delete operations"""
    deleted_count: int
    deleted_ids: List[int]