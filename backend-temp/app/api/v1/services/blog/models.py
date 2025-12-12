# Backend\app\api\v1\services\blog\models.py
"""Enhanced blog models with Categories, SEO, and Image management"""
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, Table
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base
from app.users.models import User  # Import User model for relationship

# Many-to-many relationship table for tags
post_tags = Table(
    'post_tags',
    Base.metadata,
    Column('post_id', Integer, ForeignKey('blog_posts.id', ondelete='CASCADE')),
    Column('tag_id', Integer, ForeignKey('blog_tags.id', ondelete='CASCADE'))
)

# Many-to-many relationship table for categories
post_categories = Table(
    'post_categories',
    Base.metadata,
    Column('post_id', Integer, ForeignKey('blog_posts.id', ondelete='CASCADE')),
    Column('category_id', Integer, ForeignKey('blog_categories.id', ondelete='CASCADE'))
)


class BlogCategory(Base):
    """Category system for organizing posts (broader than tags)"""
    __tablename__ = "blog_categories"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    
    # Hierarchy support (for subcategories)
    parent_id = Column(Integer, ForeignKey('blog_categories.id'), nullable=True)
    parent = relationship("BlogCategory", remote_side=[id], backref="children")
    
    # SEO
    meta_title = Column(String(60), nullable=True)
    meta_description = Column(String(160), nullable=True)
    
    # Display
    color = Column(String(7), default="#3B82F6")  # Hex color for UI
    icon = Column(String(50), nullable=True)  # Icon name/emoji
    display_order = Column(Integer, default=0)  # For custom ordering
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    posts = relationship("BlogPost", secondary=post_categories, back_populates="categories")
    
    def __repr__(self):
        return f"<BlogCategory {self.name}>"


class BlogPost(Base):
    """Enhanced blog post model with full SEO, scheduling, and media support"""
    __tablename__ = "blog_posts"
    
    # Primary fields
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False, index=True)
    slug = Column(String(250), unique=True, nullable=False, index=True)
    excerpt = Column(Text, nullable=True)  # Short description
    content = Column(Text, nullable=False)
    
    # SEO fields
    meta_title = Column(String(60), nullable=True)  # Optimal: 50-60 chars
    meta_description = Column(String(160), nullable=True)  # Optimal: 150-160 chars
    meta_keywords = Column(String(255), nullable=True)  # Comma-separated
    canonical_url = Column(String(500), nullable=True)  # For duplicate content
    
    # Featured image with enhanced metadata
    featured_image = Column(String(500), nullable=True)  # URL or path
    featured_image_alt = Column(String(125), nullable=True)  # Alt text for SEO
    featured_image_caption = Column(String(255), nullable=True)  # Image caption
    
    # Publishing & Scheduling
    published = Column(Boolean, default=False, index=True)
    published_at = Column(DateTime(timezone=True), nullable=True)
    scheduled_for = Column(DateTime(timezone=True), nullable=True, index=True)  # Future publishing
    
    # Author (links to User model)
    author_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    author = relationship("User", backref="blog_posts")
    
    # Analytics
    view_count = Column(Integer, default=0)
    read_time_minutes = Column(Integer, nullable=True)  # Estimated read time
    
    # Content flags
    is_featured = Column(Boolean, default=False, index=True)  # Homepage featured
    allow_comments = Column(Boolean, default=True)  # Enable/disable comments
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    tags = relationship("BlogTag", secondary=post_tags, back_populates="posts")
    categories = relationship("BlogCategory", secondary=post_categories, back_populates="posts")
    
    def __repr__(self):
        return f"<BlogPost {self.title}>"


class BlogTag(Base):
    """Tag system for detailed categorization (more specific than categories)"""
    __tablename__ = "blog_tags"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False, index=True)
    slug = Column(String(50), unique=True, nullable=False, index=True)
    description = Column(String(255), nullable=True)
    
    # Display
    color = Column(String(7), default="#6B7280")  # Hex color for UI
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    posts = relationship("BlogPost", secondary=post_tags, back_populates="tags")
    
    def __repr__(self):
        return f"<BlogTag {self.name}>"


class BlogMedia(Base):
    """Media library for uploaded images/files"""
    __tablename__ = "blog_media"
    
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    original_filename = Column(String(255), nullable=False)
    file_path = Column(String(500), nullable=False)  # Relative path
    file_url = Column(String(500), nullable=False)  # Public URL
    
    # File metadata
    file_size = Column(Integer, nullable=False)  # Bytes
    mime_type = Column(String(100), nullable=False)
    width = Column(Integer, nullable=True)  # For images
    height = Column(Integer, nullable=True)  # For images
    
    # SEO
    alt_text = Column(String(125), nullable=True)
    caption = Column(String(255), nullable=True)
    
    # Ownership
    uploaded_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    def __repr__(self):
        return f"<BlogMedia {self.filename}>"