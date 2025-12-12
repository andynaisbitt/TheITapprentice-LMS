# Backend\app\api\v1\services\blog\crud.py
"""Enhanced CRUD operations for blog with Categories and Media"""
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import or_, desc, asc, func
from typing import List, Optional, Tuple
from datetime import datetime
import re
from ..blog.models import BlogPost, BlogTag, BlogCategory, BlogMedia
from ..blog.schemas import (
    BlogPostCreate, BlogPostUpdate, 
    BlogTagCreate, BlogTagUpdate,
    BlogCategoryCreate, BlogCategoryUpdate
)


def slugify(text: str) -> str:
    """Convert text to URL-friendly slug"""
    text = text.lower().strip()
    # Replace spaces and special chars with hyphens
    text = re.sub(r'[^\w\s-]', '', text)
    text = re.sub(r'[-\s]+', '-', text)
    return text[:250]  # Max length


def calculate_read_time(content: str) -> int:
    """Estimate read time in minutes (average 200 words/min)"""
    word_count = len(content.split())
    return max(1, round(word_count / 200))


# ============================================================================
# CATEGORY OPERATIONS
# ============================================================================

def get_category(db: Session, category_id: int) -> Optional[BlogCategory]:
    """Get category by ID"""
    return db.query(BlogCategory).filter(BlogCategory.id == category_id).first()


def get_category_by_slug(db: Session, slug: str) -> Optional[BlogCategory]:
    """Get category by slug"""
    return db.query(BlogCategory).filter(BlogCategory.slug == slug).first()


def get_categories(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    parent_id: Optional[int] = None
) -> List[BlogCategory]:
    """Get all categories with optional parent filter and computed post_count"""
    query = db.query(BlogCategory)

    if parent_id is not None:
        query = query.filter(BlogCategory.parent_id == parent_id)

    categories = query.order_by(BlogCategory.display_order, BlogCategory.name).offset(skip).limit(limit).all()

    # Compute post_count for each category
    for category in categories:
        category.post_count = len(category.posts)

    return categories


def create_category(db: Session, category: BlogCategoryCreate) -> BlogCategory:
    """Create new category"""
    slug = slugify(category.name)
    
    # Ensure unique slug
    existing = db.query(BlogCategory).filter(BlogCategory.slug == slug).first()
    if existing:
        counter = 1
        while db.query(BlogCategory).filter(BlogCategory.slug == f"{slug}-{counter}").first():
            counter += 1
        slug = f"{slug}-{counter}"
    
    db_category = BlogCategory(
        name=category.name,
        slug=slug,
        description=category.description,
        parent_id=category.parent_id,
        color=category.color,
        icon=category.icon,
        meta_title=category.meta_title,
        meta_description=category.meta_description
    )
    db.add(db_category)
    db.commit()
    db.refresh(db_category)
    return db_category


def update_category(
    db: Session, 
    category_id: int, 
    category_update: BlogCategoryUpdate
) -> Optional[BlogCategory]:
    """Update category"""
    db_category = get_category(db, category_id)
    if not db_category:
        return None
    
    update_data = category_update.model_dump(exclude_unset=True)
    
    # Update slug if name changed
    if 'name' in update_data:
        new_slug = slugify(update_data['name'])
        if new_slug != db_category.slug:
            existing = db.query(BlogCategory).filter(BlogCategory.slug == new_slug).first()
            if not existing:
                update_data['slug'] = new_slug
    
    for field, value in update_data.items():
        setattr(db_category, field, value)
    
    db.commit()
    db.refresh(db_category)
    return db_category


def delete_category(db: Session, category_id: int) -> bool:
    """Delete category"""
    category = db.query(BlogCategory).filter(BlogCategory.id == category_id).first()
    if category:
        db.delete(category)
        db.commit()
        return True
    return False


# ============================================================================
# TAG OPERATIONS
# ============================================================================

def get_tag(db: Session, tag_id: int) -> Optional[BlogTag]:
    """Get tag by ID"""
    return db.query(BlogTag).filter(BlogTag.id == tag_id).first()


def get_tag_by_slug(db: Session, slug: str) -> Optional[BlogTag]:
    """Get tag by slug"""
    return db.query(BlogTag).filter(BlogTag.slug == slug).first()


def get_tags(db: Session, skip: int = 0, limit: int = 100) -> List[BlogTag]:
    """Get all tags"""
    return db.query(BlogTag).order_by(BlogTag.name).offset(skip).limit(limit).all()


def create_tag(db: Session, tag: BlogTagCreate) -> BlogTag:
    """Create new tag"""
    slug = slugify(tag.name)
    
    # Ensure unique slug
    existing = db.query(BlogTag).filter(BlogTag.slug == slug).first()
    if existing:
        counter = 1
        while db.query(BlogTag).filter(BlogTag.slug == f"{slug}-{counter}").first():
            counter += 1
        slug = f"{slug}-{counter}"
    
    db_tag = BlogTag(
        name=tag.name,
        slug=slug,
        description=tag.description,
        color=tag.color
    )
    db.add(db_tag)
    db.commit()
    db.refresh(db_tag)
    return db_tag


def update_tag(db: Session, tag_id: int, tag_update: BlogTagUpdate) -> Optional[BlogTag]:
    """Update tag"""
    db_tag = get_tag(db, tag_id)
    if not db_tag:
        return None
    
    update_data = tag_update.model_dump(exclude_unset=True)
    
    if 'name' in update_data:
        new_slug = slugify(update_data['name'])
        if new_slug != db_tag.slug:
            existing = db.query(BlogTag).filter(BlogTag.slug == new_slug).first()
            if not existing:
                update_data['slug'] = new_slug
    
    for field, value in update_data.items():
        setattr(db_tag, field, value)
    
    db.commit()
    db.refresh(db_tag)
    return db_tag


def delete_tag(db: Session, tag_id: int) -> bool:
    """Delete tag"""
    tag = db.query(BlogTag).filter(BlogTag.id == tag_id).first()
    if tag:
        db.delete(tag)
        db.commit()
        return True
    return False


# ============================================================================
# POST OPERATIONS
# ============================================================================

def get_post(db: Session, post_id: int) -> Optional[BlogPost]:
    """Get post by ID with tags and categories"""
    return db.query(BlogPost).options(
        joinedload(BlogPost.tags),
        joinedload(BlogPost.categories)
    ).filter(BlogPost.id == post_id).first()


def get_post_by_slug(db: Session, slug: str) -> Optional[BlogPost]:
    """Get post by slug with tags and categories"""
    return db.query(BlogPost).options(
        joinedload(BlogPost.tags),
        joinedload(BlogPost.categories)
    ).filter(BlogPost.slug == slug).first()


def get_post_by_canonical_url(db: Session, canonical_url: str) -> Optional[BlogPost]:
    """Get post by canonical URL with tags and categories"""
    return db.query(BlogPost).options(
        joinedload(BlogPost.tags),
        joinedload(BlogPost.categories)
    ).filter(BlogPost.canonical_url == canonical_url).first()


def get_posts(
    db: Session,
    skip: int = 0,
    limit: int = 10,
    published_only: bool = False,
    category_id: Optional[int] = None,
    tag_slug: Optional[str] = None,
    search: Optional[str] = None,
    is_featured: Optional[bool] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc"
) -> Tuple[List[BlogPost], int]:
    """
    Enhanced post retrieval with advanced filtering
    Returns (posts, total_count)
    """
    query = db.query(BlogPost).options(
        joinedload(BlogPost.tags),
        joinedload(BlogPost.categories)
    )
    
    # Filter by published status
    if published_only:
        query = query.filter(BlogPost.published == True)
    
    # Filter by category
    if category_id:
        query = query.join(BlogPost.categories).filter(BlogCategory.id == category_id)
    
    # Filter by tag
    if tag_slug:
        query = query.join(BlogPost.tags).filter(BlogTag.slug == tag_slug)
    
    # Filter by featured
    if is_featured is not None:
        query = query.filter(BlogPost.is_featured == is_featured)
    
    # Search in title, excerpt, content
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            or_(
                BlogPost.title.ilike(search_term),
                BlogPost.excerpt.ilike(search_term),
                BlogPost.content.ilike(search_term)
            )
        )
    
    # Get total count before pagination
    total = query.count()
    
    # Sorting
    sort_column = getattr(BlogPost, sort_by, BlogPost.created_at)
    if sort_order == "asc":
        query = query.order_by(asc(sort_column))
    else:
        query = query.order_by(desc(sort_column))
    
    # Pagination
    posts = query.offset(skip).limit(limit).all()
    
    return posts, total


def create_post(
    db: Session,
    post: BlogPostCreate,
    author_id: int
) -> BlogPost:
    """Create new blog post"""
    
    # Generate slug if not provided
    slug = post.slug if post.slug else slugify(post.title)
    
    # Ensure unique slug
    existing = db.query(BlogPost).filter(BlogPost.slug == slug).first()
    if existing:
        counter = 1
        while db.query(BlogPost).filter(BlogPost.slug == f"{slug}-{counter}").first():
            counter += 1
        slug = f"{slug}-{counter}"
    
    # Calculate read time
    read_time = calculate_read_time(post.content)
    
    # Auto-generate SEO fields if not provided
    meta_title = post.meta_title if post.meta_title else post.title[:60]
    
    if not post.meta_description:
        if post.excerpt:
            meta_description = post.excerpt[:160]
        else:
            meta_description = post.content[:160]
    else:
        meta_description = post.meta_description
    
    # Handle publishing
    published_at = None
    if post.published and not post.scheduled_for:
        published_at = datetime.utcnow()
    elif post.scheduled_for:
        published_at = post.scheduled_for if post.published else None
    
    # Create post
    db_post = BlogPost(
        title=post.title,
        slug=slug,
        excerpt=post.excerpt,
        content=post.content,
        meta_title=meta_title,
        meta_description=meta_description,
        meta_keywords=post.meta_keywords,
        canonical_url=post.canonical_url,
        featured_image=post.featured_image,
        featured_image_alt=post.featured_image_alt,
        featured_image_caption=post.featured_image_caption,
        published=post.published,
        published_at=published_at,
        scheduled_for=post.scheduled_for,
        is_featured=post.is_featured,
        allow_comments=post.allow_comments,
        author_id=author_id,
        read_time_minutes=read_time
    )
    
    # Add tags
    if post.tag_ids:
        tags = db.query(BlogTag).filter(BlogTag.id.in_(post.tag_ids)).all()
        db_post.tags = tags
    
    # Add categories
    if post.category_ids:
        categories = db.query(BlogCategory).filter(BlogCategory.id.in_(post.category_ids)).all()
        db_post.categories = categories
    
    db.add(db_post)
    db.commit()
    db.refresh(db_post)
    return db_post


def update_post(
    db: Session,
    post_id: int,
    post_update: BlogPostUpdate
) -> Optional[BlogPost]:
    """Update existing blog post"""
    db_post = get_post(db, post_id)
    if not db_post:
        return None
    
    update_data = post_update.model_dump(exclude_unset=True)
    
    # Update slug if title changed and slug not explicitly provided
    if 'title' in update_data and 'slug' not in update_data:
        new_slug = slugify(update_data['title'])
        if new_slug != db_post.slug:
            existing = db.query(BlogPost).filter(BlogPost.slug == new_slug).first()
            if not existing:
                update_data['slug'] = new_slug
    
    # Update published_at if publishing for first time
    if 'published' in update_data and update_data['published'] and not db_post.published:
        if 'scheduled_for' not in update_data or not update_data.get('scheduled_for'):
            update_data['published_at'] = datetime.utcnow()
    
    # Recalculate read time if content changed
    if 'content' in update_data:
        update_data['read_time_minutes'] = calculate_read_time(update_data['content'])
    
    # Update tags
    if 'tag_ids' in update_data:
        tag_ids = update_data.pop('tag_ids')
        if tag_ids is not None:
            tags = db.query(BlogTag).filter(BlogTag.id.in_(tag_ids)).all()
            db_post.tags = tags
    
    # Update categories
    if 'category_ids' in update_data:
        category_ids = update_data.pop('category_ids')
        if category_ids is not None:
            categories = db.query(BlogCategory).filter(BlogCategory.id.in_(category_ids)).all()
            db_post.categories = categories
    
    # Apply updates
    for field, value in update_data.items():
        setattr(db_post, field, value)
    
    db.commit()
    db.refresh(db_post)
    return db_post


def delete_post(db: Session, post_id: int) -> bool:
    """Delete blog post"""
    post = db.query(BlogPost).filter(BlogPost.id == post_id).first()
    if post:
        db.delete(post)
        db.commit()
        return True
    return False


def bulk_update_posts(
    db: Session,
    post_ids: List[int],
    published: Optional[bool] = None,
    is_featured: Optional[bool] = None,
    category_ids: Optional[List[int]] = None,
    tag_ids: Optional[List[int]] = None
) -> int:
    """Bulk update multiple posts"""
    posts = db.query(BlogPost).filter(BlogPost.id.in_(post_ids)).all()
    
    for post in posts:
        if published is not None:
            post.published = published
            if published and not post.published_at:
                post.published_at = datetime.utcnow()
        
        if is_featured is not None:
            post.is_featured = is_featured
        
        if category_ids is not None:
            categories = db.query(BlogCategory).filter(BlogCategory.id.in_(category_ids)).all()
            post.categories = categories
        
        if tag_ids is not None:
            tags = db.query(BlogTag).filter(BlogTag.id.in_(tag_ids)).all()
            post.tags = tags
    
    db.commit()
    return len(posts)


def increment_view_count(db: Session, post_id: int) -> bool:
    """Increment view count for a post"""
    post = db.query(BlogPost).filter(BlogPost.id == post_id).first()
    if post:
        post.view_count += 1
        db.commit()
        return True
    return False


def get_popular_posts(db: Session, limit: int = 5) -> List[BlogPost]:
    """Get most viewed published posts"""
    return db.query(BlogPost).options(
        joinedload(BlogPost.tags),
        joinedload(BlogPost.categories)
    ).filter(
        BlogPost.published == True
    ).order_by(desc(BlogPost.view_count)).limit(limit).all()


def get_recent_posts(db: Session, limit: int = 5) -> List[BlogPost]:
    """Get most recent published posts"""
    return db.query(BlogPost).options(
        joinedload(BlogPost.tags),
        joinedload(BlogPost.categories)
    ).filter(
        BlogPost.published == True
    ).order_by(desc(BlogPost.published_at)).limit(limit).all()


def get_featured_posts(db: Session, limit: int = 5) -> List[BlogPost]:
    """Get featured published posts"""
    return db.query(BlogPost).options(
        joinedload(BlogPost.tags),
        joinedload(BlogPost.categories)
    ).filter(
        BlogPost.published == True,
        BlogPost.is_featured == True
    ).order_by(desc(BlogPost.published_at)).limit(limit).all()


def get_blog_stats(db: Session) -> dict:
    """Get blog statistics for homepage"""
    # Total published posts
    total_posts = db.query(BlogPost).filter(BlogPost.published == True).count()

    # Total categories
    total_categories = db.query(BlogCategory).count()

    # Total views across all posts
    total_views = db.query(func.sum(BlogPost.view_count)).scalar() or 0

    # Total tags
    total_tags = db.query(BlogTag).count()

    return {
        "total_posts": total_posts,
        "total_categories": total_categories,
        "total_views": total_views,
        "total_tags": total_tags
    }