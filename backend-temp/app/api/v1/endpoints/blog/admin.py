# Backend\app\api\v1\endpoints\blog\admin.py
"""Admin blog management routes - Authentication required"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional
import math

from app.core.database import get_db
from app.auth.dependencies import get_current_admin_user
from app.users.models import User
from app.api.v1.services.blog import crud
from app.api.v1.services.blog.schemas import (
    BlogPostCreate,
    BlogPostUpdate,
    BlogPostResponse,
    BlogPostListResponse,
    BulkPostUpdate,
    BlogCategoryCreate,
    BlogCategoryUpdate,
    BlogCategoryResponse,
    BlogTagCreate,
    BlogTagUpdate,
    BlogTagResponse
)

router = APIRouter(tags=["Blog - Admin"])


# ============================================================================
# POST MANAGEMENT
# ============================================================================

@router.get("/admin/blog/posts", response_model=BlogPostListResponse)
async def admin_get_all_posts(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    search: Optional[str] = None,
    published: Optional[bool] = None,
    category_id: Optional[int] = None,
    is_featured: Optional[bool] = None,
    sort_by: str = Query("created_at", regex="^(created_at|published_at|view_count|title)$"),
    sort_order: str = Query("desc", regex="^(asc|desc)$"),
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Admin: Get all posts with advanced filtering"""
    skip = (page - 1) * page_size
    
    posts, total = crud.get_posts(
        db,
        skip=skip,
        limit=page_size,
        published_only=False,
        category_id=category_id,
        search=search,
        is_featured=is_featured,
        sort_by=sort_by,
        sort_order=sort_order
    )
    
    # Filter by published status if specified
    if published is not None:
        posts = [p for p in posts if p.published == published]
        total = len(posts)
    
    total_pages = math.ceil(total / page_size) if total > 0 else 0
    
    return {
        "posts": posts,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages
    }


@router.get("/admin/blog/posts/{post_id}", response_model=BlogPostResponse)
async def admin_get_post(
    post_id: int,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Admin: Get any post by ID"""
    post = crud.get_post(db, post_id)
    if not post:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Blog post not found"
        )
    return post


@router.post("/admin/blog/posts", response_model=BlogPostResponse, status_code=status.HTTP_201_CREATED)
async def admin_create_post(
    post: BlogPostCreate,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Admin: Create new blog post"""
    return crud.create_post(db, post, author_id=current_user.id)


@router.put("/admin/blog/posts/{post_id}", response_model=BlogPostResponse)
async def admin_update_post(
    post_id: int,
    post_update: BlogPostUpdate,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Admin: Update existing blog post"""
    updated_post = crud.update_post(db, post_id, post_update)
    if not updated_post:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Blog post not found"
        )
    return updated_post


@router.delete("/admin/blog/posts/{post_id}", status_code=status.HTTP_204_NO_CONTENT)
async def admin_delete_post(
    post_id: int,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Admin: Delete blog post"""
    if not crud.delete_post(db, post_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Blog post not found"
        )
    return None


@router.patch("/admin/blog/posts/{post_id}/publish", response_model=BlogPostResponse)
async def admin_toggle_publish(
    post_id: int,
    published: bool,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Admin: Publish or unpublish a post"""
    post_update = BlogPostUpdate(published=published)
    updated_post = crud.update_post(db, post_id, post_update)
    if not updated_post:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Blog post not found"
        )
    return updated_post


@router.post("/admin/blog/posts/bulk-update", response_model=dict)
async def admin_bulk_update_posts(
    bulk_update: BulkPostUpdate,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Admin: Bulk update multiple posts"""
    updated_count = crud.bulk_update_posts(
        db,
        post_ids=bulk_update.post_ids,
        published=bulk_update.published,
        is_featured=bulk_update.is_featured,
        category_ids=bulk_update.category_ids,
        tag_ids=bulk_update.tag_ids
    )
    
    return {
        "message": f"Successfully updated {updated_count} posts",
        "updated_count": updated_count
    }


# ============================================================================
# CATEGORY MANAGEMENT
# ============================================================================

@router.get("/admin/blog/categories", response_model=List[BlogCategoryResponse])
async def admin_get_categories(
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Admin: Get all categories"""
    return crud.get_categories(db)


@router.post("/admin/blog/categories", response_model=BlogCategoryResponse, status_code=status.HTTP_201_CREATED)
async def admin_create_category(
    category: BlogCategoryCreate,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Admin: Create new category"""
    return crud.create_category(db, category)


@router.put("/admin/blog/categories/{category_id}", response_model=BlogCategoryResponse)
async def admin_update_category(
    category_id: int,
    category_update: BlogCategoryUpdate,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Admin: Update category"""
    updated_category = crud.update_category(db, category_id, category_update)
    if not updated_category:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Category not found"
        )
    return updated_category


@router.delete("/admin/blog/categories/{category_id}", status_code=status.HTTP_204_NO_CONTENT)
async def admin_delete_category(
    category_id: int,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Admin: Delete category"""
    if not crud.delete_category(db, category_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Category not found"
        )
    return None


# ============================================================================
# TAG MANAGEMENT
# ============================================================================

@router.post("/admin/blog/tags", response_model=BlogTagResponse, status_code=status.HTTP_201_CREATED)
async def admin_create_tag(
    tag: BlogTagCreate,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Admin: Create new tag"""
    return crud.create_tag(db, tag)


@router.put("/admin/blog/tags/{tag_id}", response_model=BlogTagResponse)
async def admin_update_tag(
    tag_id: int,
    tag_update: BlogTagUpdate,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Admin: Update tag"""
    updated_tag = crud.update_tag(db, tag_id, tag_update)
    if not updated_tag:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tag not found"
        )
    return updated_tag


@router.delete("/admin/blog/tags/{tag_id}", status_code=status.HTTP_204_NO_CONTENT)
async def admin_delete_tag(
    tag_id: int,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Admin: Delete tag"""
    if not crud.delete_tag(db, tag_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tag not found"
        )
    return None