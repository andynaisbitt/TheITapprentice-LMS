# Backend/app/api/v1/endpoints/content.py
"""Unified content lookup endpoints - for blog posts and pages"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import Literal, Dict, Any

from app.core.database import get_db
from app.api.v1.services.blog import crud as blog_crud
from app.api.v1.services.pages import crud as pages_crud

router = APIRouter(tags=["Content - Unified"])


@router.get("/content/by-canonical")
async def get_content_by_canonical_url(
    url: str = Query(..., description="Canonical URL to lookup"),
    db: Session = Depends(get_db)
):
    """
    Get content (blog post or page) by canonical URL

    This endpoint searches both blog posts and pages for the given canonical URL.
    It returns the content type (post/page), slug, and full data.

    This is useful for:
    - Canonical URL routing (resolve canonical URL to actual content)
    - SSR servers (fetch content for any canonical URL)
    - SEO tools (validate canonical URLs)

    Returns:
        - type: "post" or "page"
        - slug: The URL slug of the content
        - data: Full content object (BlogPost or Page)
    """
    # Try blog posts first (more common)
    post = blog_crud.get_post_by_canonical_url(db, url)
    if post and post.published:
        return {
            "type": "post",
            "slug": post.slug,
            "data": post
        }

    # Try pages second
    page = pages_crud.get_page_by_canonical_url(db, url)
    if page and page.published:
        return {
            "type": "page",
            "slug": page.slug,
            "data": page
        }

    # Not found in either
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"No published content found with canonical URL: {url}"
    )
