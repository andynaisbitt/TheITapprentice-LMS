# Backend\app\api\v1\endpoints\pages\public.py
"""Public endpoints for viewing published pages"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List

from app.core.database import get_db
from app.api.v1.services.pages import crud, schemas

router = APIRouter()


@router.get("/pages/{slug}", response_model=schemas.PageResponse)
def get_page_by_slug(
    slug: str,
    db: Session = Depends(get_db)
):
    """Get a published page by slug (public endpoint)"""
    page = crud.get_page_by_slug(db, slug, published_only=True)
    if not page:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Page '{slug}' not found"
        )
    return page


@router.get("/pages/by-canonical", response_model=schemas.PageResponse)
def get_page_by_canonical_url(
    url: str = Query(..., description="Canonical URL to lookup"),
    db: Session = Depends(get_db)
):
    """
    Get a published page by its canonical URL

    This endpoint allows looking up pages by their canonical URL,
    which is useful for SEO and handling duplicate content.
    """
    page = crud.get_page_by_canonical_url(db, url)

    if not page or not page.published:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Page not found with this canonical URL"
        )

    return page


@router.get("/pages", response_model=schemas.PageListResponse)
def list_published_pages(
    skip: int = 0,
    limit: int = 20,
    db: Session = Depends(get_db)
):
    """List all published pages (public endpoint)"""
    pages, total = crud.get_pages(db, skip, limit, published_only=True)

    return {
        "pages": pages,
        "total": total,
        "page": (skip // limit) + 1,
        "page_size": limit,
        "total_pages": (total + limit - 1) // limit
    }
