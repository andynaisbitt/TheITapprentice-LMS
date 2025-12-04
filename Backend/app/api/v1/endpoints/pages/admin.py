# Backend\app\api\v1\endpoints\pages\admin.py
"""Admin endpoints for managing dynamic pages"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.core.database import get_db
from app.api.v1.services.pages import crud, schemas
from app.auth.dependencies import get_current_admin_user
from app.users.models import User

router = APIRouter()


@router.post("/admin/pages", response_model=schemas.PageResponse, status_code=status.HTTP_201_CREATED)
def create_page(
    page: schemas.PageCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Create a new page (admin only)"""
    # Check if slug already exists
    existing = crud.get_page_by_slug(db, page.slug, published_only=False)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Page with slug '{page.slug}' already exists"
        )

    return crud.create_page(db, page, current_user.id)


@router.get("/admin/pages", response_model=schemas.PageListResponse)
def list_pages(
    skip: int = 0,
    limit: int = 20,
    published_only: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """List all pages with pagination (admin only)"""
    pages, total = crud.get_pages(db, skip, limit, published_only)

    return {
        "pages": pages,
        "total": total,
        "page": (skip // limit) + 1,
        "page_size": limit,
        "total_pages": (total + limit - 1) // limit
    }


@router.get("/admin/pages/{page_id}", response_model=schemas.PageResponse)
def get_page(
    page_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Get a specific page by ID (admin only)"""
    page = crud.get_page_by_id(db, page_id)
    if not page:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Page with id {page_id} not found"
        )
    return page


@router.put("/admin/pages/{page_id}", response_model=schemas.PageResponse)
def update_page(
    page_id: int,
    page_update: schemas.PageUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Update a page (admin only)"""
    # If slug is being changed, check for conflicts
    if page_update.slug:
        existing = crud.get_page_by_slug(db, page_update.slug, published_only=False)
        if existing and existing.id != page_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Page with slug '{page_update.slug}' already exists"
            )

    updated_page = crud.update_page(db, page_id, page_update)
    if not updated_page:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Page with id {page_id} not found"
        )
    return updated_page


@router.delete("/admin/pages/{page_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_page(
    page_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Delete a page (admin only)"""
    success = crud.delete_page(db, page_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Page with id {page_id} not found"
        )
    return None
