# Backend\app\api\v1\services\pages\crud.py
"""CRUD operations for dynamic pages"""
from sqlalchemy.orm import Session
from typing import List, Tuple, Optional
from .models import Page
from .schemas import PageCreate, PageUpdate


def get_page_by_slug(db: Session, slug: str, published_only: bool = True) -> Optional[Page]:
    """Get page by slug"""
    query = db.query(Page).filter(Page.slug == slug)
    if published_only:
        query = query.filter(Page.published == True)
    return query.first()


def get_page_by_canonical_url(db: Session, canonical_url: str) -> Optional[Page]:
    """Get page by canonical URL"""
    return db.query(Page).filter(Page.canonical_url == canonical_url).first()


def get_page_by_id(db: Session, page_id: int) -> Optional[Page]:
    """Get page by ID"""
    return db.query(Page).filter(Page.id == page_id).first()


def get_pages(
    db: Session,
    skip: int = 0,
    limit: int = 20,
    published_only: bool = True
) -> Tuple[List[Page], int]:
    """Get all pages with pagination"""
    query = db.query(Page)

    if published_only:
        query = query.filter(Page.published == True)

    total = query.count()
    pages = query.order_by(Page.created_at.desc()).offset(skip).limit(limit).all()

    return pages, total


def create_page(db: Session, page: PageCreate, user_id: int) -> Page:
    """Create new page"""
    db_page = Page(
        **page.model_dump(),
        created_by=user_id
    )
    db.add(db_page)
    db.commit()
    db.refresh(db_page)
    return db_page


def update_page(db: Session, page_id: int, page_update: PageUpdate) -> Optional[Page]:
    """Update existing page"""
    db_page = get_page_by_id(db, page_id)

    if not db_page:
        return None

    update_data = page_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_page, field, value)

    db.commit()
    db.refresh(db_page)
    return db_page


def delete_page(db: Session, page_id: int) -> bool:
    """Delete page"""
    db_page = get_page_by_id(db, page_id)

    if not db_page:
        return False

    db.delete(db_page)
    db.commit()
    return True
