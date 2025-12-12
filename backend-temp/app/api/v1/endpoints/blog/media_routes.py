# Backend\app\api\v1\endpoints\blog\media_routes.py
"""Media upload and management routes"""
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import Optional, List

from app.core.database import get_db
from app.auth.dependencies import get_current_admin_user
from app.users.models import User
from .media import upload_blog_image, delete_blog_image, get_media_library, update_media_metadata
from app.api.v1.services.blog.models import BlogMedia

router = APIRouter(tags=["Blog - Media"])


@router.post("/admin/blog/media/upload")
async def upload_image(
    file: UploadFile = File(...),
    alt_text: Optional[str] = None,
    caption: Optional[str] = None,
    optimize: bool = True,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Upload blog image

    - **file**: Image file (max 10MB)
    - **alt_text**: Alt text for accessibility (optional)
    - **caption**: Image caption (optional)
    - **optimize**: Auto-optimize image (default: true)

    Allowed formats: JPEG, PNG, GIF, WebP
    """
    try:
        media = await upload_blog_image(
            file=file,
            db=db,
            user_id=current_user.id,
            alt_text=alt_text,
            caption=caption,
            optimize=optimize
        )

        return {
            "id": media.id,
            "filename": media.filename,
            "url": media.file_url,
            "file_size": media.file_size,
            "width": media.width,
            "height": media.height,
            "alt_text": media.alt_text,
            "caption": media.caption,
            "created_at": media.created_at
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Upload failed: {str(e)}"
        )


@router.get("/admin/blog/media")
async def list_media(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Get media library with pagination"""
    skip = (page - 1) * page_size

    media_list, total = get_media_library(
        db=db,
        user_id=None,  # Show all media
        skip=skip,
        limit=page_size
    )

    total_pages = (total + page_size - 1) // page_size

    return {
        "media": [
            {
                "id": m.id,
                "filename": m.filename,
                "original_filename": m.original_filename,
                "url": m.file_url,
                "file_size": m.file_size,
                "width": m.width,
                "height": m.height,
                "alt_text": m.alt_text,
                "caption": m.caption,
                "created_at": m.created_at,
            }
            for m in media_list
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages
    }


@router.patch("/admin/blog/media/{media_id}")
async def update_media(
    media_id: int,
    alt_text: Optional[str] = None,
    caption: Optional[str] = None,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Update media metadata (alt text, caption)"""
    media = update_media_metadata(
        db=db,
        media_id=media_id,
        alt_text=alt_text,
        caption=caption
    )

    if not media:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Media not found"
        )

    return {
        "id": media.id,
        "filename": media.filename,
        "url": media.file_url,
        "alt_text": media.alt_text,
        "caption": media.caption
    }


@router.delete("/admin/blog/media/{media_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_media(
    media_id: int,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Delete media file"""
    success = delete_blog_image(db=db, media_id=media_id, user_id=current_user.id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Media not found"
        )

    return None
