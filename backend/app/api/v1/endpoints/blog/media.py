# Backend\app\api\v1\endpoints\blog\media.py
"""File upload handler for blog media - Security Hardened"""
import os
import shutil
import uuid
import io
import xml.etree.ElementTree as ET
from typing import Optional, Tuple
from datetime import datetime
from pathlib import Path
from PIL import Image
from fastapi import UploadFile, HTTPException, status
from sqlalchemy.orm import Session
import logging

from ...services.blog.models import BlogMedia
from app.core.config import settings
from app.core.security_utils import sanitize_filename

logger = logging.getLogger(__name__)

# Configuration
UPLOAD_DIR = Path("static/blog/uploads")
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp", "image/svg+xml"}
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg"}

# Create upload directory if it doesn't exist
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def validate_svg(file_content: bytes) -> None:
    """
    Validate SVG file for security
    Prevents XSS attacks by checking for dangerous elements
    """
    try:
        # Parse SVG XML
        root = ET.fromstring(file_content)

        # Dangerous elements that could execute scripts
        dangerous_tags = {'script', 'iframe', 'object', 'embed', 'foreignObject'}

        # Check all elements in the SVG
        for elem in root.iter():
            # Get tag name without namespace
            tag = elem.tag.split('}')[-1].lower() if '}' in elem.tag else elem.tag.lower()

            if tag in dangerous_tags:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"SVG contains forbidden element: {tag}"
                )

            # Check for event handlers in attributes (onclick, onload, etc.)
            for attr_name in elem.attrib:
                if attr_name.lower().startswith('on'):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"SVG contains forbidden event handler: {attr_name}"
                    )

        logger.info("SVG validation passed")
    except ET.ParseError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid SVG file: {str(e)}"
        )


def validate_image(file: UploadFile) -> None:
    """Validate uploaded image file"""

    # Check file extension
    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File type not allowed. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    # Check MIME type
    if file.content_type not in ALLOWED_IMAGE_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file type. Must be an image."
        )


def get_image_dimensions(file_path: Path) -> Tuple[int, int]:
    """Get image width and height"""
    try:
        with Image.open(file_path) as img:
            return img.size
    except Exception:
        return (0, 0)


def optimize_image(file_path: Path, max_width: int = 1920, quality: int = 85) -> None:
    """Optimize image size and quality"""
    try:
        with Image.open(file_path) as img:
            # Convert RGBA to RGB if necessary
            if img.mode == 'RGBA':
                background = Image.new('RGB', img.size, (255, 255, 255))
                background.paste(img, mask=img.split()[3])  # Alpha channel
                img = background
            
            # Resize if too large
            if img.width > max_width:
                ratio = max_width / img.width
                new_height = int(img.height * ratio)
                img = img.resize((max_width, new_height), Image.LANCZOS)
            
            # Save optimized
            img.save(file_path, optimize=True, quality=quality)
    except Exception as e:
        print(f"Image optimization failed: {e}")
        # Continue even if optimization fails


async def upload_blog_image(
    file: UploadFile,
    db: Session,
    user_id: int,
    alt_text: Optional[str] = None,
    caption: Optional[str] = None,
    optimize: bool = True
) -> BlogMedia:
    """
    Upload and process blog image with enhanced security

    Security Features:
    - File type validation (extension + MIME + content)
    - Size limits enforced
    - Malicious content detection
    - Filename sanitization
    - Image re-encoding (strips EXIF/metadata)

    Rate Limited: 10 uploads per hour per user (applied at router level)

    Args:
        file: Uploaded file
        db: Database session
        user_id: ID of user uploading
        alt_text: Alt text for accessibility
        caption: Image caption
        optimize: Whether to optimize the image

    Returns:
        BlogMedia object with file details
    """

    # Sanitize original filename to prevent directory traversal
    safe_filename = sanitize_filename(file.filename) if file.filename else "unnamed"
    logger.info(f"Upload attempt: {safe_filename} by user {user_id}")

    # Validate file type (extension + MIME)
    validate_image(file)

    # Read file content for size check and validation
    file_content = await file.read()
    file_size = len(file_content)

    # Check file size
    if file_size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File too large. Maximum size: {MAX_FILE_SIZE / 1024 / 1024}MB"
        )

    # Determine if file is SVG
    file_ext = Path(safe_filename).suffix.lower()
    is_svg = file_ext == '.svg'

    # Validate based on file type
    if is_svg:
        # Validate SVG for security (no scripts, no event handlers)
        validate_svg(file_content)
        logger.info("SVG file validated successfully")
    else:
        # Validate raster image is actually a valid image (prevents corrupted/malicious files)
        try:
            img = Image.open(io.BytesIO(file_content))
            img.verify()  # Verifies image integrity
            logger.info(f"Image verified: {img.format} {img.size}")
        except Exception as e:
            logger.warning(f"Invalid image file uploaded: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File is not a valid image or is corrupted"
            )

    # Reset file pointer for saving
    await file.seek(0)

    # Generate unique filename (no user input used)
    file_ext = Path(safe_filename).suffix.lower()
    unique_filename = f"{uuid.uuid4().hex}{file_ext}"
    
    # Organize by date
    date_path = datetime.now().strftime("%Y/%m")
    upload_path = UPLOAD_DIR / date_path
    upload_path.mkdir(parents=True, exist_ok=True)
    
    file_path = upload_path / unique_filename
    
    # Save file
    try:
        with file_path.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save file: {str(e)}"
        )

    # Optimize image if requested (skip for SVG files)
    if optimize and not is_svg:
        optimize_image(file_path)
    
    # Get final file size and dimensions
    final_size = file_path.stat().st_size

    # Get dimensions (SVG files will return 0, 0 which is fine)
    width, height = get_image_dimensions(file_path) if not is_svg else (0, 0)
    
    # Generate URL (relative to static directory)
    relative_path = str(file_path.relative_to(Path("static")))
    file_url = f"/static/{relative_path.replace(os.sep, '/')}"
    
    # Create database record
    db_media = BlogMedia(
        filename=unique_filename,
        original_filename=file.filename,
        file_path=str(file_path),
        file_url=file_url,
        file_size=final_size,
        mime_type=file.content_type,
        width=width,
        height=height,
        alt_text=alt_text,
        caption=caption,
        uploaded_by=user_id
    )
    
    db.add(db_media)
    db.commit()
    db.refresh(db_media)
    
    return db_media


def delete_blog_image(db: Session, media_id: int, user_id: int) -> bool:
    """
    Delete blog image from filesystem and database
    
    Args:
        db: Database session
        media_id: ID of media to delete
        user_id: ID of user requesting deletion
    
    Returns:
        True if deleted, False if not found
    """
    media = db.query(BlogMedia).filter(BlogMedia.id == media_id).first()
    
    if not media:
        return False
    
    # Check permissions (user must be uploader or admin)
    # TODO: Add admin check when you have user roles
    if media.uploaded_by != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to delete this file"
        )
    
    # Delete file from filesystem
    try:
        file_path = Path(media.file_path)
        if file_path.exists():
            file_path.unlink()
    except Exception as e:
        print(f"Failed to delete file: {e}")
        # Continue with database deletion even if file delete fails
    
    # Delete from database
    db.delete(media)
    db.commit()
    
    return True


def get_media_library(
    db: Session,
    user_id: Optional[int] = None,
    skip: int = 0,
    limit: int = 50
) -> Tuple[list[BlogMedia], int]:
    """
    Get media library with pagination
    
    Args:
        db: Database session
        user_id: Filter by uploader (None for all)
        skip: Pagination offset
        limit: Items per page
    
    Returns:
        Tuple of (media_list, total_count)
    """
    query = db.query(BlogMedia)
    
    if user_id:
        query = query.filter(BlogMedia.uploaded_by == user_id)
    
    total = query.count()
    media = query.order_by(BlogMedia.created_at.desc()).offset(skip).limit(limit).all()
    
    return media, total


def update_media_metadata(
    db: Session,
    media_id: int,
    alt_text: Optional[str] = None,
    caption: Optional[str] = None
) -> Optional[BlogMedia]:
    """Update media metadata (alt text, caption)"""
    media = db.query(BlogMedia).filter(BlogMedia.id == media_id).first()
    
    if not media:
        return None
    
    if alt_text is not None:
        media.alt_text = alt_text
    
    if caption is not None:
        media.caption = caption
    
    db.commit()
    db.refresh(media)
    
    return media