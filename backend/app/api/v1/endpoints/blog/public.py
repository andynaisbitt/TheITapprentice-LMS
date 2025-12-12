# Backend\app\api\v1\endpoints\blog\public.py
"""Public blog routes - No authentication required"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional
import math

from app.core.database import get_db
from app.api.v1.services.blog import crud
from app.api.v1.services.blog.schemas import (
    BlogPostListResponse,
    BlogPostPublic,
    BlogPostPublicDetail,
    BlogCategoryResponse,
    BlogTagResponse
)

router = APIRouter(tags=["Blog - Public"])


@router.get("/blog/posts", response_model=BlogPostListResponse)
async def get_published_posts(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(10, ge=1, le=50, description="Items per page"),
    category_id: Optional[int] = Query(None, description="Filter by category ID"),
    tag: Optional[str] = Query(None, description="Filter by tag slug"),
    search: Optional[str] = Query(None, description="Search in title/content"),
    featured_only: bool = Query(False, description="Show only featured posts"),
    db: Session = Depends(get_db)
):
    """Get list of published blog posts with pagination and filters"""
    skip = (page - 1) * page_size

    posts, total = crud.get_posts(
        db,
        skip=skip,
        limit=page_size,
        published_only=True,
        category_id=category_id,
        tag_slug=tag,
        search=search,
        is_featured=True if featured_only else None
    )

    total_pages = math.ceil(total / page_size) if total > 0 else 0

    return {
        "posts": posts,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages
    }


@router.get("/blog/posts/{slug}", response_model=BlogPostPublicDetail)
async def get_post_by_slug(slug: str, db: Session = Depends(get_db)):
    """Get a single published blog post by slug and increment view count"""
    post = crud.get_post_by_slug(db, slug)

    if not post or not post.published:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Blog post not found"
        )

    # Increment view count
    crud.increment_view_count(db, post.id)

    return post


@router.get("/blog/posts/featured/list", response_model=List[BlogPostPublic])
async def get_featured_posts(
    limit: int = Query(5, ge=1, le=10, description="Number of posts"),
    db: Session = Depends(get_db)
):
    """Get featured published posts"""
    return crud.get_featured_posts(db, limit)


@router.get("/blog/posts/popular/list", response_model=List[BlogPostPublic])
async def get_popular_posts(
    limit: int = Query(5, ge=1, le=10, description="Number of posts"),
    db: Session = Depends(get_db)
):
    """Get most popular published posts by view count"""
    return crud.get_popular_posts(db, limit)


@router.get("/blog/posts/recent/list", response_model=List[BlogPostPublic])
async def get_recent_posts(
    limit: int = Query(5, ge=1, le=10, description="Number of posts"),
    db: Session = Depends(get_db)
):
    """Get most recent published posts"""
    return crud.get_recent_posts(db, limit)


@router.get("/blog/categories", response_model=List[BlogCategoryResponse])
async def get_all_categories(
    parent_id: Optional[int] = Query(None, description="Filter by parent category"),
    db: Session = Depends(get_db)
):
    """Get all categories"""
    return crud.get_categories(db, parent_id=parent_id)


@router.get("/blog/categories/{slug}", response_model=BlogCategoryResponse)
async def get_category_by_slug(slug: str, db: Session = Depends(get_db)):
    """Get category details by slug"""
    category = crud.get_category_by_slug(db, slug)
    if not category:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Category not found"
        )
    return category


@router.get("/blog/tags", response_model=List[BlogTagResponse])
async def get_all_tags(db: Session = Depends(get_db)):
    """Get all available tags"""
    return crud.get_tags(db)


@router.get("/blog/tags/{slug}", response_model=BlogTagResponse)
async def get_tag_by_slug(slug: str, db: Session = Depends(get_db)):
    """Get tag details by slug"""
    tag = crud.get_tag_by_slug(db, slug)
    if not tag:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tag not found"
        )
    return tag


@router.get("/blog/stats")
async def get_blog_statistics(db: Session = Depends(get_db)):
    """Get blog statistics for homepage (total posts, categories, views, tags)"""
    return crud.get_blog_stats(db)


@router.get("/blog/posts/by-canonical", response_model=BlogPostPublicDetail)
async def get_post_by_canonical_url(
    url: str = Query(..., description="Canonical URL to lookup"),
    db: Session = Depends(get_db)
):
    """
    Get a published blog post by its canonical URL

    This endpoint allows looking up posts by their canonical URL,
    which is useful for SEO and handling duplicate content.
    """
    # Query the database for a post with this canonical URL
    post = crud.get_post_by_canonical_url(db, url)

    if not post or not post.published:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Blog post not found with this canonical URL"
        )

    # Don't increment view count for canonical lookups (it's metadata, not a view)
    return post


@router.get("/sitemap.xml")
async def get_sitemap(db: Session = Depends(get_db)):
    """Generate XML sitemap for SEO"""
    from fastapi.responses import Response
    from datetime import datetime

    posts, _ = crud.get_posts(db, skip=0, limit=1000, published_only=True)

    xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'

    # Homepage
    xml += '  <url>\n'
    xml += '    <loc>https://yourdomain.com/</loc>\n'
    xml += '    <changefreq>daily</changefreq>\n'
    xml += '    <priority>1.0</priority>\n'
    xml += '  </url>\n'

    # Blog posts
    for post in posts:
        xml += '  <url>\n'
        xml += f'    <loc>https://yourdomain.com/blog/{post.slug}</loc>\n'
        xml += f'    <lastmod>{post.updated_at or post.created_at}</lastmod>\n'
        xml += '    <changefreq>weekly</changefreq>\n'
        xml += '    <priority>0.8</priority>\n'
        xml += '  </url>\n'

    # Static pages
    for page in ['/about', '/contact', '/privacy', '/terms']:
        xml += '  <url>\n'
        xml += f'    <loc>https://yourdomain.com{page}</loc>\n'
        xml += '    <changefreq>monthly</changefreq>\n'
        xml += '    <priority>0.5</priority>\n'
        xml += '  </url>\n'

    xml += '</urlset>'

    return Response(content=xml, media_type="application/xml")


@router.get("/rss.xml")
async def get_rss_feed(db: Session = Depends(get_db)):
    """Generate RSS feed for blog posts"""
    from fastapi.responses import Response
    from datetime import datetime

    posts, _ = crud.get_posts(db, skip=0, limit=20, published_only=True, sort_by="created_at", sort_order="desc")

    xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">\n'
    xml += '  <channel>\n'
    xml += '    <title>Your Blog Title</title>\n'
    xml += '    <link>https://yourdomain.com</link>\n'
    xml += '    <description>Your blog description</description>\n'
    xml += '    <language>en-us</language>\n'
    xml += '    <atom:link href="https://yourdomain.com/rss.xml" rel="self" type="application/rss+xml"/>\n'

    for post in posts:
        xml += '    <item>\n'
        xml += f'      <title><![CDATA[{post.title}]]></title>\n'
        xml += f'      <link>https://yourdomain.com/blog/{post.slug}</link>\n'
        xml += f'      <description><![CDATA[{post.excerpt or post.content[:200]}]]></description>\n'
        xml += f'      <pubDate>{post.created_at.strftime("%a, %d %b %Y %H:%M:%S GMT")}</pubDate>\n'
        xml += f'      <guid>https://yourdomain.com/blog/{post.slug}</guid>\n'
        xml += '    </item>\n'

    xml += '  </channel>\n'
    xml += '</rss>'

    return Response(content=xml, media_type="application/xml")