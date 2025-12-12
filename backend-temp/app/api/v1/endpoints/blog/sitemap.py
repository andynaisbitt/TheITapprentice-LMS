# Backend\app\api\v1\endpoints\blog\sitemap.py
"""XML sitemap generation"""
from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session
from datetime import datetime
from xml.etree.ElementTree import Element, SubElement, tostring
from app.core.database import get_db
from app.api.v1.services.blog.models import BlogPost
from app.api.v1.services.pages.models import Page
from app.api.v1.services.site_settings.models import SiteSettings

router = APIRouter()


def generate_sitemap(posts: list, pages: list, site_url: str = "http://localhost:5174") -> str:
    """Generate XML sitemap"""

    # Create urlset root element
    urlset = Element('urlset', attrib={
        'xmlns': 'http://www.sitemaps.org/schemas/sitemap/0.9',
        'xmlns:xhtml': 'http://www.w3.org/1999/xhtml'
    })

    # Homepage
    url = SubElement(urlset, 'url')
    SubElement(url, 'loc').text = site_url
    SubElement(url, 'changefreq').text = 'daily'
    SubElement(url, 'priority').text = '1.0'

    # Static pages
    static_pages = [
        {'path': '/about', 'priority': '0.8'},
        {'path': '/contact', 'priority': '0.8'},
        {'path': '/privacy', 'priority': '0.5'},
        {'path': '/terms', 'priority': '0.5'},
    ]

    for page_info in static_pages:
        url = SubElement(urlset, 'url')
        SubElement(url, 'loc').text = f"{site_url}{page_info['path']}"
        SubElement(url, 'changefreq').text = 'monthly'
        SubElement(url, 'priority').text = page_info['priority']

    # Dynamic pages
    for page in pages:
        url = SubElement(urlset, 'url')
        SubElement(url, 'loc').text = f"{site_url}/pages/{page.slug}"
        if page.updated_at:
            SubElement(url, 'lastmod').text = page.updated_at.strftime('%Y-%m-%d')
        else:
            SubElement(url, 'lastmod').text = page.created_at.strftime('%Y-%m-%d')
        SubElement(url, 'changefreq').text = 'weekly'
        SubElement(url, 'priority').text = '0.7'

    # Blog posts
    for post in posts:
        url = SubElement(urlset, 'url')
        SubElement(url, 'loc').text = f"{site_url}/blog/{post.slug}"
        if post.updated_at:
            SubElement(url, 'lastmod').text = post.updated_at.strftime('%Y-%m-%d')
        else:
            SubElement(url, 'lastmod').text = post.published_at.strftime('%Y-%m-%d')
        SubElement(url, 'changefreq').text = 'weekly'
        SubElement(url, 'priority').text = '0.6'

    # Convert to string with XML declaration
    xml_str = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml_str += tostring(urlset, encoding='unicode')

    return xml_str


@router.get("/sitemap.xml", response_class=Response)
def get_sitemap(db: Session = Depends(get_db)):
    """Generate XML sitemap for all published content"""

    # Get site settings
    settings = db.query(SiteSettings).filter(SiteSettings.id == 1).first()
    site_url = settings.site_url if settings else "https://yourdomain.com"

    # Get all published blog posts
    posts = db.query(BlogPost).filter(
        BlogPost.published == True
    ).order_by(
        BlogPost.published_at.desc()
    ).all()

    # Get all published dynamic pages
    pages = db.query(Page).filter(
        Page.published == True
    ).order_by(
        Page.created_at.desc()
    ).all()

    sitemap_content = generate_sitemap(posts, pages, site_url=site_url)

    return Response(
        content=sitemap_content,
        media_type="application/xml"
    )
