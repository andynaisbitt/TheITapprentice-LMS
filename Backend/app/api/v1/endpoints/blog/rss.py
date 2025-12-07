# Backend\app\api\v1\endpoints\blog\rss.py
"""RSS feed generation"""
from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session
from datetime import datetime
from xml.etree.ElementTree import Element, SubElement, tostring
from app.core.database import get_db
from app.api.v1.services.blog.models import BlogPost

router = APIRouter()


def generate_rss_feed(posts: list, site_url: str = "http://localhost:5174") -> str:
    """Generate RSS 2.0 feed from blog posts"""

    # Create RSS root element
    rss = Element('rss', version='2.0', attrib={
        'xmlns:atom': 'http://www.w3.org/2005/Atom',
        'xmlns:content': 'http://purl.org/rss/1.0/modules/content/'
    })

    channel = SubElement(rss, 'channel')

    # Channel metadata
    SubElement(channel, 'title').text = 'BlogCMS'
    SubElement(channel, 'link').text = site_url
    SubElement(channel, 'description').text = 'Latest blog posts from BlogCMS'
    SubElement(channel, 'language').text = 'en-us'
    SubElement(channel, 'lastBuildDate').text = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')

    # Atom self link
    SubElement(channel, '{http://www.w3.org/2005/Atom}link', attrib={
        'href': f'{site_url}/rss.xml',
        'rel': 'self',
        'type': 'application/rss+xml'
    })

    # Add items
    for post in posts:
        item = SubElement(channel, 'item')

        SubElement(item, 'title').text = post.title
        SubElement(item, 'link').text = f'{site_url}/blog/{post.slug}'
        SubElement(item, 'guid', isPermaLink='true').text = f'{site_url}/blog/{post.slug}'

        # Handle null published_at
        if post.published_at:
            SubElement(item, 'pubDate').text = post.published_at.strftime('%a, %d %b %Y %H:%M:%S +0000')
        else:
            # Use created_at as fallback
            SubElement(item, 'pubDate').text = post.created_at.strftime('%a, %d %b %Y %H:%M:%S +0000')

        if post.excerpt:
            SubElement(item, 'description').text = post.excerpt

        if post.content:
            SubElement(item, '{http://purl.org/rss/1.0/modules/content/}encoded').text = f'<![CDATA[{post.content}]]>'

        if post.author:
            SubElement(item, 'author').text = post.author.email

        # Categories/tags
        if post.category:
            SubElement(item, 'category').text = post.category.name

        for tag in post.tags:
            SubElement(item, 'category').text = tag.name

    # Convert to string with XML declaration
    xml_str = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml_str += tostring(rss, encoding='unicode')

    return xml_str


@router.get("/rss.xml", response_class=Response)
def get_rss_feed(db: Session = Depends(get_db)):
    """Generate RSS feed for published blog posts"""

    # Get latest 50 published posts
    posts = db.query(BlogPost).filter(
        BlogPost.published == True
    ).order_by(
        BlogPost.published_at.desc()
    ).limit(50).all()

    rss_content = generate_rss_feed(posts)

    return Response(
        content=rss_content,
        media_type="application/rss+xml"
    )
