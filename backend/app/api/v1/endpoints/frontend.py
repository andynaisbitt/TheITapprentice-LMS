# Backend/app/api/v1/endpoints/frontend.py
"""
Frontend HTML serving with dynamic script injection
Injects Google Analytics and AdSense scripts into index.html based on site settings
"""
from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from pathlib import Path
import os

from app.core.database import get_db
from app.api.v1.services.site_settings.crud import get_site_settings

router = APIRouter()

# Path to frontend build
FRONTEND_DIST = Path(__file__).parent.parent.parent.parent.parent.parent / "Frontend" / "dist"
INDEX_HTML_PATH = FRONTEND_DIST / "index.html"


def inject_analytics_scripts(html: str, google_analytics_id: str = None, google_adsense_client_id: str = None) -> str:
    """
    Inject Google Analytics and AdSense scripts into HTML head

    Args:
        html: Original HTML content
        google_analytics_id: GA4 Measurement ID (G-XXXXXXXXXX)
        google_adsense_client_id: AdSense Client ID (ca-pub-XXXXXXXXXXXXXXXX)

    Returns:
        Modified HTML with scripts injected
    """
    scripts = []

    # Google AdSense Auto Ads (must come FIRST for Google's crawler to detect)
    if google_adsense_client_id and google_adsense_client_id.startswith('ca-pub-'):
        adsense_script = f'''
    <!-- Google AdSense Auto Ads -->
    <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client={google_adsense_client_id}"
            crossorigin="anonymous"></script>'''
        scripts.append(adsense_script)

    # Google Analytics 4 (optional - already loaded by React component)
    # Including here for crawler visibility
    if google_analytics_id and google_analytics_id.startswith('G-'):
        ga_script = f'''
    <!-- Google Analytics 4 -->
    <script async src="https://www.googletagmanager.com/gtag/js?id={google_analytics_id}"></script>
    <script>
      window.dataLayer = window.dataLayer || [];
      function gtag(){{dataLayer.push(arguments);}}
      gtag('js', new Date());
      gtag('config', '{google_analytics_id}', {{
        'anonymize_ip': true,
        'cookie_flags': 'SameSite=None;Secure'
      }});
    </script>'''
        scripts.append(ga_script)

    if scripts:
        # Inject before closing </head> tag
        scripts_html = '\n'.join(scripts)
        html = html.replace('</head>', f'{scripts_html}\n  </head>')

    return html


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
@router.get("/{full_path:path}", response_class=HTMLResponse, include_in_schema=False)
async def serve_frontend(request: Request, full_path: str = "", db: Session = Depends(get_db)):
    """
    Serve frontend HTML with dynamically injected analytics scripts

    This ensures Google's crawler sees the AdSense script in the initial HTML
    """
    # Get site settings for analytics IDs
    settings = get_site_settings(db)

    # Read index.html
    if not INDEX_HTML_PATH.exists():
        return HTMLResponse(
            content="<h1>Frontend not built</h1><p>Run: cd Frontend && npm run build</p>",
            status_code=503
        )

    with open(INDEX_HTML_PATH, 'r', encoding='utf-8') as f:
        html_content = f.read()

    # Inject analytics scripts
    html_content = inject_analytics_scripts(
        html_content,
        google_analytics_id=settings.google_analytics_id,
        google_adsense_client_id=settings.google_adsense_client_id
    )

    return HTMLResponse(content=html_content)
