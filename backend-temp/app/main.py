# Backend\app\main.py
"""
BlogCMS - Minimal Blog Platform
FastAPI application with JWT authentication and blog management
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os

from app.core.config import settings
from app.core.database import engine, Base

# Import routers
from app.auth.routes import router as auth_router
from app.api.v1.endpoints.blog.public import router as blog_public_router
from app.api.v1.endpoints.blog.admin import router as blog_admin_router
from app.api.v1.endpoints.blog.media_routes import router as blog_media_router
from app.api.v1.endpoints.pages.admin import router as pages_admin_router
from app.api.v1.endpoints.pages.public import router as pages_public_router
from app.api.v1.endpoints.blog.rss import router as rss_router
from app.api.v1.endpoints.blog.sitemap import router as sitemap_router
from app.api.v1.endpoints.navigation.public import router as navigation_public_router
from app.api.v1.endpoints.navigation.admin import router as navigation_admin_router
from app.api.v1.endpoints.theme.public import router as theme_public_router
from app.api.v1.endpoints.theme.admin import router as theme_admin_router
from app.api.v1.endpoints.site_settings.admin import router as site_settings_admin_router
from app.api.v1.endpoints.site_settings.public import router as site_settings_public_router
from app.api.v1.endpoints.newsletter.public import router as newsletter_public_router
from app.api.v1.endpoints.newsletter.admin import router as newsletter_admin_router
from app.api.v1.endpoints.content import router as content_router

# Create tables (for development only - use Alembic in production)
if settings.ENVIRONMENT == "development":
    Base.metadata.create_all(bind=engine)

# Initialize FastAPI app
app = FastAPI(
    title="BlogCMS API",
    description="Minimal blog platform with authentication and CMS",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files (for uploaded media)
if not os.path.exists("static"):
    os.makedirs("static")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Register routers
app.include_router(auth_router, tags=["Authentication"])
app.include_router(blog_public_router, prefix="/api/v1", tags=["Blog - Public"])
app.include_router(blog_admin_router, prefix="/api/v1", tags=["Blog - Admin"])
app.include_router(blog_media_router, prefix="/api/v1", tags=["Blog - Media"])
app.include_router(pages_admin_router, prefix="/api/v1", tags=["Pages - Admin"])
app.include_router(pages_public_router, prefix="/api/v1", tags=["Pages - Public"])
app.include_router(navigation_public_router, prefix="/api/v1", tags=["Navigation - Public"])
app.include_router(navigation_admin_router, prefix="/api/v1", tags=["Navigation - Admin"])
app.include_router(theme_public_router, prefix="/api/v1", tags=["Theme - Public"])
app.include_router(theme_admin_router, prefix="/api/v1", tags=["Theme - Admin"])
app.include_router(site_settings_public_router, prefix="/api/v1", tags=["Site Settings - Public"])
app.include_router(site_settings_admin_router, prefix="/api/v1", tags=["Site Settings - Admin"])
app.include_router(newsletter_public_router, prefix="/api/v1", tags=["Newsletter - Public"])
app.include_router(newsletter_admin_router, prefix="/api/v1", tags=["Newsletter - Admin"])
app.include_router(content_router, prefix="/api/v1", tags=["Content - Unified"])
app.include_router(rss_router, prefix="/api/v1", tags=["RSS/Sitemap"])
app.include_router(sitemap_router, prefix="/api/v1", tags=["RSS/Sitemap"])

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "app": "BlogCMS", "version": "1.0.0"}

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "BlogCMS API",
        "docs": "/docs",
        "health": "/health"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8100)
