# Backend\app\main.py
"""
The IT Apprentice LMS - Learning Management System
FastAPI application with JWT authentication, CMS, and LMS plugins
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os

from app.core.config import settings
from app.core.database import engine, Base

# Import routers
from app.auth.routes import router as auth_router
from app.auth.oauth import router as oauth_router
from app.auth.verification_routes import router as verification_router
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
from app.api.v1.endpoints.admin.users import router as admin_users_router
from app.api.v1.endpoints.admin.plugins import router as admin_plugins_router
from app.api.v1.endpoints.admin.system import router as admin_system_router
from app.api.v1.endpoints.admin.activities import router as admin_activities_router
from app.api.v1.endpoints.admin.stats import router as admin_stats_router

# Plugin routers (conditional imports based on settings.PLUGINS_ENABLED)
if settings.PLUGINS_ENABLED.get("tutorials", False):
    from app.plugins.tutorials.routes import router as tutorials_router

if settings.PLUGINS_ENABLED.get("courses", False):
    from app.plugins.courses.routes import router as courses_router

if settings.PLUGINS_ENABLED.get("typing_game", False):
    from app.plugins.typing_game.routes import router as typing_game_router
    from app.websocket.pvp_handler import pvp_router as pvp_websocket_router

if settings.PLUGINS_ENABLED.get("quizzes", False):
    from app.plugins.quizzes.routes import router as quizzes_router

# Shared plugin routes (XP, Achievements, Progress - always enabled)
from app.plugins.shared.routes import router as progress_router

# Create tables (for development only - use Alembic in production)
if settings.ENVIRONMENT == "development":
    Base.metadata.create_all(bind=engine)

# Initialize FastAPI app
app = FastAPI(
    title="The IT Apprentice LMS API",
    description="Learning Management System with tutorials, typing games, XP/achievements, and CMS",
    version="2.0.0",
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
app.include_router(oauth_router, prefix="/api/v1", tags=["OAuth"])
app.include_router(verification_router, prefix="/api/v1", tags=["Email Verification"])
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
app.include_router(admin_users_router, prefix="/api/v1", tags=["Admin - Users"])
app.include_router(admin_plugins_router, prefix="/api/v1", tags=["Admin - Plugins"])
app.include_router(admin_system_router, prefix="/api/v1", tags=["Admin - System"])
app.include_router(admin_activities_router, prefix="/api/v1", tags=["Admin - Activities"])
app.include_router(admin_stats_router, prefix="/api/v1", tags=["Admin - Stats"])

# Mount plugin routers (conditional based on settings.PLUGINS_ENABLED)
if settings.PLUGINS_ENABLED.get("tutorials", False):
    app.include_router(tutorials_router, prefix="/api/v1/tutorials", tags=["Tutorials - LMS"])

if settings.PLUGINS_ENABLED.get("courses", False):
    app.include_router(courses_router, prefix="/api/v1/courses", tags=["Courses - LMS"])

if settings.PLUGINS_ENABLED.get("typing_game", False):
    app.include_router(typing_game_router, prefix="/api/v1", tags=["Typing Game - LMS"])
    # WebSocket routes for PVP (no prefix - WebSocket paths are absolute)
    app.include_router(pvp_websocket_router, tags=["Typing Game - WebSocket"])

if settings.PLUGINS_ENABLED.get("quizzes", False):
    app.include_router(quizzes_router, prefix="/api/v1", tags=["Quizzes - LMS"])

# Shared plugin routes (XP, Achievements, Progress)
app.include_router(progress_router, prefix="/api/v1", tags=["Progress & Achievements"])

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
