"""
Centralized Rate Limiting Configuration
Provides comprehensive protection against API abuse, DDoS, and resource exhaustion
"""
from typing import Dict
from enum import Enum


class RateLimitTier(str, Enum):
    """Rate limit tiers based on endpoint risk and resource usage"""

    # Authentication & Security (Strictest)
    AUTH = "auth"                    # Login, registration, password reset

    # Data Modification (Strict)
    WRITE = "write"                  # POST, PUT, DELETE operations

    # Expensive Operations (Moderate-Strict)
    EXPENSIVE = "expensive"          # Certificate generation, PDF creation, complex queries

    # Public Read (Moderate)
    PUBLIC_READ = "public_read"      # Public content access (no auth required)

    # Authenticated Read (Lenient)
    AUTH_READ = "auth_read"          # User's own data, course content

    # Uploads (Strict)
    UPLOAD = "upload"                # File uploads

    # Admin (Lenient - trusted users)
    ADMIN = "admin"                  # Admin operations

    # WebSocket (Special)
    WEBSOCKET = "websocket"          # Real-time connections


# Rate Limit Definitions
# Format: "requests/time_window"
# Time windows: second, minute, hour, day
RATE_LIMITS: Dict[RateLimitTier, Dict[str, str]] = {

    # ============================================================================
    # AUTHENTICATION & SECURITY (Prevent brute force, credential stuffing)
    # ============================================================================
    RateLimitTier.AUTH: {
        "per_ip": "5/minute",        # 5 login attempts per IP per minute
        "per_user": "10/hour",       # 10 login attempts per account per hour
        "description": "Login, registration, password reset",
        "burst": False,              # No burst allowed for auth
    },

    # ============================================================================
    # DATA MODIFICATION (Prevent spam, abuse)
    # ============================================================================
    RateLimitTier.WRITE: {
        "per_ip": "30/minute",       # 30 writes per IP per minute
        "per_user": "100/hour",      # 100 writes per user per hour
        "description": "POST, PUT, DELETE operations",
        "burst": True,               # Allow short bursts (e.g., saving course progress)
    },

    # ============================================================================
    # EXPENSIVE OPERATIONS (Prevent resource exhaustion)
    # ============================================================================
    RateLimitTier.EXPENSIVE: {
        "per_ip": "10/minute",       # 10 expensive ops per IP per minute
        "per_user": "30/hour",       # 30 expensive ops per user per hour
        "description": "Certificate generation, PDF creation, complex analytics",
        "burst": False,              # No burst for expensive ops
    },

    # ============================================================================
    # PUBLIC READ (Prevent scraping, DDoS)
    # ============================================================================
    RateLimitTier.PUBLIC_READ: {
        "per_ip": "100/minute",      # 100 reads per IP per minute
        "per_user": None,            # No user limit (may not be authenticated)
        "description": "Public courses, blog posts, certificate verification",
        "burst": True,               # Allow normal browsing patterns
    },

    # ============================================================================
    # AUTHENTICATED READ (Lenient - legitimate user activity)
    # ============================================================================
    RateLimitTier.AUTH_READ: {
        "per_ip": "200/minute",      # 200 reads per IP per minute
        "per_user": "1000/hour",     # 1000 reads per user per hour
        "description": "User's own data, enrolled courses, progress",
        "burst": True,               # Allow fast page navigation
    },

    # ============================================================================
    # FILE UPLOADS (Prevent storage exhaustion)
    # ============================================================================
    RateLimitTier.UPLOAD: {
        "per_ip": "10/hour",         # 10 uploads per IP per hour
        "per_user": "20/hour",       # 20 uploads per user per hour
        "description": "Image/file uploads",
        "burst": False,              # No burst for uploads
    },

    # ============================================================================
    # ADMIN OPERATIONS (Lenient - trusted users)
    # ============================================================================
    RateLimitTier.ADMIN: {
        "per_ip": "500/minute",      # High limit for admin tools
        "per_user": "5000/hour",     # Very high hourly limit
        "description": "Admin panel operations",
        "burst": True,               # Allow admin workflows
    },

    # ============================================================================
    # WEBSOCKET CONNECTIONS (Prevent connection flooding)
    # ============================================================================
    RateLimitTier.WEBSOCKET: {
        "per_ip": "10/minute",       # 10 new connections per minute
        "per_user": "20/hour",       # 20 connections per user per hour
        "description": "WebSocket connections (PVP)",
        "burst": False,              # No burst for connections
    },
}


# ============================================================================
# ENDPOINT-SPECIFIC RATE LIMITS
# For endpoints that need custom limits beyond tier defaults
# ============================================================================
CUSTOM_LIMITS = {
    # Auth endpoints (strictest)
    "/auth/login": "5/minute",
    "/auth/register": "3/hour",              # Prevent account spam
    "/auth/password-reset": "3/hour",        # Prevent email spam

    # Quiz attempts (prevent answer farming)
    "/quizzes/start": "10/hour",             # 10 quiz attempts per hour
    "/quizzes/submit": "10/hour",            # Match start limit

    # Certificate generation (expensive)
    "/certificates/generate": "5/hour",      # Limit PDF generation
    "/certificates/download": "20/hour",     # Limit downloads

    # Typing game (prevent score manipulation)
    "/games/typing/start": "30/hour",        # 30 games per hour
    "/games/typing/submit": "30/hour",       # Match start limit

    # PVP matchmaking (prevent queue flooding)
    "/games/pvp/matchmaking": "20/hour",     # 20 matchmaking attempts

    # Course enrollment (prevent spam)
    "/courses/enroll": "20/hour",            # 20 enrollments per hour

    # Blog post creation (prevent spam)
    "/blog/posts": "5/hour",                 # 5 blog posts per hour

    # Comment/discussion posting (prevent spam)
    "/community/discussions": "20/hour",     # 20 discussions per hour
    "/community/replies": "50/hour",         # 50 replies per hour

    # File uploads (storage protection)
    "/blog/media/upload": "10/hour",         # 10 image uploads per hour

    # Email-triggering endpoints (prevent email spam)
    "/users/verify-email": "3/hour",
    "/users/resend-verification": "3/hour",

    # Password changes (security)
    "/users/change-password": "5/hour",      # Limit password changes

    # Public certificate verification (prevent scraping)
    "/certificates/verify": "100/minute",    # Allow employers to verify

    # Leaderboard queries (expensive)
    "/skills/leaderboard": "20/minute",      # Limit leaderboard queries
    "/games/pvp/leaderboard": "20/minute",
}


# ============================================================================
# BURST ALLOWANCE
# For endpoints that may have legitimate burst traffic
# ============================================================================
BURST_MULTIPLIER = {
    RateLimitTier.AUTH_READ: 1.5,      # Allow 50% more in short burst
    RateLimitTier.PUBLIC_READ: 2.0,    # Allow 2x in short burst
    RateLimitTier.WRITE: 1.3,          # Allow 30% more in short burst
}


# ============================================================================
# IP WHITELIST (for monitoring, health checks, etc.)
# ============================================================================
RATE_LIMIT_WHITELIST = [
    "127.0.0.1",           # Localhost
    # Add your monitoring IPs here
]


# ============================================================================
# RATE LIMIT RESPONSES
# ============================================================================
RATE_LIMIT_MESSAGES = {
    RateLimitTier.AUTH: "Too many authentication attempts. Please try again in {retry_after} seconds.",
    RateLimitTier.WRITE: "Too many requests. Please slow down and try again in {retry_after} seconds.",
    RateLimitTier.EXPENSIVE: "This operation is resource-intensive. Please wait {retry_after} seconds before trying again.",
    RateLimitTier.UPLOAD: "Upload limit reached. You can upload again in {retry_after} seconds.",
    RateLimitTier.PUBLIC_READ: "Too many requests. Please try again in {retry_after} seconds.",
    RateLimitTier.AUTH_READ: "Request limit exceeded. Please try again in {retry_after} seconds.",
    RateLimitTier.WEBSOCKET: "Connection limit reached. Please wait {retry_after} seconds before reconnecting.",
    RateLimitTier.ADMIN: "Admin rate limit exceeded. Please try again in {retry_after} seconds.",
}


# ============================================================================
# PROGRESSIVE RATE LIMITING
# Increase restrictions for repeat offenders
# ============================================================================
PROGRESSIVE_PENALTIES = {
    "first_violation": 1.0,      # Normal rate limit
    "second_violation": 0.5,     # 50% of normal limit (2x stricter)
    "third_violation": 0.25,     # 25% of normal limit (4x stricter)
    "fourth_violation": 0.1,     # 10% of normal limit (10x stricter)
    "ban_threshold": 5,          # Ban after 5 violations in 24 hours
}


# ============================================================================
# MONITORING THRESHOLDS
# Alert when limits are hit frequently (potential attack)
# ============================================================================
MONITORING_THRESHOLDS = {
    "alert_if_hit_count": 100,         # Alert if same IP hits limit 100 times/hour
    "auto_ban_if_hit_count": 1000,     # Auto-ban if 1000 hits/hour
    "suspicious_pattern_window": 300,   # Check patterns every 5 minutes
}


def get_rate_limit(tier: RateLimitTier, per: str = "per_ip") -> str:
    """
    Get rate limit for a specific tier

    Args:
        tier: Rate limit tier
        per: 'per_ip' or 'per_user'

    Returns:
        Rate limit string (e.g., "5/minute")
    """
    return RATE_LIMITS[tier][per]


def get_custom_limit(endpoint: str) -> str:
    """
    Get custom rate limit for specific endpoint

    Args:
        endpoint: Endpoint path

    Returns:
        Rate limit string or None
    """
    return CUSTOM_LIMITS.get(endpoint)


def is_whitelisted(ip: str) -> bool:
    """Check if IP is whitelisted"""
    return ip in RATE_LIMIT_WHITELIST
