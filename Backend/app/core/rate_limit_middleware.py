"""
Enhanced Rate Limiting Middleware with Progressive Penalties and Monitoring
"""
from fastapi import Request, HTTPException, status
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from typing import Optional, Callable
import logging
from datetime import datetime, timedelta
from collections import defaultdict
import asyncio

from app.core.rate_limits import (
    RateLimitTier,
    RATE_LIMITS,
    CUSTOM_LIMITS,
    RATE_LIMIT_MESSAGES,
    PROGRESSIVE_PENALTIES,
    MONITORING_THRESHOLDS,
    is_whitelisted,
)

logger = logging.getLogger(__name__)


# ============================================================================
# VIOLATION TRACKING (In-memory - use Redis in production)
# ============================================================================
class ViolationTracker:
    """Track rate limit violations for progressive penalties"""

    def __init__(self):
        self.violations = defaultdict(list)  # ip -> [timestamps]
        self.bans = {}  # ip -> ban_until_timestamp

    def record_violation(self, ip: str) -> None:
        """Record a rate limit violation"""
        now = datetime.utcnow()
        self.violations[ip].append(now)

        # Clean old violations (24 hour window)
        cutoff = now - timedelta(hours=24)
        self.violations[ip] = [v for v in self.violations[ip] if v > cutoff]

        # Check for ban threshold
        if len(self.violations[ip]) >= PROGRESSIVE_PENALTIES["ban_threshold"]:
            self.ban_ip(ip, hours=24)
            logger.warning(f"IP {ip} banned for 24 hours after {len(self.violations[ip])} violations")

    def get_violation_count(self, ip: str, hours: int = 24) -> int:
        """Get violation count for IP in time window"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        return len([v for v in self.violations[ip] if v > cutoff])

    def ban_ip(self, ip: str, hours: int = 24) -> None:
        """Ban IP for specified hours"""
        self.bans[ip] = datetime.utcnow() + timedelta(hours=hours)

    def is_banned(self, ip: str) -> bool:
        """Check if IP is currently banned"""
        if ip not in self.bans:
            return False

        if datetime.utcnow() >= self.bans[ip]:
            del self.bans[ip]
            return False

        return True

    def get_penalty_multiplier(self, ip: str) -> float:
        """Get rate limit penalty multiplier based on violation history"""
        count = self.get_violation_count(ip, hours=1)  # Last hour

        if count == 0:
            return PROGRESSIVE_PENALTIES["first_violation"]
        elif count == 1:
            return PROGRESSIVE_PENALTIES["second_violation"]
        elif count == 2:
            return PROGRESSIVE_PENALTIES["third_violation"]
        else:
            return PROGRESSIVE_PENALTIES["fourth_violation"]


# Global tracker instance
violation_tracker = ViolationTracker()


# ============================================================================
# ENHANCED RATE LIMITER
# ============================================================================
def get_real_ip(request: Request) -> str:
    """
    Get real client IP, considering proxies

    Checks (in order):
    1. X-Forwarded-For header (proxy)
    2. X-Real-IP header (nginx)
    3. Direct client IP
    """
    # Check X-Forwarded-For (most common proxy header)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Take first IP (client IP) if multiple proxies
        return forwarded.split(",")[0].strip()

    # Check X-Real-IP (nginx)
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip

    # Fallback to direct client
    return request.client.host if request.client else "unknown"


def get_user_identifier(request: Request) -> Optional[str]:
    """
    Get user identifier from JWT token in cookie

    Returns user_id or email if authenticated, None otherwise
    """
    try:
        from jose import jwt
        from app.core.config import settings

        # Get token from cookie
        token = request.cookies.get(settings.COOKIE_NAME)
        if not token:
            return None

        # Decode token
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        return payload.get("sub")  # Email

    except Exception:
        return None


# ============================================================================
# RATE LIMIT KEY FUNCTIONS
# ============================================================================
def rate_limit_key_ip(request: Request) -> str:
    """Rate limit key based on IP"""
    return get_real_ip(request)


def rate_limit_key_user(request: Request) -> str:
    """Rate limit key based on user (falls back to IP if not authenticated)"""
    user_id = get_user_identifier(request)
    if user_id:
        return f"user:{user_id}"
    return f"ip:{get_real_ip(request)}"


def rate_limit_key_ip_and_user(request: Request) -> str:
    """Rate limit key based on both IP and user"""
    ip = get_real_ip(request)
    user_id = get_user_identifier(request)
    if user_id:
        return f"ip:{ip}:user:{user_id}"
    return f"ip:{ip}"


# ============================================================================
# RATE LIMITER INSTANCES
# ============================================================================

# Primary limiter (per-IP)
limiter = Limiter(
    key_func=rate_limit_key_ip,
    default_limits=["1000/hour"],  # Global fallback
    storage_uri="memory://",       # Use Redis in production: "redis://localhost:6379"
    strategy="fixed-window",
)

# Secondary limiter (per-user)
user_limiter = Limiter(
    key_func=rate_limit_key_user,
    storage_uri="memory://",
    strategy="fixed-window",
)

# Combined limiter (IP + user)
combined_limiter = Limiter(
    key_func=rate_limit_key_ip_and_user,
    storage_uri="memory://",
    strategy="moving-window",  # More accurate for combined limits
)


# ============================================================================
# CUSTOM EXCEPTION HANDLER
# ============================================================================
async def rate_limit_exception_handler(request: Request, exc: RateLimitExceeded):
    """
    Custom handler for rate limit exceeded

    Features:
    - Records violation for progressive penalties
    - Checks for ban status
    - Returns helpful error message with retry time
    """
    ip = get_real_ip(request)

    # Check whitelist
    if is_whitelisted(ip):
        return  # Allow whitelisted IPs

    # Record violation
    violation_tracker.record_violation(ip)

    # Get violation info
    violation_count = violation_tracker.get_violation_count(ip, hours=1)

    # Determine message
    tier = RateLimitTier.PUBLIC_READ  # Default
    message = RATE_LIMIT_MESSAGES.get(tier, "Rate limit exceeded. Please try again later.")

    # Calculate retry_after (from exception if available)
    retry_after = getattr(exc, "retry_after", 60)

    # Log the violation
    logger.warning(
        f"Rate limit exceeded - IP: {ip}, "
        f"Path: {request.url.path}, "
        f"Violations (1h): {violation_count}, "
        f"Retry after: {retry_after}s"
    )

    # Check for excessive violations (potential attack)
    if violation_count >= MONITORING_THRESHOLDS["alert_if_hit_count"]:
        logger.error(
            f"SECURITY ALERT - Excessive rate limit violations from IP: {ip}, "
            f"Count: {violation_count} in last hour"
        )

    # Auto-ban for extreme abuse
    if violation_count >= MONITORING_THRESHOLDS["auto_ban_if_hit_count"]:
        violation_tracker.ban_ip(ip, hours=24)
        logger.critical(f"IP {ip} auto-banned for 24 hours due to excessive violations")

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your IP has been temporarily banned due to excessive requests. Please contact support if this is a mistake.",
        )

    # Return rate limit error
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=message.format(retry_after=retry_after),
        headers={"Retry-After": str(retry_after)},
    )


# ============================================================================
# BAN CHECK MIDDLEWARE
# ============================================================================
async def check_ip_ban(request: Request) -> None:
    """
    Middleware to check if IP is banned

    Raises HTTPException if banned
    """
    ip = get_real_ip(request)

    # Check whitelist
    if is_whitelisted(ip):
        return

    # Check ban status
    if violation_tracker.is_banned(ip):
        logger.warning(f"Banned IP attempted access: {ip} - Path: {request.url.path}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your IP has been temporarily banned due to excessive requests. Please try again later or contact support.",
        )


# ============================================================================
# HELPER DECORATORS FOR COMMON PATTERNS
# ============================================================================
def limit_by_tier(tier: RateLimitTier):
    """
    Decorator to apply rate limit based on tier

    Usage:
        @router.post("/some-endpoint")
        @limit_by_tier(RateLimitTier.WRITE)
        async def my_endpoint(...):
            ...
    """
    def decorator(func: Callable):
        # Apply per-IP limit
        ip_limit = RATE_LIMITS[tier]["per_ip"]
        if ip_limit:
            func = limiter.limit(ip_limit)(func)

        # Apply per-user limit if specified
        user_limit = RATE_LIMITS[tier]["per_user"]
        if user_limit:
            func = user_limiter.limit(user_limit)(func)

        return func

    return decorator


# ============================================================================
# MONITORING & METRICS
# ============================================================================
class RateLimitMetrics:
    """Track rate limiting metrics for monitoring"""

    def __init__(self):
        self.total_requests = 0
        self.rate_limited_requests = 0
        self.banned_ips = set()
        self.top_violators = defaultdict(int)

    def record_request(self):
        """Record a request"""
        self.total_requests += 1

    def record_violation(self, ip: str):
        """Record a violation"""
        self.rate_limited_requests += 1
        self.top_violators[ip] += 1

    def record_ban(self, ip: str):
        """Record an IP ban"""
        self.banned_ips.add(ip)

    def get_stats(self) -> dict:
        """Get current metrics"""
        return {
            "total_requests": self.total_requests,
            "rate_limited_requests": self.rate_limited_requests,
            "rate_limit_percentage": (
                (self.rate_limited_requests / self.total_requests * 100)
                if self.total_requests > 0
                else 0
            ),
            "banned_ips_count": len(self.banned_ips),
            "top_violators": dict(sorted(
                self.top_violators.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
        }

    def reset(self):
        """Reset metrics (for daily/hourly resets)"""
        self.total_requests = 0
        self.rate_limited_requests = 0
        self.top_violators.clear()


# Global metrics instance
rate_limit_metrics = RateLimitMetrics()


# ============================================================================
# ADMIN ENDPOINTS FOR RATE LIMIT MANAGEMENT
# ============================================================================
def get_violation_stats(ip: Optional[str] = None) -> dict:
    """Get violation statistics"""
    if ip:
        return {
            "ip": ip,
            "violations_1h": violation_tracker.get_violation_count(ip, hours=1),
            "violations_24h": violation_tracker.get_violation_count(ip, hours=24),
            "is_banned": violation_tracker.is_banned(ip),
            "penalty_multiplier": violation_tracker.get_penalty_multiplier(ip),
        }

    return {
        "total_tracked_ips": len(violation_tracker.violations),
        "total_banned_ips": len(violation_tracker.bans),
        "metrics": rate_limit_metrics.get_stats(),
    }


def unban_ip(ip: str) -> bool:
    """Manually unban an IP (admin function)"""
    if ip in violation_tracker.bans:
        del violation_tracker.bans[ip]
        logger.info(f"IP {ip} manually unbanned by admin")
        return True
    return False


def clear_violations(ip: str) -> bool:
    """Clear violation history for an IP (admin function)"""
    if ip in violation_tracker.violations:
        violation_tracker.violations[ip] = []
        logger.info(f"Violation history cleared for IP {ip}")
        return True
    return False
