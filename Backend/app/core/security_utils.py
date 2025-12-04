"""
Security Utilities - Email Masking, Input Sanitization, PII Protection
"""
import hashlib
import re
from typing import Optional
import logging


logger = logging.getLogger(__name__)


# ============================================================================
# EMAIL MASKING FOR LOGS (GDPR/Privacy Compliance)
# ============================================================================

def mask_email(email: str) -> str:
    """
    Mask email address for logging while maintaining some context

    Examples:
        user@example.com -> u***@e***.com
        john.doe@company.co.uk -> j***@c***.uk
        a@b.com -> a***@b***.com

    Args:
        email: Email address to mask

    Returns:
        Masked email string
    """
    if not email or '@' not in email:
        return "***@***.***"

    try:
        local, domain = email.split('@', 1)

        # Mask local part (keep first char)
        if len(local) > 0:
            masked_local = f"{local[0]}***"
        else:
            masked_local = "***"

        # Mask domain (keep first char and TLD)
        if '.' in domain:
            domain_parts = domain.rsplit('.', 1)
            domain_name = domain_parts[0]
            tld = domain_parts[1]

            if len(domain_name) > 0:
                masked_domain = f"{domain_name[0]}***"
            else:
                masked_domain = "***"

            masked_email = f"{masked_local}@{masked_domain}.{tld}"
        else:
            # No TLD (unusual but handle it)
            masked_email = f"{masked_local}@{domain[0] if domain else '***'}***"

        return masked_email

    except Exception as e:
        logger.error(f"Error masking email: {e}")
        return "***@***.***"


def hash_email(email: str, salt: str = "") -> str:
    """
    Create a consistent hash of email for tracking without exposing PII

    Useful for:
    - Analytics
    - Fraud detection
    - User tracking across sessions
    - GDPR-compliant logging

    Args:
        email: Email to hash
        salt: Optional salt for additional security

    Returns:
        SHA256 hash of email (hex string)
    """
    combined = f"{email}{salt}"
    return hashlib.sha256(combined.encode()).hexdigest()


def mask_ip(ip: str) -> str:
    """
    Mask IP address for logging

    Examples:
        192.168.1.100 -> 192.168.***.***
        2001:0db8:85a3:0000:0000:8a2e:0370:7334 -> 2001:0db8:****:****

    Args:
        ip: IP address to mask

    Returns:
        Masked IP string
    """
    if not ip:
        return "***.***.***"

    try:
        if ':' in ip:
            # IPv6
            parts = ip.split(':')
            if len(parts) >= 4:
                return f"{':'.join(parts[:2])}:****:****"
            return "****:****:****:****"
        else:
            # IPv4
            parts = ip.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.***.***"
            return "***.***.***"

    except Exception as e:
        logger.error(f"Error masking IP: {e}")
        return "***.***.***"


# ============================================================================
# INPUT SANITIZATION
# ============================================================================

def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent directory traversal and injection attacks

    Removes:
    - Path separators (/, \)
    - Null bytes
    - Control characters
    - Leading/trailing spaces and dots

    Args:
        filename: Original filename

    Returns:
        Sanitized filename
    """
    if not filename:
        return "unnamed"

    # Remove path separators
    filename = filename.replace('/', '_').replace('\\', '_')

    # Remove null bytes
    filename = filename.replace('\x00', '')

    # Remove control characters
    filename = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', filename)

    # Remove leading/trailing spaces and dots
    filename = filename.strip('. ')

    # If empty after sanitization, use default
    if not filename:
        return "unnamed"

    # Limit length (255 chars is filesystem limit)
    if len(filename) > 255:
        # Keep extension
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        max_name_len = 250 - len(ext)
        filename = f"{name[:max_name_len]}.{ext}" if ext else name[:255]

    return filename


def sanitize_search_query(query: str, max_length: int = 200) -> str:
    """
    Sanitize search query to prevent injection attacks

    Args:
        query: User search query
        max_length: Maximum allowed length

    Returns:
        Sanitized query
    """
    if not query:
        return ""

    # Remove null bytes
    query = query.replace('\x00', '')

    # Remove SQL injection patterns (defense in depth - ORM already protects)
    dangerous_patterns = [
        r'--',           # SQL comment
        r';',            # SQL statement terminator
        r'\bUNION\b',    # SQL UNION
        r'\bSELECT\b',   # SQL SELECT
        r'\bINSERT\b',   # SQL INSERT
        r'\bUPDATE\b',   # SQL UPDATE
        r'\bDELETE\b',   # SQL DELETE
        r'\bDROP\b',     # SQL DROP
        r'<script',      # XSS
        r'javascript:',  # XSS
        r'onerror=',     # XSS
        r'onclick=',     # XSS
    ]

    for pattern in dangerous_patterns:
        query = re.sub(pattern, '', query, flags=re.IGNORECASE)

    # Trim to max length
    query = query[:max_length]

    # Strip whitespace
    query = query.strip()

    return query


# ============================================================================
# SAFE LOGGING WRAPPERS
# ============================================================================

class SafeLogger:
    """
    Logger wrapper that automatically masks PII in log messages

    Usage:
        safe_logger = SafeLogger(logger)
        safe_logger.info("User {email} logged in", email="user@example.com")
        # Logs: "User u***@e***.com logged in"
    """

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def _mask_message(self, message: str, **kwargs) -> str:
        """Mask PII in message"""
        for key, value in kwargs.items():
            if isinstance(value, str):
                if '@' in value:  # Likely an email
                    masked = mask_email(value)
                elif key in ['ip', 'ip_address', 'client_ip']:
                    masked = mask_ip(value)
                else:
                    masked = value

                message = message.replace(f"{{{key}}}", masked)

        return message

    def debug(self, message: str, **kwargs):
        """Log debug with PII masking"""
        message = self._mask_message(message, **kwargs)
        self.logger.debug(message)

    def info(self, message: str, **kwargs):
        """Log info with PII masking"""
        message = self._mask_message(message, **kwargs)
        self.logger.info(message)

    def warning(self, message: str, **kwargs):
        """Log warning with PII masking"""
        message = self._mask_message(message, **kwargs)
        self.logger.warning(message)

    def error(self, message: str, **kwargs):
        """Log error with PII masking"""
        message = self._mask_message(message, **kwargs)
        self.logger.error(message)

    def critical(self, message: str, **kwargs):
        """Log critical with PII masking"""
        message = self._mask_message(message, **kwargs)
        self.logger.critical(message)


# ============================================================================
# PASSWORD STRENGTH VALIDATION
# ============================================================================

def check_password_strength(password: str) -> dict:
    """
    Check password strength and return detailed feedback

    Args:
        password: Password to check

    Returns:
        Dict with 'is_strong' (bool) and 'issues' (list of strings)
    """
    issues = []

    if len(password) < 8:
        issues.append("Password must be at least 8 characters long")

    if len(password) < 12:
        issues.append("Consider using at least 12 characters for better security")

    if not re.search(r'[a-z]', password):
        issues.append("Password should contain lowercase letters")

    if not re.search(r'[A-Z]', password):
        issues.append("Password should contain uppercase letters")

    if not re.search(r'\d', password):
        issues.append("Password should contain numbers")

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        issues.append("Password should contain special characters")

    # Check for common weak patterns
    common_patterns = [
        r'12345',
        r'password',
        r'qwerty',
        r'abc123',
        r'letmein',
    ]

    for pattern in common_patterns:
        if re.search(pattern, password, re.IGNORECASE):
            issues.append("Password contains common weak patterns")
            break

    return {
        "is_strong": len(issues) == 0,
        "score": max(0, 100 - (len(issues) * 15)),  # 100 = perfect, 0 = very weak
        "issues": issues,
    }


# ============================================================================
# SECURE RANDOM GENERATION
# ============================================================================

def generate_secure_token(length: int = 32) -> str:
    """
    Generate cryptographically secure random token

    Args:
        length: Length of token in bytes

    Returns:
        URL-safe base64-encoded token
    """
    import secrets
    return secrets.token_urlsafe(length)


def generate_verification_code(length: int = 6) -> str:
    """
    Generate numeric verification code for email/SMS

    Args:
        length: Number of digits

    Returns:
        Numeric string (e.g., "123456")
    """
    import secrets
    return ''.join(str(secrets.randbelow(10)) for _ in range(length))


# ============================================================================
# RATE LIMITING HELPERS
# ============================================================================

def calculate_backoff_time(attempt_count: int, base_delay: int = 60) -> int:
    """
    Calculate exponential backoff time for rate limiting

    Args:
        attempt_count: Number of failed attempts
        base_delay: Base delay in seconds

    Returns:
        Delay in seconds (capped at 1 hour)
    """
    # Exponential backoff: base_delay * 2^(attempt_count - 1)
    delay = base_delay * (2 ** (attempt_count - 1))

    # Cap at 1 hour
    return min(delay, 3600)


# ============================================================================
# CONTENT SECURITY
# ============================================================================

def is_safe_redirect_url(url: str, allowed_hosts: list) -> bool:
    """
    Check if redirect URL is safe (prevents open redirect vulnerabilities)

    Args:
        url: URL to check
        allowed_hosts: List of allowed hostnames

    Returns:
        True if URL is safe to redirect to
    """
    if not url:
        return False

    # Only allow relative URLs or URLs from allowed hosts
    if url.startswith('/'):
        return True

    from urllib.parse import urlparse
    parsed = urlparse(url)

    # Check if host is in allowed list
    return parsed.netloc in allowed_hosts


def strip_html_tags(text: str) -> str:
    """
    Strip HTML tags from text (basic XSS prevention)

    Note: Use this as defense-in-depth. React already handles XSS.

    Args:
        text: Text potentially containing HTML

    Returns:
        Text with HTML tags removed
    """
    import html
    # First, unescape any HTML entities
    text = html.unescape(text)
    # Remove all HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    return text
