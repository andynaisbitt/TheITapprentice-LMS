# Backend/app/auth/websocket_auth.py
"""
WebSocket JWT Authentication
Handles authentication for WebSocket connections using JWT tokens
"""
from fastapi import WebSocket, WebSocketException, status
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from typing import Optional
import logging

from app.core.config import settings
from app.users.models import User

logger = logging.getLogger(__name__)


async def get_user_from_websocket_token(
    websocket: WebSocket,
    db: Session,
    token: Optional[str] = None
) -> User:
    """
    Authenticate WebSocket connection using JWT token.
    Token can be passed via query parameter: ?token=...

    Args:
        websocket: WebSocket connection
        db: Database session
        token: JWT token (from query params)

    Returns:
        User: Authenticated user

    Raises:
        WebSocketException: If authentication fails
    """
    # Get token from query parameter if not provided
    if not token:
        token = websocket.query_params.get("token")

    if not token:
        logger.warning(f"WebSocket auth failed: No token provided for {websocket.url.path}")
        raise WebSocketException(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="Authentication token required"
        )

    try:
        # Decode JWT token
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=["HS256"]
        )
        email: str = payload.get("sub")

        if email is None:
            logger.warning("WebSocket auth failed: No email in token payload")
            raise WebSocketException(
                code=status.WS_1008_POLICY_VIOLATION,
                reason="Invalid token payload"
            )

    except JWTError as e:
        logger.warning(f"WebSocket JWT validation failed: {str(e)}")
        raise WebSocketException(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="Invalid or expired token"
        )

    # Get user from database
    user = db.query(User).filter(User.email == email).first()

    if user is None:
        logger.warning(f"WebSocket auth failed: User not found: {email}")
        raise WebSocketException(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="User not found"
        )

    if not user.is_active:
        logger.warning(f"WebSocket auth failed: Inactive user: {email}")
        raise WebSocketException(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="Account is inactive"
        )

    logger.info(f"WebSocket authenticated: {user.email} (ID: {user.id})")
    return user


def get_token_from_cookie(cookie_header: Optional[str]) -> Optional[str]:
    """
    Extract JWT token from cookie header string.

    Args:
        cookie_header: Cookie header string (e.g., "auth_token=xxx; session=yyy")

    Returns:
        str: JWT token if found, None otherwise
    """
    if not cookie_header:
        return None

    # Parse cookies
    cookies = {}
    for cookie in cookie_header.split(';'):
        cookie = cookie.strip()
        if '=' in cookie:
            key, value = cookie.split('=', 1)
            cookies[key.strip()] = value.strip()

    return cookies.get(settings.COOKIE_NAME)


async def get_user_from_websocket_cookie(
    websocket: WebSocket,
    db: Session
) -> User:
    """
    Authenticate WebSocket connection using cookie-based JWT token.

    Note: WebSocket clients don't automatically send cookies in browsers,
    so this method may not work in all scenarios. Prefer query parameter auth.

    Args:
        websocket: WebSocket connection
        db: Database session

    Returns:
        User: Authenticated user

    Raises:
        WebSocketException: If authentication fails
    """
    # Get cookie header
    cookie_header = websocket.headers.get("cookie")
    token = get_token_from_cookie(cookie_header)

    if not token:
        logger.warning("WebSocket auth failed: No token in cookies")
        raise WebSocketException(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="Authentication token required"
        )

    return await get_user_from_websocket_token(websocket, db, token)
