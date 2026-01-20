# backend/app/websocket/__init__.py
"""
WebSocket module for real-time features
- PVP typing game matches
- Live opponent progress
- Match notifications
"""

from .manager import ConnectionManager
from .pvp_handler import pvp_router

__all__ = ["ConnectionManager", "pvp_router"]
