# backend/app/websocket/manager.py
"""
WebSocket Connection Manager
Handles all WebSocket connections for real-time features
"""
from typing import Dict, List, Optional, Set
from fastapi import WebSocket
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class ConnectionManager:
    """
    Manages WebSocket connections for real-time communication.

    Supports:
    - User-specific connections (by user_id)
    - Match-specific rooms (by match_id)
    - Broadcasting to rooms
    - Direct messaging to users
    """

    def __init__(self):
        # user_id -> list of WebSocket connections (user can have multiple tabs)
        self.user_connections: Dict[int, List[WebSocket]] = {}

        # match_id -> set of user_ids in the match
        self.match_rooms: Dict[str, Set[int]] = {}

        # user_id -> current match_id (for quick lookup)
        self.user_match: Dict[int, str] = {}

    async def connect(self, websocket: WebSocket, user_id: int):
        """Accept a new WebSocket connection for a user."""
        await websocket.accept()

        if user_id not in self.user_connections:
            self.user_connections[user_id] = []

        self.user_connections[user_id].append(websocket)
        logger.info(f"User {user_id} connected via WebSocket. Total connections: {len(self.user_connections[user_id])}")

    def disconnect(self, websocket: WebSocket, user_id: int):
        """Remove a WebSocket connection for a user."""
        if user_id in self.user_connections:
            if websocket in self.user_connections[user_id]:
                self.user_connections[user_id].remove(websocket)

            # Clean up if no more connections
            if not self.user_connections[user_id]:
                del self.user_connections[user_id]

                # Also remove from match room if in one
                if user_id in self.user_match:
                    match_id = self.user_match[user_id]
                    self.leave_match(user_id, match_id)

        logger.info(f"User {user_id} disconnected from WebSocket")

    def join_match(self, user_id: int, match_id: str):
        """Add a user to a match room."""
        if match_id not in self.match_rooms:
            self.match_rooms[match_id] = set()

        self.match_rooms[match_id].add(user_id)
        self.user_match[user_id] = match_id
        logger.info(f"User {user_id} joined match room {match_id}")

    def leave_match(self, user_id: int, match_id: str):
        """Remove a user from a match room."""
        if match_id in self.match_rooms:
            self.match_rooms[match_id].discard(user_id)

            # Clean up empty rooms
            if not self.match_rooms[match_id]:
                del self.match_rooms[match_id]

        if user_id in self.user_match:
            del self.user_match[user_id]

        logger.info(f"User {user_id} left match room {match_id}")

    async def send_to_user(self, user_id: int, message: dict):
        """Send a message to all connections for a specific user."""
        if user_id in self.user_connections:
            dead_connections = []

            for websocket in self.user_connections[user_id]:
                try:
                    await websocket.send_json(message)
                except Exception as e:
                    logger.error(f"Failed to send to user {user_id}: {e}")
                    dead_connections.append(websocket)

            # Clean up dead connections
            for ws in dead_connections:
                self.user_connections[user_id].remove(ws)

    async def broadcast_to_match(self, match_id: str, message: dict, exclude_user: Optional[int] = None):
        """Broadcast a message to all users in a match room."""
        if match_id not in self.match_rooms:
            return

        for user_id in self.match_rooms[match_id]:
            if exclude_user and user_id == exclude_user:
                continue
            await self.send_to_user(user_id, message)

    async def send_match_update(self, match_id: str, event_type: str, data: dict, exclude_user: Optional[int] = None):
        """Send a typed match update to all users in a match."""
        message = {
            "type": event_type,
            "match_id": match_id,
            "timestamp": datetime.utcnow().isoformat(),
            "data": data
        }
        await self.broadcast_to_match(match_id, message, exclude_user)

    def get_match_users(self, match_id: str) -> Set[int]:
        """Get all user IDs in a match room."""
        return self.match_rooms.get(match_id, set())

    def is_user_connected(self, user_id: int) -> bool:
        """Check if a user has any active connections."""
        return user_id in self.user_connections and len(self.user_connections[user_id]) > 0

    def get_user_match(self, user_id: int) -> Optional[str]:
        """Get the match ID a user is currently in."""
        return self.user_match.get(user_id)


# Global connection manager instance
manager = ConnectionManager()
