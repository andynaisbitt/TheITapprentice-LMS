# backend/app/websocket/pvp_handler.py
"""
WebSocket handler for PVP typing game matches
Handles real-time communication during matches
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query
from sqlalchemy.orm import Session
import json
import logging
from typing import Optional
from datetime import datetime

from app.core.database import get_db
from app.users.models import User
from app.plugins.typing_game.models import PVPMatch, MatchStatus
from app.plugins.typing_game import crud as typing_crud
from .manager import manager

logger = logging.getLogger(__name__)

pvp_router = APIRouter()


async def get_user_from_token(token: str, db: Session) -> Optional[User]:
    """Validate token and return user. Simplified for now."""
    # In production, this should properly validate JWT token
    # For now, we'll accept user_id directly for simplicity
    try:
        from app.auth.dependencies import get_current_user_from_token
        user = await get_current_user_from_token(token, db)
        return user
    except Exception as e:
        logger.error(f"Token validation failed: {e}")
        return None


@pvp_router.websocket("/ws/pvp/{match_id}")
async def pvp_websocket(
    websocket: WebSocket,
    match_id: str,
    token: str = Query(...),
):
    """
    WebSocket endpoint for PVP match communication.

    Message Types (Client -> Server):
    - join: Join the match room
    - progress: Update typing progress (words typed, but not the actual text)
    - round_complete: Signal round completion
    - forfeit: Forfeit the match
    - ping: Keep-alive ping

    Message Types (Server -> Client):
    - match_joined: Confirmation of joining
    - opponent_joined: Opponent has connected
    - opponent_progress: Opponent's typing progress
    - round_started: New round has started
    - round_ended: Round has ended with results
    - match_ended: Match has ended with final results
    - opponent_disconnected: Opponent has disconnected
    - error: Error message
    - pong: Response to ping
    """
    # Get database session
    from app.core.database import SessionLocal
    db = SessionLocal()

    try:
        # Validate user
        user = await get_user_from_token(token, db)
        if not user:
            await websocket.close(code=4001, reason="Invalid authentication")
            return

        user_id = user.id

        # Validate match exists and user is a participant
        match = db.query(PVPMatch).filter(PVPMatch.match_id == match_id).first()
        if not match:
            await websocket.close(code=4004, reason="Match not found")
            return

        if user_id not in [match.player1_id, match.player2_id]:
            await websocket.close(code=4003, reason="Not a participant in this match")
            return

        # Connect user
        await manager.connect(websocket, user_id)
        manager.join_match(user_id, match_id)

        # Notify user of successful join
        await manager.send_to_user(user_id, {
            "type": "match_joined",
            "match_id": match_id,
            "user_id": user_id,
            "player_number": 1 if user_id == match.player1_id else 2,
            "match_status": match.status.value,
            "current_round": match.current_round,
            "total_rounds": match.total_rounds,
        })

        # Notify opponent that we joined
        opponent_id = match.player2_id if user_id == match.player1_id else match.player1_id
        if opponent_id and manager.is_user_connected(opponent_id):
            await manager.send_to_user(opponent_id, {
                "type": "opponent_joined",
                "match_id": match_id,
                "opponent_id": user_id,
            })

        # Handle incoming messages
        try:
            while True:
                data = await websocket.receive_json()
                await handle_pvp_message(websocket, user_id, match_id, data, db)
        except WebSocketDisconnect:
            logger.info(f"User {user_id} disconnected from match {match_id}")

            # Notify opponent of disconnection
            if opponent_id:
                await manager.send_to_user(opponent_id, {
                    "type": "opponent_disconnected",
                    "match_id": match_id,
                    "opponent_id": user_id,
                })

    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await websocket.close(code=4000, reason=str(e))

    finally:
        manager.disconnect(websocket, user_id if 'user_id' in locals() else 0)
        db.close()


async def handle_pvp_message(
    websocket: WebSocket,
    user_id: int,
    match_id: str,
    data: dict,
    db: Session
):
    """Handle incoming PVP WebSocket messages."""
    message_type = data.get("type")

    if message_type == "ping":
        await manager.send_to_user(user_id, {"type": "pong"})
        return

    if message_type == "progress":
        # User is reporting their typing progress
        # We only share progress percentage, not actual text (anti-cheat)
        progress = data.get("progress", 0)  # 0-100 percentage
        words_typed = data.get("words_typed", 0)
        current_wpm = data.get("current_wpm", 0)

        # Broadcast to opponent (but not the actual typed text)
        await manager.send_match_update(
            match_id,
            "opponent_progress",
            {
                "user_id": user_id,
                "progress": min(100, max(0, progress)),  # Clamp 0-100
                "words_typed": words_typed,
                "current_wpm": current_wpm,
            },
            exclude_user=user_id
        )

    elif message_type == "round_ready":
        # User signals they're ready for the round
        await manager.send_match_update(
            match_id,
            "player_ready",
            {"user_id": user_id},
            exclude_user=user_id
        )

    elif message_type == "round_complete":
        # User completed their round - actual submission goes through REST API
        # This just notifies the opponent
        wpm = data.get("wpm", 0)
        accuracy = data.get("accuracy", 0)

        await manager.send_match_update(
            match_id,
            "opponent_finished",
            {
                "user_id": user_id,
                "wpm": wpm,
                "accuracy": accuracy,
            },
            exclude_user=user_id
        )

    elif message_type == "forfeit":
        # User forfeits the match
        match = db.query(PVPMatch).filter(PVPMatch.match_id == match_id).first()
        if match and match.status == MatchStatus.IN_PROGRESS:
            # Determine winner (the other player)
            winner_id = match.player2_id if user_id == match.player1_id else match.player1_id

            match.status = MatchStatus.COMPLETED
            match.winner_id = winner_id
            match.completed_at = datetime.utcnow()
            db.commit()

            # Notify both players
            await manager.broadcast_to_match(match_id, {
                "type": "match_ended",
                "match_id": match_id,
                "reason": "forfeit",
                "forfeit_by": user_id,
                "winner_id": winner_id,
            })

    elif message_type == "chat":
        # In-match chat (optional feature)
        message_text = data.get("message", "")[:200]  # Limit message length

        await manager.broadcast_to_match(match_id, {
            "type": "chat",
            "user_id": user_id,
            "message": message_text,
            "timestamp": datetime.utcnow().isoformat(),
        })

    else:
        await manager.send_to_user(user_id, {
            "type": "error",
            "message": f"Unknown message type: {message_type}"
        })


# Utility functions for REST API to trigger WebSocket events

async def notify_match_started(match_id: str, text_content: str, time_limit: int):
    """Notify all users in a match that the round has started."""
    await manager.broadcast_to_match(match_id, {
        "type": "round_started",
        "match_id": match_id,
        "text_content": text_content,
        "time_limit": time_limit,
        "timestamp": datetime.utcnow().isoformat(),
    })


async def notify_round_ended(match_id: str, round_number: int, results: dict):
    """Notify all users that a round has ended."""
    await manager.broadcast_to_match(match_id, {
        "type": "round_ended",
        "match_id": match_id,
        "round_number": round_number,
        "results": results,
        "timestamp": datetime.utcnow().isoformat(),
    })


async def notify_match_ended(match_id: str, results: dict):
    """Notify all users that the match has ended."""
    await manager.broadcast_to_match(match_id, {
        "type": "match_ended",
        "match_id": match_id,
        "results": results,
        "timestamp": datetime.utcnow().isoformat(),
    })


async def notify_opponent_found(match_id: str, player1_id: int, player2_id: int, player1_info: dict, player2_info: dict):
    """Notify both players that an opponent has been found."""
    # Notify player 1
    await manager.send_to_user(player1_id, {
        "type": "opponent_found",
        "match_id": match_id,
        "opponent": player2_info,
    })

    # Notify player 2
    await manager.send_to_user(player2_id, {
        "type": "opponent_found",
        "match_id": match_id,
        "opponent": player1_info,
    })
