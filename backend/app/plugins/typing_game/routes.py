# backend/app/plugins/typing_game/routes.py
"""
Typing Game API routes
Solo practice, PVP battles, leaderboards
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional
from datetime import datetime, timedelta

from app.core.database import get_db
from app.core.config import settings
from app.auth.dependencies import get_current_user, get_optional_user, require_admin
from app.users.models import User
from app.plugins.skills.service import award_skill_xp, calculate_typing_skill_xp
import logging

logger = logging.getLogger(__name__)

from . import crud, schemas, models

router = APIRouter(prefix="/games/typing", tags=["typing_game"])


# ==================== WORD LISTS ====================

@router.get("/word-lists", response_model=List[schemas.TypingWordListResponse])
async def get_word_lists(
    difficulty: Optional[str] = None,
    theme: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """Get all available word lists"""
    word_lists = crud.get_word_lists(
        db=db,
        difficulty=difficulty,
        theme=theme,
        skip=skip,
        limit=limit
    )

    # Enrich with user data if authenticated
    response = []
    for wl in word_lists:
        # Build response dict with all fields
        word_list_dict = {
            **wl.__dict__,
            "word_count": len(wl.words) if wl.words else 0,
            "is_unlocked": True,  # TODO: Check user level vs wl.unlock_level
            "user_best_wpm": None,  # TODO: Query user's best WPM for this word list
            "user_times_played": 0  # TODO: Query user's play count for this word list
        }

        # Create response object from dict
        data = schemas.TypingWordListResponse(**word_list_dict)
        response.append(data)

    return response


@router.get("/word-lists/featured", response_model=List[schemas.TypingWordListSummary])
async def get_featured_word_lists(
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """Get featured word lists"""
    word_lists = crud.get_featured_word_lists(db)

    return [
        schemas.TypingWordListSummary(
            id=wl.id,
            name=wl.name,
            difficulty=wl.difficulty,
            theme=wl.theme,
            word_count=len(wl.words) if wl.words else 0,
            unlock_level=wl.unlock_level,
            is_unlocked=True,
            is_featured=wl.is_featured
        )
        for wl in word_lists
    ]


@router.get("/word-lists/{word_list_id}", response_model=schemas.TypingWordListResponse)
async def get_word_list(
    word_list_id: str,
    db: Session = Depends(get_db)
):
    """Get word list by ID"""
    word_list = crud.get_word_list(db, word_list_id)
    if not word_list:
        raise HTTPException(status_code=404, detail="Word list not found")

    return word_list


# ==================== GAME SESSIONS ====================

@router.post("/start", response_model=schemas.TypingGameStartResponse)
async def start_game(
    request: schemas.TypingGameStartRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Start a new typing game session"""
    session, checksum = crud.create_game_session(
        db=db,
        user_id=current_user.id,
        word_list_id=request.word_list_id,
        mode=request.mode,
        word_count=request.word_count
    )

    # Get word list name if specified
    word_list_name = None
    difficulty = "medium"
    related_skills = []

    if request.word_list_id:
        word_list = crud.get_word_list(db, request.word_list_id)
        if word_list:
            word_list_name = word_list.name
            difficulty = word_list.difficulty
            related_skills = word_list.related_skills or []

    return schemas.TypingGameStartResponse(
        session_id=session.id,
        text=session.text_content,
        checksum=checksum,
        word_list_name=word_list_name,
        difficulty=difficulty,
        word_count=session.word_count,
        related_skills=related_skills
    )


@router.post("/submit", response_model=schemas.TypingGameResultsResponse)
async def submit_game(
    request: schemas.TypingGameSubmitRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Submit typing game results"""
    result = crud.complete_game_session(
        db=db,
        session_id=request.session_id,
        user_input=request.user_input,
        time_elapsed=request.time_elapsed,
        checksum=request.checksum
    )

    if not result:
        raise HTTPException(
            status_code=400,
            detail="Invalid session or checksum"
        )

    session, metrics = result

    # =========== SKILL XP INTEGRATION ===========
    # Award typing skill XP (if skills plugin enabled)
    if settings.PLUGINS_ENABLED.get("skills", False):
        try:
            wpm = metrics["metrics"].get("wpm", 0)
            accuracy = metrics["metrics"].get("accuracy", 0)
            skill_xp = calculate_typing_skill_xp(wpm, accuracy)

            # Award XP to programming skill (typing practice improves coding speed)
            skill_result = await award_skill_xp(
                db=db,
                user_id=current_user.id,
                skill_slug="programming",
                xp_amount=skill_xp,
                source_type="typing_game",
                source_id=str(session.id),
                source_metadata={
                    "wpm": wpm,
                    "accuracy": accuracy,
                    "time_elapsed": request.time_elapsed
                }
            )
            if skill_result.level_up:
                logger.info(f"User {current_user.id} leveled up programming: {skill_result.old_level} -> {skill_result.new_level}")
        except Exception as e:
            logger.error(f"Failed to award skill XP for typing game: {e}")

    return schemas.TypingGameResultsResponse(
        session_id=session.id,
        metrics=schemas.TypingPerformanceMetrics(**metrics["metrics"]),
        xp_earned=metrics["xp_earned"],
        is_personal_best_wpm=metrics["is_personal_best_wpm"],
        is_personal_best_accuracy=metrics["is_personal_best_accuracy"]
    )


@router.get("/history", response_model=schemas.TypingGameHistoryResponse)
async def get_game_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get user's game history"""
    skip = (page - 1) * page_size

    games, total = crud.get_user_game_history(
        db=db,
        user_id=current_user.id,
        skip=skip,
        limit=page_size
    )

    history_entries = []
    for game in games:
        word_list = crud.get_word_list(db, game.word_list_id) if game.word_list_id else None

        history_entries.append(schemas.TypingGameHistoryEntry(
            session_id=game.id,
            word_list_name=word_list.name if word_list else "Quick Practice",
            difficulty=word_list.difficulty if word_list else "medium",
            wpm=game.wpm or 0,
            accuracy=game.accuracy or 0,
            time_elapsed=int(game.time_taken or 0),
            xp_earned=game.total_xp_earned,
            completed_at=game.completed_at
        ))

    return schemas.TypingGameHistoryResponse(
        games=history_entries,
        total_games=total,
        page=page,
        page_size=page_size
    )


# ==================== USER STATS ====================

@router.get("/stats/me", response_model=schemas.UserTypingStatsResponse)
async def get_my_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get current user's typing stats"""
    stats = crud.get_or_create_user_stats(db, current_user.id)
    return stats


@router.get("/stats/{user_id}", response_model=schemas.UserTypingStatsResponse)
async def get_user_stats(
    user_id: int,
    db: Session = Depends(get_db)
):
    """Get user's typing stats (public)"""
    stats = crud.get_user_stats(db, user_id)
    if not stats:
        raise HTTPException(status_code=404, detail="User stats not found")
    return stats


# ==================== LEADERBOARD ====================

@router.get("/leaderboard", response_model=schemas.LeaderboardResponse)
async def get_leaderboard(
    leaderboard_type: str = Query("wpm", description="wpm, accuracy, or pvp"),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """Get typing game leaderboard"""
    if leaderboard_type == "pvp":
        entries = crud.get_pvp_leaderboard(db, limit)
    else:
        entries = crud.get_leaderboard(db, leaderboard_type, limit)

    # Find user's rank if authenticated
    user_rank = None
    if current_user:
        for entry in entries:
            if entry["user_id"] == current_user.id:
                user_rank = entry["rank"]
                break

    return schemas.LeaderboardResponse(
        leaderboard_type=leaderboard_type,
        period=None,
        entries=[
            schemas.LeaderboardEntryResponse(
                rank=e["rank"],
                user_id=e["user_id"],
                username=e["username"],
                display_name=e.get("display_name"),
                best_wpm=e.get("best_wpm", e.get("rating", 0)),
                avg_wpm=e.get("avg_wpm", 0),
                avg_accuracy=e.get("avg_accuracy", e.get("win_rate", 0)),
                games_played=e.get("games_played", e.get("wins", 0) + e.get("losses", 0))
            )
            for e in entries
        ],
        user_rank=user_rank,
        total_entries=len(entries)
    )


# ==================== PVP SETTINGS ====================

@router.get("/pvp/settings")
async def get_pvp_settings():
    """Get PVP mode settings (public)"""
    return {
        "pvp_enabled": settings.PLUGINS_ENABLED.get("typing_game_pvp", False)
    }


@router.put("/admin/pvp/settings")
async def update_pvp_settings(
    enabled: bool = Query(..., description="Enable or disable PVP mode"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Toggle PVP mode on/off (admin only)"""
    settings.PLUGIN_TYPING_GAME_PVP_ENABLED = enabled
    settings.PLUGINS_ENABLED["typing_game_pvp"] = enabled
    return {
        "pvp_enabled": enabled,
        "message": f"PVP mode {'enabled' if enabled else 'disabled'}"
    }


# ==================== PVP ====================

@router.post("/pvp/find-match", response_model=schemas.PVPMatchResponse)
async def find_pvp_match(
    request: schemas.PVPFindMatchRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Find or create PVP match"""
    if not settings.PLUGINS_ENABLED.get("typing_game_pvp", False):
        raise HTTPException(status_code=403, detail="PVP mode is currently disabled")

    # Try to find existing match
    existing_match = crud.find_match_for_player(
        db=db,
        player_id=current_user.id,
        difficulty=request.difficulty
    )

    if existing_match:
        # Join existing match
        match = crud.join_pvp_match(db, existing_match.id, current_user.id)
        if match:
            return match

    # Create new match
    match = crud.create_pvp_match(
        db=db,
        player1_id=current_user.id,
        difficulty=request.difficulty
    )

    return match


@router.get("/pvp/match/{match_id}", response_model=schemas.PVPMatchDetailResponse)
async def get_pvp_match(
    match_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get PVP match details"""
    match = crud.get_pvp_match(db, match_id)
    if not match:
        raise HTTPException(status_code=404, detail="Match not found")

    # Verify user is participant
    if current_user.id not in [match.player1_id, match.player2_id]:
        raise HTTPException(status_code=403, detail="Not a participant")

    return match


@router.post("/pvp/submit-round", response_model=schemas.PVPRoundResultResponse)
async def submit_pvp_round(
    request: schemas.PVPRoundSubmitRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Submit PVP round results"""
    result = crud.submit_pvp_round(
        db=db,
        match_id=request.match_id,
        player_id=current_user.id,
        wpm=request.wpm,
        accuracy=request.accuracy,
        time_elapsed=request.time_elapsed,
        words_typed=request.words_typed
    )

    if not result:
        raise HTTPException(
            status_code=400,
            detail="Invalid match or round"
        )

    return schemas.PVPRoundResultResponse(
        round_number=result["round_number"],
        winner=result.get("winner", "pending"),
        player_wpm=result.get("player_wpm", 0),
        opponent_wpm=result.get("opponent_wpm", 0),
        player_accuracy=result.get("player_accuracy", 0),
        opponent_accuracy=result.get("opponent_accuracy", 0),
        match_status=result["match_status"],
        current_score=result["current_score"],
        xp_earned=result.get("xp_earned"),
        next_round_content=result.get("next_round_content"),
        next_round_word_count=result.get("next_round_word_count")
    )


@router.get("/pvp/stats/me", response_model=schemas.UserPVPStatsResponse)
async def get_my_pvp_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get current user's PVP stats"""
    stats = crud.get_or_create_pvp_stats(db, current_user.id)
    return stats


@router.post("/pvp/cancel/{match_id}")
async def cancel_pvp_match(
    match_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Cancel waiting PVP match"""
    match = crud.get_pvp_match(db, match_id)
    if not match:
        raise HTTPException(status_code=404, detail="Match not found")

    if match.player1_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not the match creator")

    if match.status != models.MatchStatus.WAITING:
        raise HTTPException(status_code=400, detail="Match already started")

    match.status = models.MatchStatus.CANCELLED
    db.commit()

    return {"message": "Match cancelled"}


# ==================== ADMIN ROUTES ====================

@router.post("/admin/word-lists", response_model=schemas.TypingWordListResponse)
async def create_word_list(
    word_list: schemas.TypingWordListCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Create new word list (admin only)"""
    existing = crud.get_word_list(db, word_list.id)
    if existing:
        raise HTTPException(status_code=400, detail="Word list ID already exists")

    return crud.create_word_list(db, word_list)


@router.put("/admin/word-lists/{word_list_id}", response_model=schemas.TypingWordListResponse)
async def update_word_list(
    word_list_id: str,
    word_list: schemas.TypingWordListUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Update word list (admin only)"""
    updated = crud.update_word_list(db, word_list_id, word_list)
    if not updated:
        raise HTTPException(status_code=404, detail="Word list not found")
    return updated


@router.delete("/admin/word-lists/{word_list_id}")
async def delete_word_list(
    word_list_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Delete word list (admin only)"""
    word_list = crud.get_word_list(db, word_list_id)
    if not word_list:
        raise HTTPException(status_code=404, detail="Word list not found")

    db.delete(word_list)
    db.commit()

    return {"message": "Word list deleted"}


@router.get("/admin/analytics", response_model=schemas.TypingGameAnalyticsResponse)
async def get_analytics(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Get typing game analytics (admin only)"""
    from sqlalchemy import func

    # Get total games
    total_games = db.query(models.TypingGameSession).filter(
        models.TypingGameSession.is_completed == True
    ).count()

    # Get total unique players
    total_players = db.query(func.count(func.distinct(models.TypingGameSession.user_id))).scalar()

    # Get average WPM and accuracy
    avg_stats = db.query(
        func.avg(models.TypingGameSession.wpm),
        func.avg(models.TypingGameSession.accuracy)
    ).filter(models.TypingGameSession.is_completed == True).first()

    avg_wpm = avg_stats[0] or 0
    avg_accuracy = avg_stats[1] or 0

    # Games in last 7 days
    week_ago = datetime.utcnow() - timedelta(days=7)
    games_last_week = db.query(models.TypingGameSession).filter(
        models.TypingGameSession.is_completed == True,
        models.TypingGameSession.completed_at >= week_ago
    ).count()

    # Top word lists
    top_word_lists = db.query(
        models.TypingWordList.id,
        models.TypingWordList.name,
        models.TypingWordList.times_played
    ).order_by(desc(models.TypingWordList.times_played)).limit(5).all()

    # PVP matches today
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    pvp_today = db.query(models.PVPMatch).filter(
        models.PVPMatch.created_at >= today_start
    ).count()

    # Active players today
    active_today = db.query(func.count(func.distinct(models.TypingGameSession.user_id))).filter(
        models.TypingGameSession.started_at >= today_start
    ).scalar()

    return schemas.TypingGameAnalyticsResponse(
        total_games_played=total_games,
        total_players=total_players or 0,
        average_wpm=round(avg_wpm, 1),
        average_accuracy=round(avg_accuracy, 1),
        games_last_7_days=games_last_week,
        top_word_lists=[
            {"id": wl[0], "name": wl[1], "times_played": wl[2]}
            for wl in top_word_lists
        ],
        pvp_matches_today=pvp_today,
        active_players_today=active_today or 0
    )


# ==================== ADMIN LEADERBOARD ====================

@router.get("/admin/leaderboard")
async def get_admin_leaderboard(
    sort: str = Query("best_wpm", description="Sort by: best_wpm, avg_wpm, games_played"),
    period: str = Query("all", description="Period: all, month, week, today"),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Admin-only leaderboard with extra user information.
    Includes email, total XP, and suspicious activity flags.
    """
    from sqlalchemy import func

    # Calculate today's start for period filters
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    # Build base query with user join
    query = db.query(
        models.UserTypingStats,
        User.email,
        User.display_name,
        User.username,
        User.total_points.label("total_xp")
    ).join(User, models.UserTypingStats.user_id == User.id).filter(
        models.UserTypingStats.total_games_completed > 0
    )

    # Sort options
    sort_columns = {
        "best_wpm": models.UserTypingStats.best_wpm.desc(),
        "avg_wpm": models.UserTypingStats.average_wpm.desc(),
        "games_played": models.UserTypingStats.total_games_completed.desc()
    }
    query = query.order_by(sort_columns.get(sort, models.UserTypingStats.best_wpm.desc()))

    results = query.limit(limit).all()

    # Get last played date for each user (subquery)
    last_played_subq = db.query(
        models.TypingGameSession.user_id,
        func.max(models.TypingGameSession.completed_at).label("last_played")
    ).filter(
        models.TypingGameSession.is_completed == True
    ).group_by(models.TypingGameSession.user_id).subquery()

    # Build response with suspicious flag
    entries = []
    for idx, (stats, email, display_name, username, total_xp) in enumerate(results):
        # Flag as suspicious if best WPM > 180 AND games played < 10
        is_suspicious = stats.best_wpm > 180 and stats.total_games_completed < 10

        # Get last played date
        last_played = db.query(last_played_subq.c.last_played).filter(
            last_played_subq.c.user_id == stats.user_id
        ).scalar()

        entries.append({
            "rank": idx + 1,
            "id": stats.user_id,
            "username": display_name or username,
            "email": email,
            "best_wpm": stats.best_wpm or 0,
            "avg_wpm": round(stats.average_wpm or 0, 1),
            "games_played": stats.total_games_completed,
            "total_xp": total_xp or 0,
            "is_suspicious": is_suspicious,
            "last_played": last_played.isoformat() if last_played else None
        })

    # Calculate stats
    stats_result = {
        "total_players": db.query(models.UserTypingStats).filter(
            models.UserTypingStats.total_games_completed > 0
        ).count(),
        "games_played_today": db.query(models.TypingGameSession).filter(
            models.TypingGameSession.completed_at >= today_start,
            models.TypingGameSession.is_completed == True
        ).count(),
        "avg_wpm_global": round(db.query(func.avg(models.UserTypingStats.average_wpm)).scalar() or 0, 1),
        "top_wpm_today": db.query(func.max(models.TypingGameSession.wpm)).filter(
            models.TypingGameSession.completed_at >= today_start
        ).scalar() or 0
    }

    return {
        "entries": entries,
        "stats": stats_result
    }


# ==================== SENTENCE POOL ROUTES ====================

@router.get("/sentence-pools", response_model=schemas.SentencePoolListResponse)
async def get_sentence_pools(
    difficulty: Optional[str] = Query(None, description="Filter by difficulty (easy, medium, hard, expert)"),
    category: Optional[str] = Query(None, description="Filter by category"),
    is_active: bool = Query(True, description="Filter by active status"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """Get all sentence pools with optional filters"""
    pools, total = crud.get_sentence_pools(
        db=db,
        difficulty=difficulty,
        category=category,
        is_active=is_active,
        skip=skip,
        limit=limit
    )

    return schemas.SentencePoolListResponse(
        pools=[schemas.SentencePoolResponse.from_orm_with_count(p) for p in pools],
        total=total,
        page=skip // limit + 1,
        page_size=limit
    )


@router.get("/sentence-pools/{pool_id}", response_model=schemas.SentencePoolResponse)
async def get_sentence_pool(
    pool_id: str,
    db: Session = Depends(get_db)
):
    """Get sentence pool by ID"""
    pool = crud.get_sentence_pool(db, pool_id)
    if not pool:
        raise HTTPException(status_code=404, detail="Sentence pool not found")

    return schemas.SentencePoolResponse.from_orm_with_count(pool)


@router.post("/admin/sentence-pools", response_model=schemas.SentencePoolResponse)
async def create_sentence_pool(
    pool_data: schemas.SentencePoolCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Create new sentence pool (admin only)"""
    # Validate sentences
    if not pool_data.sentences:
        raise HTTPException(status_code=400, detail="At least one sentence is required")

    # Validate sentence lengths
    for sentence in pool_data.sentences:
        if len(sentence) < pool_data.min_length:
            raise HTTPException(
                status_code=400,
                detail=f"Sentence too short: '{sentence[:50]}...' (min: {pool_data.min_length} chars)"
            )
        if len(sentence) > pool_data.max_length:
            raise HTTPException(
                status_code=400,
                detail=f"Sentence too long: '{sentence[:50]}...' (max: {pool_data.max_length} chars)"
            )

    pool = crud.create_sentence_pool(db, pool_data, created_by=current_user.id)
    return schemas.SentencePoolResponse.from_orm_with_count(pool)


@router.put("/admin/sentence-pools/{pool_id}", response_model=schemas.SentencePoolResponse)
async def update_sentence_pool(
    pool_id: str,
    pool_data: schemas.SentencePoolUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Update sentence pool (admin only)"""
    # Validate sentence lengths if sentences are being updated
    if pool_data.sentences:
        min_length = pool_data.min_length or 20
        max_length = pool_data.max_length or 200

        # Get existing pool to use its min/max if not being updated
        existing = crud.get_sentence_pool(db, pool_id)
        if existing:
            min_length = pool_data.min_length if pool_data.min_length is not None else existing.min_length
            max_length = pool_data.max_length if pool_data.max_length is not None else existing.max_length

        for sentence in pool_data.sentences:
            if len(sentence) < min_length:
                raise HTTPException(
                    status_code=400,
                    detail=f"Sentence too short: '{sentence[:50]}...' (min: {min_length} chars)"
                )
            if len(sentence) > max_length:
                raise HTTPException(
                    status_code=400,
                    detail=f"Sentence too long: '{sentence[:50]}...' (max: {max_length} chars)"
                )

    updated = crud.update_sentence_pool(db, pool_id, pool_data)
    if not updated:
        raise HTTPException(status_code=404, detail="Sentence pool not found")

    return schemas.SentencePoolResponse.from_orm_with_count(updated)


@router.delete("/admin/sentence-pools/{pool_id}")
async def delete_sentence_pool(
    pool_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Delete sentence pool (admin only)"""
    deleted = crud.delete_sentence_pool(db, pool_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Sentence pool not found")

    return {"message": "Sentence pool deleted"}


@router.post("/admin/sentence-pools/{pool_id}/add-sentences")
async def add_sentences_to_pool(
    pool_id: str,
    sentences: List[str],
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Add sentences to an existing pool (admin only)"""
    pool = crud.get_sentence_pool(db, pool_id)
    if not pool:
        raise HTTPException(status_code=404, detail="Sentence pool not found")

    # Validate new sentences
    for sentence in sentences:
        if len(sentence) < pool.min_length:
            raise HTTPException(
                status_code=400,
                detail=f"Sentence too short: '{sentence[:50]}...' (min: {pool.min_length} chars)"
            )
        if len(sentence) > pool.max_length:
            raise HTTPException(
                status_code=400,
                detail=f"Sentence too long: '{sentence[:50]}...' (max: {pool.max_length} chars)"
            )

    # Add sentences to existing pool
    existing_sentences = pool.sentences or []
    new_sentences = existing_sentences + sentences

    # Remove duplicates while preserving order
    seen = set()
    unique_sentences = []
    for s in new_sentences:
        if s not in seen:
            seen.add(s)
            unique_sentences.append(s)

    update_data = schemas.SentencePoolUpdate(sentences=unique_sentences)
    updated = crud.update_sentence_pool(db, pool_id, update_data)

    return {
        "message": f"Added {len(sentences)} sentences",
        "total_sentences": len(unique_sentences),
        "duplicates_removed": len(new_sentences) - len(unique_sentences)
    }


@router.get("/admin/sentence-pools/stats/summary")
async def get_sentence_pool_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Get summary statistics for all sentence pools (admin only)"""
    from sqlalchemy import func

    # Total pools
    total_pools = db.query(models.SentencePool).count()
    active_pools = db.query(models.SentencePool).filter(
        models.SentencePool.is_active == True
    ).count()

    # Pool counts by difficulty
    difficulty_counts = db.query(
        models.SentencePool.difficulty,
        func.count(models.SentencePool.id)
    ).group_by(models.SentencePool.difficulty).all()

    # Pool counts by category
    category_counts = db.query(
        models.SentencePool.category,
        func.count(models.SentencePool.id)
    ).group_by(models.SentencePool.category).all()

    # Most used pools
    top_pools = db.query(
        models.SentencePool.id,
        models.SentencePool.name,
        models.SentencePool.times_used,
        models.SentencePool.avg_wpm,
        models.SentencePool.avg_accuracy
    ).order_by(desc(models.SentencePool.times_used)).limit(10).all()

    return {
        "total_pools": total_pools,
        "active_pools": active_pools,
        "by_difficulty": {d: c for d, c in difficulty_counts},
        "by_category": {c: cnt for c, cnt in category_counts},
        "top_pools": [
            {
                "id": p[0],
                "name": p[1],
                "times_used": p[2],
                "avg_wpm": round(p[3], 1) if p[3] else 0,
                "avg_accuracy": round(p[4], 1) if p[4] else 0
            }
            for p in top_pools
        ]
    }


# ==================== ANALYTICS ROUTES ====================

@router.get("/analytics/me")
async def get_my_analytics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get current user's detailed typing analytics"""
    return crud.get_user_analytics_summary(db, current_user.id)


@router.get("/analytics/letter-stats")
async def get_my_letter_stats(
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get letter-by-letter accuracy breakdown"""
    stats = crud.get_user_letter_stats(db, current_user.id, limit)

    return {
        "letters": [
            {
                "character": s.character,
                "total_attempts": s.total_attempts,
                "total_correct": s.total_correct,
                "accuracy_rate": round(s.accuracy_rate, 1),
                "avg_time_ms": round(s.avg_time_to_type, 1) if s.avg_time_to_type else None,
                "min_time_ms": round(s.min_time_to_type, 1) if s.min_time_to_type else None,
                "max_time_ms": round(s.max_time_to_type, 1) if s.max_time_to_type else None,
                "common_mistakes": s.common_mistakes or []
            }
            for s in stats
        ],
        "total_tracked": len(stats)
    }


@router.get("/analytics/pattern-stats")
async def get_my_pattern_stats(
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get pattern/digraph accuracy breakdown"""
    stats = crud.get_user_pattern_stats(db, current_user.id, limit)

    return {
        "patterns": [
            {
                "pattern": s.pattern,
                "total_attempts": s.total_attempts,
                "total_correct": s.total_correct,
                "accuracy_rate": round(s.accuracy_rate, 1),
                "avg_time_ms": round(s.avg_time_ms, 1) if s.avg_time_ms else None
            }
            for s in stats
        ],
        "total_tracked": len(stats)
    }


@router.get("/analytics/weak-spots")
async def get_my_weak_spots(
    min_attempts: int = Query(10, ge=1, description="Minimum attempts to consider"),
    limit: int = Query(10, ge=1, le=20),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get personalized weak spot recommendations"""
    weak_letters = crud.get_user_weak_letters(db, current_user.id, min_attempts, limit)
    weak_patterns = crud.get_user_weak_patterns(db, current_user.id, min_attempts=5, limit=limit)
    recommendations = crud.generate_practice_recommendations(weak_letters, weak_patterns)

    return {
        "weak_letters": [
            {
                "character": s.character,
                "accuracy_rate": round(s.accuracy_rate, 1),
                "attempts": s.total_attempts,
                "common_mistakes": s.common_mistakes[:3] if s.common_mistakes else []
            }
            for s in weak_letters
        ],
        "weak_patterns": [
            {
                "pattern": s.pattern,
                "accuracy_rate": round(s.accuracy_rate, 1),
                "attempts": s.total_attempts
            }
            for s in weak_patterns
        ],
        "recommendations": recommendations
    }


@router.get("/analytics/session/{session_id}")
async def get_session_analytics(
    session_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get detailed analytics for a specific session"""
    # Verify session belongs to user
    session = crud.get_game_session(db, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    if session.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to view this session")

    analytics = crud.get_session_analytics(db, session_id)
    if not analytics:
        return {
            "session_id": session_id,
            "message": "Detailed analytics not available for this session",
            "basic_stats": {
                "wpm": session.wpm,
                "accuracy": session.accuracy,
                "mistakes": session.mistakes,
                "time_taken": session.time_taken
            }
        }

    return {
        "session_id": session_id,
        "wpm_timeline": analytics.wpm_timeline,
        "error_positions": analytics.error_positions,
        "error_heatmap": analytics.error_heatmap,
        "avg_inter_key_time": round(analytics.avg_inter_key_time, 1),
        "std_dev_inter_key_time": round(analytics.std_dev_inter_key_time, 1),
        "slowest_words": analytics.slowest_words,
        "fastest_words": analytics.fastest_words,
        "confidence_score": analytics.confidence_score,
        "basic_stats": {
            "wpm": session.wpm,
            "accuracy": session.accuracy,
            "mistakes": session.mistakes,
            "time_taken": session.time_taken
        }
    }


# ==================== STREAK ROUTES ====================

@router.get("/streak/me")
async def get_my_streak(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get current user's streak information"""
    return crud.get_user_streak_info(db, current_user.id)


@router.post("/streak/freeze")
async def use_streak_freeze(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Use a streak freeze to protect streak"""
    return crud.use_streak_freeze(db, current_user.id)


# ==================== DAILY CHALLENGE ROUTES ====================

@router.get("/challenges/daily")
async def get_daily_challenges(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get today's daily challenges with progress"""
    challenges = crud.get_daily_challenges_with_progress(db, current_user.id)
    streak_info = crud.get_user_streak_info(db, current_user.id)

    return {
        "challenges": challenges,
        "streak": streak_info,
        "date": datetime.utcnow().date().isoformat()
    }


@router.post("/challenges/{challenge_id}/claim")
async def claim_challenge_reward(
    challenge_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Claim reward for a completed challenge"""
    result = crud.claim_challenge_reward(db, current_user.id, challenge_id)

    if not result.get('success'):
        raise HTTPException(status_code=400, detail=result.get('message', 'Failed to claim reward'))

    return result


# ==================== ENHANCED SUBMIT V2 ====================

@router.post("/submit/v2", response_model=schemas.TypingGameResultsResponse)
async def submit_game_v2(
    request: schemas.TypingGameSubmitRequestV2,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Enhanced game submission with anti-cheat validation and analytics.
    Includes combo tracking, streak updates, and daily challenge progress.
    """
    # Prepare anti-cheat data if provided
    anti_cheat_data = None
    if request.anti_cheat:
        anti_cheat_data = {
            "keystroke_timings": request.anti_cheat.keystroke_timings,
            "keystroke_count": request.anti_cheat.keystroke_count,
            "paste_attempts": request.anti_cheat.paste_attempts,
            "focus_lost_count": request.anti_cheat.focus_lost_count,
            "total_focus_lost_time": request.anti_cheat.total_focus_lost_time,
            "first_segment_avg": request.anti_cheat.first_segment_avg,
            "last_segment_avg": request.anti_cheat.last_segment_avg
        }

    # Complete game session with anti-cheat
    result = crud.complete_game_session_v2(
        db=db,
        session_id=request.session_id,
        user_input=request.user_input,
        time_elapsed=request.time_elapsed,
        checksum=request.checksum,
        max_combo=request.max_combo,
        anti_cheat_data=anti_cheat_data
    )

    if not result:
        raise HTTPException(
            status_code=400,
            detail="Invalid session or checksum"
        )

    session, metrics = result

    # Update user streak
    streak_result = crud.update_user_streak(db, current_user.id)

    # Process daily challenges
    words_typed = len(request.user_input.split())
    completed_challenges = crud.process_game_completion_for_challenges(
        db=db,
        user_id=current_user.id,
        wpm=metrics["metrics"]["wpm"],
        accuracy=metrics["metrics"]["accuracy"],
        words_typed=words_typed,
        max_combo=request.max_combo
    )

    # =========== SKILL XP INTEGRATION ===========
    # Award typing skill XP (if skills plugin enabled)
    if settings.PLUGINS_ENABLED.get("skills", False):
        try:
            wpm = metrics["metrics"].get("wpm", 0)
            accuracy = metrics["metrics"].get("accuracy", 0)
            skill_xp = calculate_typing_skill_xp(wpm, accuracy)

            # Award XP to programming skill (typing practice improves coding speed)
            skill_result = await award_skill_xp(
                db=db,
                user_id=current_user.id,
                skill_slug="programming",
                xp_amount=skill_xp,
                source_type="typing_game",
                source_id=str(session.id),
                source_metadata={
                    "wpm": wpm,
                    "accuracy": accuracy,
                    "time_elapsed": request.time_elapsed,
                    "max_combo": request.max_combo
                }
            )
            if skill_result.level_up:
                logger.info(f"User {current_user.id} leveled up programming: {skill_result.old_level} -> {skill_result.new_level}")
        except Exception as e:
            logger.error(f"Failed to award skill XP for typing game v2: {e}")

    # Build response
    response = schemas.TypingGameResultsResponse(
        session_id=session.id,
        metrics=schemas.TypingPerformanceMetrics(**metrics["metrics"]),
        xp_earned=metrics["xp_earned"],
        is_personal_best_wpm=metrics["is_personal_best_wpm"],
        is_personal_best_accuracy=metrics["is_personal_best_accuracy"],
        max_combo=metrics.get("max_combo", 0)
    )

    # Add anti-cheat info if present
    if "anti_cheat" in metrics:
        response.anti_cheat = schemas.AntiCheatResultResponse(
            confidence_score=metrics["anti_cheat"]["confidence_score"],
            flags=metrics["anti_cheat"]["flags"],
            is_valid=metrics["anti_cheat"]["is_valid"]
        )

    # Add streak info
    if streak_result:
        streak_bonus_xp = 0
        if isinstance(streak_result, dict):
            streak_bonus_xp = streak_result.get("streak_bonus_xp", 0)
            response.streak = schemas.StreakResultResponse(
                current_streak=streak_result.get("current_streak", 0),
                streak_extended=streak_result.get("streak_extended", False),
                streak_bonus_xp=streak_bonus_xp
            )
        else:
            response.streak = schemas.StreakResultResponse(
                current_streak=getattr(streak_result, 'current_streak', 0),
                streak_extended=getattr(streak_result, 'streak_extended', False),
                streak_bonus_xp=getattr(streak_result, 'streak_bonus_xp', 0)
            )

    # Add completed challenges
    if completed_challenges:
        response.challenges_completed = [
            schemas.ChallengeCompletedResponse(
                challenge_id=c.get("challenge_id", "") if isinstance(c, dict) else getattr(c, "challenge_id", ""),
                challenge_type=c.get("challenge_type", "") if isinstance(c, dict) else getattr(c, "challenge_type", ""),
                xp_reward=c.get("xp_reward", 0) if isinstance(c, dict) else getattr(c, "xp_reward", 0),
                difficulty=c.get("difficulty", "medium") if isinstance(c, dict) else getattr(c, "difficulty", "medium"),
            )
            for c in completed_challenges
        ]

    return response
