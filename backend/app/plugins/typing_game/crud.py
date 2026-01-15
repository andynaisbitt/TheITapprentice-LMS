# backend/app/plugins/typing_game/crud.py
"""
Typing Game CRUD operations
Session management, stats tracking, leaderboards, PVP
"""
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
import uuid
import random
import hashlib

from . import models, schemas


# ==================== WORD LIST CRUD ====================

def get_word_list(db: Session, word_list_id: str) -> Optional[models.TypingWordList]:
    """Get word list by ID"""
    return db.query(models.TypingWordList).filter(
        models.TypingWordList.id == word_list_id
    ).first()


def get_word_lists(
    db: Session,
    difficulty: Optional[str] = None,
    theme: Optional[str] = None,
    is_active: bool = True,
    skip: int = 0,
    limit: int = 100
) -> List[models.TypingWordList]:
    """Get all word lists with optional filters"""
    query = db.query(models.TypingWordList)

    if is_active is not None:
        query = query.filter(models.TypingWordList.is_active == is_active)

    if difficulty:
        query = query.filter(models.TypingWordList.difficulty == difficulty)

    if theme:
        query = query.filter(models.TypingWordList.theme == theme)

    return query.order_by(
        models.TypingWordList.display_order,
        models.TypingWordList.name
    ).offset(skip).limit(limit).all()


def get_featured_word_lists(db: Session) -> List[models.TypingWordList]:
    """Get featured word lists"""
    return db.query(models.TypingWordList).filter(
        models.TypingWordList.is_featured == True,
        models.TypingWordList.is_active == True
    ).order_by(models.TypingWordList.display_order).all()


def create_word_list(
    db: Session,
    word_list: schemas.TypingWordListCreate
) -> models.TypingWordList:
    """Create new word list (admin only)"""
    db_word_list = models.TypingWordList(**word_list.model_dump())
    db.add(db_word_list)
    db.commit()
    db.refresh(db_word_list)
    return db_word_list


def update_word_list(
    db: Session,
    word_list_id: str,
    word_list: schemas.TypingWordListUpdate
) -> Optional[models.TypingWordList]:
    """Update word list (admin only)"""
    db_word_list = get_word_list(db, word_list_id)
    if not db_word_list:
        return None

    update_data = word_list.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_word_list, field, value)

    db.commit()
    db.refresh(db_word_list)
    return db_word_list


# ==================== GAME SESSION CRUD ====================

def generate_text_from_word_list(word_list: models.TypingWordList, word_count: int = 50) -> str:
    """Generate random text from word list"""
    words = word_list.words if word_list.words else []
    if not words:
        # Fallback to default text
        return "The quick brown fox jumps over the lazy dog."

    # Generate text by randomly selecting words
    selected_words = [random.choice(words) for _ in range(word_count)]
    return " ".join(selected_words)


def generate_default_text(word_count: int = 50) -> str:
    """Generate default typing text"""
    default_words = [
        "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog",
        "computer", "network", "server", "database", "program", "code",
        "system", "software", "hardware", "keyboard", "mouse", "screen",
        "python", "javascript", "html", "css", "api", "function", "variable",
        "class", "object", "method", "data", "string", "number", "array",
        "loop", "if", "else", "while", "for", "return", "import", "export"
    ]
    selected_words = [random.choice(default_words) for _ in range(word_count)]
    return " ".join(selected_words)


def create_game_session(
    db: Session,
    user_id: int,
    word_list_id: Optional[str] = None,
    mode: str = "practice",
    word_count: int = 50
) -> Tuple[models.TypingGameSession, str]:
    """Create new typing game session"""
    session_id = str(uuid.uuid4())

    # Generate text content
    if word_list_id:
        word_list = get_word_list(db, word_list_id)
        if word_list:
            text_content = generate_text_from_word_list(word_list, word_count)
            # Update play count
            word_list.times_played += 1
        else:
            text_content = generate_default_text(word_count)
    else:
        text_content = generate_default_text(word_count)

    # Generate checksum for anti-cheat
    checksum = hashlib.sha256(f"{session_id}:{text_content}".encode()).hexdigest()

    session = models.TypingGameSession(
        id=session_id,
        user_id=user_id,
        word_list_id=word_list_id,
        mode=mode,
        text_content=text_content,
        text_checksum=checksum,
        word_count=len(text_content.split()),
        status="in_progress",
        started_at=datetime.utcnow()
    )

    db.add(session)
    db.commit()
    db.refresh(session)

    return session, checksum


def get_game_session(db: Session, session_id: str) -> Optional[models.TypingGameSession]:
    """Get game session by ID"""
    return db.query(models.TypingGameSession).filter(
        models.TypingGameSession.id == session_id
    ).first()


def complete_game_session(
    db: Session,
    session_id: str,
    user_input: str,
    time_elapsed: int,
    checksum: str
) -> Optional[Tuple[models.TypingGameSession, Dict[str, Any]]]:
    """Complete game session and calculate results"""
    session = get_game_session(db, session_id)
    if not session or session.is_completed:
        return None

    # Verify checksum
    expected_checksum = hashlib.sha256(
        f"{session_id}:{session.text_content}".encode()
    ).hexdigest()

    if checksum != expected_checksum:
        # Invalid checksum - potential cheating
        session.status = "abandoned"
        db.commit()
        return None

    # Calculate metrics
    original_text = session.text_content
    original_words = original_text.split()
    user_words = user_input.split()

    # Calculate accuracy
    correct_chars = 0
    total_chars = len(original_text)
    min_len = min(len(original_text), len(user_input))

    for i in range(min_len):
        if i < len(user_input) and i < len(original_text):
            if user_input[i] == original_text[i]:
                correct_chars += 1

    accuracy = (correct_chars / total_chars * 100) if total_chars > 0 else 0

    # Calculate WPM (words per minute)
    # Standard: 5 characters = 1 word
    chars_typed = len(user_input)
    minutes = time_elapsed / 60.0 if time_elapsed > 0 else 1/60
    raw_wpm = int((chars_typed / 5) / minutes)

    # Adjusted WPM (penalized for errors)
    error_count = total_chars - correct_chars
    adjusted_wpm = max(0, int(((chars_typed / 5) - error_count) / minutes))

    # Update session
    session.user_input = user_input
    session.time_taken = time_elapsed
    session.wpm = adjusted_wpm
    session.raw_wpm = raw_wpm
    session.accuracy = round(accuracy, 2)
    session.mistakes = error_count
    session.characters_typed = chars_typed
    session.is_completed = True
    session.status = "completed"
    session.completed_at = datetime.utcnow()

    # Calculate XP
    base_xp = 10
    wpm_bonus = adjusted_wpm // 10
    accuracy_bonus = int(accuracy // 10)
    xp_earned = base_xp + wpm_bonus + accuracy_bonus
    session.total_xp_earned = xp_earned

    # Update user stats and check personal bests
    stats = get_or_create_user_stats(db, session.user_id)
    is_pb_wpm = False
    is_pb_accuracy = False

    if adjusted_wpm > stats.best_wpm:
        stats.best_wpm = adjusted_wpm
        stats.best_wpm_achieved_at = datetime.utcnow()
        stats.best_wpm_word_list = session.word_list_id
        is_pb_wpm = True
        session.is_personal_best_wpm = True

    if accuracy > stats.best_accuracy:
        stats.best_accuracy = accuracy
        stats.best_accuracy_achieved_at = datetime.utcnow()
        is_pb_accuracy = True
        session.is_personal_best_accuracy = True

    # Update totals
    stats.total_games_played += 1
    stats.total_games_completed += 1
    stats.total_words_typed += len(user_words)
    stats.total_characters_typed += chars_typed
    stats.total_time_seconds += time_elapsed
    stats.last_game_at = datetime.utcnow()

    if not stats.first_game_at:
        stats.first_game_at = datetime.utcnow()

    # Update averages
    stats.avg_wpm = (
        (stats.avg_wpm * (stats.total_games_completed - 1) + adjusted_wpm)
        / stats.total_games_completed
    )
    stats.avg_accuracy = (
        (stats.avg_accuracy * (stats.total_games_completed - 1) + accuracy)
        / stats.total_games_completed
    )

    # Check milestones
    if adjusted_wpm >= 50 and not stats.reached_50_wpm_at:
        stats.reached_50_wpm_at = datetime.utcnow()
    if adjusted_wpm >= 100 and not stats.reached_100_wpm_at:
        stats.reached_100_wpm_at = datetime.utcnow()
    if adjusted_wpm >= 150 and not stats.reached_150_wpm_at:
        stats.reached_150_wpm_at = datetime.utcnow()

    # Update word list stats
    if session.word_list_id:
        word_list = get_word_list(db, session.word_list_id)
        if word_list:
            # Update averages
            total_plays = word_list.times_played
            word_list.avg_wpm = (
                (word_list.avg_wpm * (total_plays - 1) + adjusted_wpm)
                / total_plays
            ) if total_plays > 0 else adjusted_wpm
            word_list.avg_accuracy = (
                (word_list.avg_accuracy * (total_plays - 1) + accuracy)
                / total_plays
            ) if total_plays > 0 else accuracy

    db.commit()
    db.refresh(session)

    return session, {
        "metrics": {
            "wpm": adjusted_wpm,
            "raw_wpm": raw_wpm,
            "accuracy": round(accuracy, 2),
            "error_count": error_count,
            "total_characters": total_chars,
            "time_elapsed": time_elapsed
        },
        "xp_earned": xp_earned,
        "is_personal_best_wpm": is_pb_wpm,
        "is_personal_best_accuracy": is_pb_accuracy
    }


def get_user_game_history(
    db: Session,
    user_id: int,
    skip: int = 0,
    limit: int = 10
) -> Tuple[List[models.TypingGameSession], int]:
    """Get user's game history"""
    query = db.query(models.TypingGameSession).filter(
        models.TypingGameSession.user_id == user_id,
        models.TypingGameSession.is_completed == True
    )

    total = query.count()

    games = query.order_by(
        desc(models.TypingGameSession.completed_at)
    ).offset(skip).limit(limit).all()

    return games, total


# ==================== USER STATS CRUD ====================

def get_or_create_user_stats(db: Session, user_id: int) -> models.UserTypingStats:
    """Get or create user typing stats"""
    stats = db.query(models.UserTypingStats).filter(
        models.UserTypingStats.user_id == user_id
    ).first()

    if not stats:
        stats = models.UserTypingStats(user_id=user_id)
        db.add(stats)
        db.commit()
        db.refresh(stats)

    return stats


def get_user_stats(db: Session, user_id: int) -> Optional[models.UserTypingStats]:
    """Get user typing stats"""
    return db.query(models.UserTypingStats).filter(
        models.UserTypingStats.user_id == user_id
    ).first()


# ==================== PVP CRUD ====================

def create_pvp_match(
    db: Session,
    player1_id: int,
    difficulty: str = "medium"
) -> models.PVPMatch:
    """Create new PVP match"""
    match_id = str(uuid.uuid4())

    # Generate content
    text_content = generate_default_text(50)
    checksum = hashlib.sha256(f"{match_id}:{text_content}".encode()).hexdigest()

    # Determine skill bracket based on user's rating
    player1_stats = get_or_create_pvp_stats(db, player1_id)
    skill_bracket = get_skill_bracket(player1_stats.current_rating)

    match = models.PVPMatch(
        id=match_id,
        player1_id=player1_id,
        difficulty=difficulty,
        skill_bracket=skill_bracket,
        content=text_content,
        checksum=checksum,
        word_count=len(text_content.split()),
        total_rounds=3,
        current_round=1,
        round_results=[],
        status=models.MatchStatus.WAITING,
        player1_rating=player1_stats.current_rating,
        created_at=datetime.utcnow()
    )

    db.add(match)
    db.commit()
    db.refresh(match)

    return match


def find_match_for_player(
    db: Session,
    player_id: int,
    difficulty: str = "medium"
) -> Optional[models.PVPMatch]:
    """Find waiting match for player"""
    # Get player's skill bracket
    player_stats = get_or_create_pvp_stats(db, player_id)
    skill_bracket = get_skill_bracket(player_stats.current_rating)

    # Clean up stale matches (older than 5 minutes)
    stale_time = datetime.utcnow() - timedelta(minutes=5)
    stale_matches = db.query(models.PVPMatch).filter(
        models.PVPMatch.status == models.MatchStatus.WAITING,
        models.PVPMatch.created_at < stale_time,
        models.PVPMatch.player2_id == None
    ).all()

    for stale_match in stale_matches:
        stale_match.status = models.MatchStatus.CANCELLED

    if stale_matches:
        db.commit()

    # Find waiting match in same skill bracket
    match = db.query(models.PVPMatch).filter(
        models.PVPMatch.status == models.MatchStatus.WAITING,
        models.PVPMatch.skill_bracket == skill_bracket,
        models.PVPMatch.player1_id != player_id,
        models.PVPMatch.player2_id == None
    ).first()

    return match


def join_pvp_match(
    db: Session,
    match_id: str,
    player2_id: int
) -> Optional[models.PVPMatch]:
    """Join existing PVP match"""
    match = db.query(models.PVPMatch).filter(
        models.PVPMatch.id == match_id
    ).first()

    if not match or match.player2_id:
        return None

    player2_stats = get_or_create_pvp_stats(db, player2_id)

    match.player2_id = player2_id
    match.player2_rating = player2_stats.current_rating
    match.status = models.MatchStatus.IN_PROGRESS
    match.started_at = datetime.utcnow()

    db.commit()
    db.refresh(match)

    return match


def get_pvp_match(db: Session, match_id: str) -> Optional[models.PVPMatch]:
    """Get PVP match by ID"""
    return db.query(models.PVPMatch).filter(
        models.PVPMatch.id == match_id
    ).first()


def submit_pvp_round(
    db: Session,
    match_id: str,
    player_id: int,
    wpm: float,
    accuracy: float,
    time_elapsed: int,
    words_typed: int
) -> Optional[Dict[str, Any]]:
    """Submit round results for PVP match"""
    match = get_pvp_match(db, match_id)
    if not match or match.status != models.MatchStatus.IN_PROGRESS:
        return None

    # Determine if player is player1 or player2
    is_player1 = match.player1_id == player_id

    # Update round results
    round_results = match.round_results or []
    current_round = match.current_round

    # Find or create current round entry
    round_entry = None
    for entry in round_results:
        if entry.get("round") == current_round:
            round_entry = entry
            break

    if not round_entry:
        round_entry = {"round": current_round}
        round_results.append(round_entry)

    # Store player's results
    if is_player1:
        round_entry["p1_wpm"] = wpm
        round_entry["p1_accuracy"] = accuracy
        match.player1_wpm = int(wpm)
        match.player1_accuracy = accuracy
    else:
        round_entry["p2_wpm"] = wpm
        round_entry["p2_accuracy"] = accuracy
        match.player2_wpm = int(wpm)
        match.player2_accuracy = accuracy

    # Check if both players have submitted
    has_p1 = "p1_wpm" in round_entry
    has_p2 = "p2_wpm" in round_entry

    result = {
        "round_number": current_round,
        "match_status": "in_progress",
        "current_score": {
            "player1": match.player1_score,
            "player2": match.player2_score
        }
    }

    if has_p1 and has_p2:
        # Determine round winner
        p1_score = round_entry["p1_wpm"] * (round_entry["p1_accuracy"] / 100)
        p2_score = round_entry["p2_wpm"] * (round_entry["p2_accuracy"] / 100)

        if p1_score > p2_score:
            round_entry["winner"] = match.player1_id
            match.player1_score += 1
        elif p2_score > p1_score:
            round_entry["winner"] = match.player2_id
            match.player2_score += 1
        else:
            round_entry["winner"] = None  # Tie

        result["winner"] = "player" if round_entry["winner"] == player_id else (
            "opponent" if round_entry["winner"] else "tie"
        )
        result["player_wpm"] = wpm
        result["opponent_wpm"] = round_entry["p2_wpm"] if is_player1 else round_entry["p1_wpm"]
        result["player_accuracy"] = accuracy
        result["opponent_accuracy"] = round_entry["p2_accuracy"] if is_player1 else round_entry["p1_accuracy"]
        result["current_score"] = {
            "player1": match.player1_score,
            "player2": match.player2_score
        }

        # Check if match is complete
        rounds_to_win = (match.total_rounds // 2) + 1
        if match.player1_score >= rounds_to_win or match.player2_score >= rounds_to_win:
            # Match complete
            match.status = models.MatchStatus.COMPLETED
            match.completed_at = datetime.utcnow()

            if match.player1_score > match.player2_score:
                match.winner_id = match.player1_id
            elif match.player2_score > match.player1_score:
                match.winner_id = match.player2_id

            # Update PVP stats
            update_pvp_stats_after_match(db, match)

            result["match_status"] = "completed"
            result["xp_earned"] = 50 if match.winner_id == player_id else 20
        elif current_round < match.total_rounds:
            # Move to next round
            match.current_round += 1

    match.round_results = round_results
    db.commit()

    return result


def get_or_create_pvp_stats(db: Session, user_id: int) -> models.UserPVPStats:
    """Get or create PVP stats for user"""
    stats = db.query(models.UserPVPStats).filter(
        models.UserPVPStats.user_id == user_id
    ).first()

    if not stats:
        stats = models.UserPVPStats(
            user_id=user_id,
            current_rating=1500,
            peak_rating=1500,
            lowest_rating=1500,
            first_match_at=datetime.utcnow()
        )
        db.add(stats)
        db.commit()
        db.refresh(stats)

    return stats


def update_pvp_stats_after_match(db: Session, match: models.PVPMatch):
    """Update PVP stats for both players after match"""
    p1_stats = get_or_create_pvp_stats(db, match.player1_id)
    p2_stats = get_or_create_pvp_stats(db, match.player2_id)

    # Calculate ELO changes (simplified)
    k_factor = 32
    expected_p1 = 1 / (1 + 10 ** ((p2_stats.current_rating - p1_stats.current_rating) / 400))
    expected_p2 = 1 - expected_p1

    if match.winner_id == match.player1_id:
        actual_p1, actual_p2 = 1, 0
        p1_stats.wins += 1
        p1_stats.current_win_streak += 1
        p1_stats.current_loss_streak = 0
        p2_stats.losses += 1
        p2_stats.current_win_streak = 0
        p2_stats.current_loss_streak += 1
    elif match.winner_id == match.player2_id:
        actual_p1, actual_p2 = 0, 1
        p1_stats.losses += 1
        p1_stats.current_win_streak = 0
        p1_stats.current_loss_streak += 1
        p2_stats.wins += 1
        p2_stats.current_win_streak += 1
        p2_stats.current_loss_streak = 0
    else:
        actual_p1, actual_p2 = 0.5, 0.5
        p1_stats.ties += 1
        p2_stats.ties += 1
        p1_stats.current_win_streak = 0
        p2_stats.current_win_streak = 0

    # Apply rating changes
    p1_change = int(k_factor * (actual_p1 - expected_p1))
    p2_change = int(k_factor * (actual_p2 - expected_p2))

    p1_stats.current_rating += p1_change
    p2_stats.current_rating += p2_change
    match.rating_change = p1_change

    # Update peaks/lows
    p1_stats.peak_rating = max(p1_stats.peak_rating, p1_stats.current_rating)
    p1_stats.lowest_rating = min(p1_stats.lowest_rating, p1_stats.current_rating)
    p2_stats.peak_rating = max(p2_stats.peak_rating, p2_stats.current_rating)
    p2_stats.lowest_rating = min(p2_stats.lowest_rating, p2_stats.current_rating)

    # Update tiers
    p1_stats.rating_tier = get_rating_tier(p1_stats.current_rating)
    p2_stats.rating_tier = get_rating_tier(p2_stats.current_rating)

    # Update longest streaks
    p1_stats.longest_win_streak = max(p1_stats.longest_win_streak, p1_stats.current_win_streak)
    p2_stats.longest_win_streak = max(p2_stats.longest_win_streak, p2_stats.current_win_streak)

    # Update match counts
    p1_stats.total_matches += 1
    p2_stats.total_matches += 1

    # Update win rates
    p1_stats.win_rate = (p1_stats.wins / p1_stats.total_matches * 100) if p1_stats.total_matches > 0 else 0
    p2_stats.win_rate = (p2_stats.wins / p2_stats.total_matches * 100) if p2_stats.total_matches > 0 else 0

    # Update performance stats
    if match.player1_wpm > p1_stats.best_wpm:
        p1_stats.best_wpm = match.player1_wpm
    if match.player1_accuracy > p1_stats.best_accuracy:
        p1_stats.best_accuracy = match.player1_accuracy
    if match.player2_wpm > p2_stats.best_wpm:
        p2_stats.best_wpm = match.player2_wpm
    if match.player2_accuracy > p2_stats.best_accuracy:
        p2_stats.best_accuracy = match.player2_accuracy

    # Update averages
    p1_stats.avg_wpm = ((p1_stats.avg_wpm * (p1_stats.total_matches - 1)) + match.player1_wpm) / p1_stats.total_matches
    p1_stats.avg_accuracy = ((p1_stats.avg_accuracy * (p1_stats.total_matches - 1)) + match.player1_accuracy) / p1_stats.total_matches
    p2_stats.avg_wpm = ((p2_stats.avg_wpm * (p2_stats.total_matches - 1)) + match.player2_wpm) / p2_stats.total_matches
    p2_stats.avg_accuracy = ((p2_stats.avg_accuracy * (p2_stats.total_matches - 1)) + match.player2_accuracy) / p2_stats.total_matches

    # Update timestamps
    p1_stats.last_match_at = datetime.utcnow()
    p2_stats.last_match_at = datetime.utcnow()

    db.commit()


# ==================== LEADERBOARD CRUD ====================

def get_leaderboard(
    db: Session,
    leaderboard_type: str = "all_time",
    limit: int = 100
) -> List[Dict[str, Any]]:
    """Get leaderboard entries"""
    from app.users.models import User

    # Query user stats with user info
    query = db.query(
        models.UserTypingStats,
        User.username,
        User.display_name
    ).join(User).filter(
        models.UserTypingStats.total_games_completed > 0
    )

    if leaderboard_type == "wpm":
        query = query.order_by(desc(models.UserTypingStats.best_wpm))
    elif leaderboard_type == "accuracy":
        query = query.order_by(desc(models.UserTypingStats.best_accuracy))
    else:
        query = query.order_by(desc(models.UserTypingStats.best_wpm))

    results = query.limit(limit).all()

    leaderboard = []
    for idx, (stats, username, display_name) in enumerate(results):
        leaderboard.append({
            "rank": idx + 1,
            "user_id": stats.user_id,
            "username": username,
            "display_name": display_name,
            "best_wpm": stats.best_wpm,
            "avg_wpm": round(stats.avg_wpm, 1),
            "avg_accuracy": round(stats.avg_accuracy, 1),
            "games_played": stats.total_games_completed
        })

    return leaderboard


def get_pvp_leaderboard(db: Session, limit: int = 100) -> List[Dict[str, Any]]:
    """Get PVP leaderboard"""
    from app.users.models import User

    query = db.query(
        models.UserPVPStats,
        User.username,
        User.display_name
    ).join(User).filter(
        models.UserPVPStats.total_matches > 0
    ).order_by(desc(models.UserPVPStats.current_rating))

    results = query.limit(limit).all()

    leaderboard = []
    for idx, (stats, username, display_name) in enumerate(results):
        leaderboard.append({
            "rank": idx + 1,
            "user_id": stats.user_id,
            "username": username,
            "display_name": display_name,
            "rating": stats.current_rating,
            "rating_tier": stats.rating_tier,
            "wins": stats.wins,
            "losses": stats.losses,
            "win_rate": round(stats.win_rate, 1),
            "best_wpm": stats.best_wpm
        })

    return leaderboard


# ==================== HELPER FUNCTIONS ====================

def get_skill_bracket(rating: int) -> str:
    """Determine skill bracket from rating"""
    if rating < 1200:
        return "beginner"
    elif rating < 1500:
        return "intermediate"
    elif rating < 1800:
        return "advanced"
    else:
        return "expert"


def get_rating_tier(rating: int) -> str:
    """Get rating tier name"""
    if rating < 1000:
        return "Bronze"
    elif rating < 1200:
        return "Silver"
    elif rating < 1400:
        return "Gold"
    elif rating < 1600:
        return "Platinum"
    elif rating < 1800:
        return "Diamond"
    elif rating < 2000:
        return "Master"
    else:
        return "Grandmaster"
