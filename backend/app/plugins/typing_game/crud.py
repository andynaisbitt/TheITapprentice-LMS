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
from app.plugins.shared.xp_service import xp_service
from app.plugins.shared.models import ChallengeType
from app.plugins.shared.challenge_service import challenge_service


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
    """Generate random text from word list.

    Handles two formats:
    - Individual words: ["computer", "network", "server"] -> randomly pick word_count words
    - Sentences/phrases: ["The quick brown fox..."] -> randomly pick sentences until reaching word_count words
    """
    entries = word_list.words if word_list.words else []
    if not entries:
        return "The quick brown fox jumps over the lazy dog."

    # Check if entries are sentences (contain spaces) or individual words
    has_sentences = any(' ' in entry.strip() for entry in entries[:10])

    if has_sentences:
        # Entries are sentences/phrases - pick enough to reach word_count
        selected = []
        total_words = 0
        shuffled = entries[:]
        random.shuffle(shuffled)
        idx = 0
        while total_words < word_count:
            entry = shuffled[idx % len(shuffled)].strip()
            selected.append(entry)
            total_words += len(entry.split())
            idx += 1
            # Re-shuffle when we've used all entries
            if idx % len(shuffled) == 0:
                random.shuffle(shuffled)
        return " ".join(selected)
    else:
        # Entries are individual words - pick word_count randomly
        selected_words = [random.choice(entries) for _ in range(word_count)]
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

    # Award XP via the XP service
    xp_result = xp_service.award_typing_game_xp(
        db=db,
        user_id=session.user_id,
        wpm=adjusted_wpm,
        accuracy=accuracy,
        is_pvp_win=False
    )

    # Update xp_earned to match actual awarded XP
    actual_xp = xp_result.get("total_xp_awarded", xp_earned)
    session.total_xp_earned = actual_xp

    # Track challenge progress for typing game completion
    challenge_service.increment_progress(
        db=db,
        user_id=session.user_id,
        challenge_type=ChallengeType.TYPING_GAME,
        amount=1
    )

    # Track WPM for WPM-based challenges
    challenge_service.increment_progress(
        db=db,
        user_id=session.user_id,
        challenge_type=ChallengeType.TYPING_WPM,
        value=adjusted_wpm
    )

    # Track XP earned for XP challenges
    if actual_xp > 0:
        challenge_service.increment_progress(
            db=db,
            user_id=session.user_id,
            challenge_type=ChallengeType.XP_EARN,
            amount=actual_xp
        )

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


def complete_game_session_v2(
    db: Session,
    session_id: str,
    user_input: str,
    time_elapsed: int,
    checksum: str,
    max_combo: int = 0,
    anti_cheat_data: Optional[Dict[str, Any]] = None
) -> Optional[Tuple[models.TypingGameSession, Dict[str, Any]]]:
    """
    Enhanced game session completion with anti-cheat validation.

    Args:
        db: Database session
        session_id: Game session ID
        user_input: User's typed text
        time_elapsed: Time taken in seconds
        checksum: Validation checksum
        max_combo: Maximum combo achieved
        anti_cheat_data: Anti-cheat telemetry data
    """
    from .anti_cheat import validate_typing_session, AntiCheatResult

    session = get_game_session(db, session_id)
    if not session or session.is_completed:
        return None

    # Verify checksum
    expected_checksum = hashlib.sha256(
        f"{session_id}:{session.text_content}".encode()
    ).hexdigest()

    if checksum != expected_checksum:
        session.status = "abandoned"
        db.commit()
        return None

    # Calculate metrics (same as v1)
    original_text = session.text_content
    original_words = original_text.split()
    user_words = user_input.split()

    correct_chars = 0
    total_chars = len(original_text)
    min_len = min(len(original_text), len(user_input))

    for i in range(min_len):
        if i < len(user_input) and i < len(original_text):
            if user_input[i] == original_text[i]:
                correct_chars += 1

    accuracy = (correct_chars / total_chars * 100) if total_chars > 0 else 0
    chars_typed = len(user_input)
    minutes = time_elapsed / 60.0 if time_elapsed > 0 else 1/60
    raw_wpm = int((chars_typed / 5) / minutes)
    error_count = total_chars - correct_chars
    adjusted_wpm = max(0, int(((chars_typed / 5) - error_count) / minutes))

    # Anti-cheat validation
    anti_cheat_result: Optional[AntiCheatResult] = None
    xp_multiplier = 1.0

    if anti_cheat_data:
        anti_cheat_result = validate_typing_session(
            keystroke_timings=anti_cheat_data.get("keystroke_timings", []),
            keystroke_count=anti_cheat_data.get("keystroke_count", 0),
            paste_attempts=anti_cheat_data.get("paste_attempts", 0),
            focus_lost_count=anti_cheat_data.get("focus_lost_count", 0),
            total_focus_lost_time=anti_cheat_data.get("total_focus_lost_time", 0),
            wpm=adjusted_wpm,
            accuracy=accuracy,
            time_elapsed=time_elapsed,
            first_segment_avg=anti_cheat_data.get("first_segment_avg"),
            last_segment_avg=anti_cheat_data.get("last_segment_avg"),
        )

        # Store anti-cheat results
        session.anti_cheat_confidence = anti_cheat_result.confidence_score
        session.anti_cheat_flags = anti_cheat_result.flags
        session.anti_cheat_flagged_for_review = anti_cheat_result.should_flag_for_review
        xp_multiplier = anti_cheat_result.adjusted_xp_multiplier

        # Reject invalid sessions
        if not anti_cheat_result.is_valid:
            session.status = "rejected"
            session.is_completed = True
            session.completed_at = datetime.utcnow()
            db.commit()
            return session, {
                "metrics": {
                    "wpm": adjusted_wpm,
                    "raw_wpm": raw_wpm,
                    "accuracy": round(accuracy, 2),
                    "error_count": error_count,
                    "total_characters": total_chars,
                    "time_elapsed": time_elapsed
                },
                "xp_earned": 0,
                "is_personal_best_wpm": False,
                "is_personal_best_accuracy": False,
                "max_combo": max_combo,
                "anti_cheat": {
                    "confidence_score": anti_cheat_result.confidence_score,
                    "flags": anti_cheat_result.flags,
                    "is_valid": False
                }
            }

    # Update session
    session.user_input = user_input
    session.time_taken = time_elapsed
    session.wpm = adjusted_wpm
    session.raw_wpm = raw_wpm
    session.accuracy = round(accuracy, 2)
    session.mistakes = error_count
    session.characters_typed = chars_typed
    session.max_combo = max_combo
    session.is_completed = True
    session.status = "completed"
    session.completed_at = datetime.utcnow()

    # Calculate XP with anti-cheat multiplier
    base_xp = 10
    wpm_bonus = adjusted_wpm // 10
    accuracy_bonus = int(accuracy // 10)
    combo_bonus = max_combo // 25  # Extra XP for combos
    raw_xp = base_xp + wpm_bonus + accuracy_bonus + combo_bonus
    xp_earned = int(raw_xp * xp_multiplier)
    session.total_xp_earned = xp_earned

    # Update user stats and check personal bests
    stats = get_or_create_user_stats(db, session.user_id)
    is_pb_wpm = False
    is_pb_accuracy = False

    # Only count personal bests for legitimate sessions
    if xp_multiplier >= 1.0:
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
            total_plays = word_list.times_played
            word_list.avg_wpm = (
                (word_list.avg_wpm * (total_plays - 1) + adjusted_wpm)
                / total_plays
            ) if total_plays > 0 else adjusted_wpm
            word_list.avg_accuracy = (
                (word_list.avg_accuracy * (total_plays - 1) + accuracy)
                / total_plays
            ) if total_plays > 0 else accuracy

    # Award XP via the XP service (only if multiplier is positive)
    if xp_multiplier > 0:
        xp_result = xp_service.award_typing_game_xp(
            db=db,
            user_id=session.user_id,
            wpm=adjusted_wpm,
            accuracy=accuracy,
            is_pvp_win=False
        )
        actual_xp = int(xp_result.get("total_xp_awarded", xp_earned) * xp_multiplier)
        session.total_xp_earned = actual_xp
    else:
        actual_xp = 0

    # Track challenge progress
    challenge_service.increment_progress(
        db=db,
        user_id=session.user_id,
        challenge_type=ChallengeType.TYPING_GAME,
        amount=1
    )

    challenge_service.increment_progress(
        db=db,
        user_id=session.user_id,
        challenge_type=ChallengeType.TYPING_WPM,
        value=adjusted_wpm
    )

    if actual_xp > 0:
        challenge_service.increment_progress(
            db=db,
            user_id=session.user_id,
            challenge_type=ChallengeType.XP_EARN,
            amount=actual_xp
        )

    db.commit()
    db.refresh(session)

    result = {
        "metrics": {
            "wpm": adjusted_wpm,
            "raw_wpm": raw_wpm,
            "accuracy": round(accuracy, 2),
            "error_count": error_count,
            "total_characters": total_chars,
            "time_elapsed": time_elapsed
        },
        "xp_earned": actual_xp,
        "is_personal_best_wpm": is_pb_wpm,
        "is_personal_best_accuracy": is_pb_accuracy,
        "max_combo": max_combo,
    }

    if anti_cheat_result:
        result["anti_cheat"] = {
            "confidence_score": anti_cheat_result.confidence_score,
            "flags": anti_cheat_result.flags,
            "is_valid": anti_cheat_result.is_valid
        }

    return session, result


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
    difficulty: str = "medium",
    use_sentences: bool = True
) -> models.PVPMatch:
    """Create new PVP match"""
    match_id = str(uuid.uuid4())

    # Generate content - prefer sentences over random words
    if use_sentences:
        text_content = generate_sentence_for_pvp(db, difficulty, round_number=1)
    else:
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

            # Generate new content for the next round
            next_round_content = generate_sentence_for_pvp(
                db, match.difficulty, round_number=match.current_round
            )
            match.content = next_round_content
            match.checksum = hashlib.sha256(
                f"{match.id}:{next_round_content}".encode()
            ).hexdigest()
            match.word_count = len(next_round_content.split())

            # Store next round content in result for immediate access
            result["next_round_content"] = next_round_content
            result["next_round_word_count"] = match.word_count

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
    """Update PVP stats for both players after match and award XP"""
    p1_stats = get_or_create_pvp_stats(db, match.player1_id)
    p2_stats = get_or_create_pvp_stats(db, match.player2_id)

    # Determine winners for XP awarding
    p1_is_winner = match.winner_id == match.player1_id
    p2_is_winner = match.winner_id == match.player2_id

    # Award XP to both players
    xp_service.award_typing_game_xp(
        db=db,
        user_id=match.player1_id,
        wpm=match.player1_wpm or 0,
        accuracy=match.player1_accuracy or 0,
        is_pvp_win=p1_is_winner
    )

    xp_service.award_typing_game_xp(
        db=db,
        user_id=match.player2_id,
        wpm=match.player2_wpm or 0,
        accuracy=match.player2_accuracy or 0,
        is_pvp_win=p2_is_winner
    )

    # Track PVP game completion for challenges
    challenge_service.increment_progress(
        db=db,
        user_id=match.player1_id,
        challenge_type=ChallengeType.TYPING_GAME,
        amount=1
    )
    challenge_service.increment_progress(
        db=db,
        user_id=match.player2_id,
        challenge_type=ChallengeType.TYPING_GAME,
        amount=1
    )

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

    # Query user stats with user info (use actual columns, not properties)
    query = db.query(
        models.UserTypingStats,
        User.username,
        User.first_name,
        User.last_name
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
    for idx, (stats, username, first_name, last_name) in enumerate(results):
        # Compute display_name from first_name/last_name or fallback to username
        if first_name and last_name:
            display_name = f"{first_name} {last_name}"
        else:
            display_name = username
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

    # Query with actual columns, not Python properties
    query = db.query(
        models.UserPVPStats,
        User.username,
        User.first_name,
        User.last_name
    ).join(User).filter(
        models.UserPVPStats.total_matches > 0
    ).order_by(desc(models.UserPVPStats.current_rating))

    results = query.limit(limit).all()

    leaderboard = []
    for idx, (stats, username, first_name, last_name) in enumerate(results):
        # Compute display_name from first_name/last_name or fallback to username
        if first_name and last_name:
            display_name = f"{first_name} {last_name}"
        else:
            display_name = username
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


# ==================== SENTENCE POOL CRUD ====================

def get_sentence_pool(db: Session, pool_id: str) -> Optional[models.SentencePool]:
    """Get sentence pool by ID"""
    return db.query(models.SentencePool).filter(
        models.SentencePool.id == pool_id
    ).first()


def get_sentence_pools(
    db: Session,
    difficulty: Optional[str] = None,
    category: Optional[str] = None,
    is_active: bool = True,
    skip: int = 0,
    limit: int = 100
) -> Tuple[List[models.SentencePool], int]:
    """Get all sentence pools with optional filters"""
    query = db.query(models.SentencePool)

    if is_active is not None:
        query = query.filter(models.SentencePool.is_active == is_active)

    if difficulty:
        query = query.filter(models.SentencePool.difficulty == difficulty)

    if category:
        query = query.filter(models.SentencePool.category == category)

    total = query.count()

    pools = query.order_by(
        models.SentencePool.display_order,
        models.SentencePool.name
    ).offset(skip).limit(limit).all()

    return pools, total


def get_sentence_pools_for_round(
    db: Session,
    difficulty: str,
    round_number: int = 1
) -> List[models.SentencePool]:
    """Get sentence pools suitable for a specific PVP round"""
    pools = db.query(models.SentencePool).filter(
        models.SentencePool.is_active == True,
        models.SentencePool.difficulty == difficulty
    ).all()

    # Filter by round suitability
    suitable_pools = []
    for pool in pools:
        round_suitable = pool.round_suitable or [1, 2, 3]
        if round_number in round_suitable:
            suitable_pools.append(pool)

    return suitable_pools if suitable_pools else pools


def create_sentence_pool(
    db: Session,
    pool_data: schemas.SentencePoolCreate,
    created_by: Optional[int] = None
) -> models.SentencePool:
    """Create new sentence pool (admin only)"""
    pool_id = str(uuid.uuid4())

    # Calculate average word count
    sentences = pool_data.sentences
    total_words = sum(len(s.split()) for s in sentences)
    avg_word_count = total_words / len(sentences) if sentences else 0

    db_pool = models.SentencePool(
        id=pool_id,
        name=pool_data.name,
        description=pool_data.description,
        difficulty=pool_data.difficulty,
        category=pool_data.category,
        sentences=sentences,
        min_length=pool_data.min_length,
        max_length=pool_data.max_length,
        avg_word_count=round(avg_word_count, 1),
        is_active=pool_data.is_active,
        is_featured=pool_data.is_featured,
        display_order=pool_data.display_order,
        round_suitable=pool_data.round_suitable,
        difficulty_weight=pool_data.difficulty_weight,
        created_by=created_by
    )

    db.add(db_pool)
    db.commit()
    db.refresh(db_pool)
    return db_pool


def update_sentence_pool(
    db: Session,
    pool_id: str,
    pool_data: schemas.SentencePoolUpdate
) -> Optional[models.SentencePool]:
    """Update sentence pool (admin only)"""
    db_pool = get_sentence_pool(db, pool_id)
    if not db_pool:
        return None

    update_data = pool_data.model_dump(exclude_unset=True)

    # Recalculate avg_word_count if sentences are updated
    if "sentences" in update_data and update_data["sentences"]:
        sentences = update_data["sentences"]
        total_words = sum(len(s.split()) for s in sentences)
        update_data["avg_word_count"] = round(total_words / len(sentences), 1) if sentences else 0

    for field, value in update_data.items():
        setattr(db_pool, field, value)

    db.commit()
    db.refresh(db_pool)
    return db_pool


def delete_sentence_pool(db: Session, pool_id: str) -> bool:
    """Delete sentence pool (admin only)"""
    db_pool = get_sentence_pool(db, pool_id)
    if not db_pool:
        return False

    db.delete(db_pool)
    db.commit()
    return True


def generate_sentence_for_pvp(
    db: Session,
    difficulty: str,
    round_number: int = 1
) -> str:
    """
    Generate text content for PVP from sentence pools.
    Falls back to default text if no suitable pools exist.
    """
    pools = get_sentence_pools_for_round(db, difficulty, round_number)

    if not pools:
        # Fallback to default word-based generation
        return generate_default_text(50)

    # Select pool based on difficulty weight
    total_weight = sum(pool.difficulty_weight for pool in pools)
    if total_weight == 0:
        selected_pool = random.choice(pools)
    else:
        rand_value = random.uniform(0, total_weight)
        cumulative_weight = 0
        selected_pool = pools[0]
        for pool in pools:
            cumulative_weight += pool.difficulty_weight
            if rand_value <= cumulative_weight:
                selected_pool = pool
                break

    # Select random sentence from the pool
    sentences = selected_pool.sentences or []
    if not sentences:
        return generate_default_text(50)

    selected_sentence = random.choice(sentences)

    # Update pool stats
    selected_pool.times_used += 1
    db.commit()

    return selected_sentence


def update_sentence_pool_stats(
    db: Session,
    pool_id: str,
    wpm: float,
    accuracy: float
) -> None:
    """Update sentence pool stats after a PVP round"""
    pool = get_sentence_pool(db, pool_id)
    if not pool:
        return

    times_used = pool.times_used or 1

    # Update running averages
    pool.avg_wpm = ((pool.avg_wpm * (times_used - 1)) + wpm) / times_used
    pool.avg_accuracy = ((pool.avg_accuracy * (times_used - 1)) + accuracy) / times_used

    db.commit()


# ==================== ANALYTICS CRUD ====================

# Common digraphs/patterns to track
COMMON_PATTERNS = [
    'th', 'he', 'in', 'er', 'an', 'on', 're', 'ed', 'nd', 'at',
    'en', 'es', 'or', 'te', 'of', 'it', 'is', 'al', 'ar', 'st',
    'to', 'nt', 'ng', 'se', 'ha', 'as', 'ou', 'io', 'le', 'ti',
    'ing', 'tion', 'the', 'and', 'ent', 'ion', 'for', 'was', 'are'
]


def get_or_create_letter_stats(
    db: Session,
    user_id: int,
    character: str
) -> models.UserLetterStats:
    """Get or create letter stats for a user and character"""
    stats = db.query(models.UserLetterStats).filter(
        models.UserLetterStats.user_id == user_id,
        models.UserLetterStats.character == character
    ).first()

    if not stats:
        stats = models.UserLetterStats(
            user_id=user_id,
            character=character,
            total_attempts=0,
            total_correct=0,
            total_incorrect=0,
            accuracy_rate=0.0,
            avg_time_to_type=0.0,
            context_stats={},
            common_mistakes=[]
        )
        db.add(stats)
        db.commit()
        db.refresh(stats)

    return stats


def update_letter_stats(
    db: Session,
    user_id: int,
    character: str,
    is_correct: bool,
    time_ms: Optional[float] = None,
    actual_typed: Optional[str] = None
) -> models.UserLetterStats:
    """Update letter stats after typing a character"""
    stats = get_or_create_letter_stats(db, user_id, character)

    stats.total_attempts += 1
    if is_correct:
        stats.total_correct += 1
    else:
        stats.total_incorrect += 1
        # Track common mistakes
        if actual_typed:
            mistakes = stats.common_mistakes or []
            mistake_entry = next(
                (m for m in mistakes if m.get('typed') == actual_typed),
                None
            )
            if mistake_entry:
                mistake_entry['count'] = mistake_entry.get('count', 0) + 1
            else:
                mistakes.append({'typed': actual_typed, 'count': 1})
            # Keep only top 5 mistakes
            mistakes.sort(key=lambda x: x.get('count', 0), reverse=True)
            stats.common_mistakes = mistakes[:5]

    # Update accuracy rate
    stats.accuracy_rate = (stats.total_correct / stats.total_attempts * 100) if stats.total_attempts > 0 else 0

    # Update timing stats
    if time_ms is not None and time_ms > 0:
        if stats.min_time_to_type is None or time_ms < stats.min_time_to_type:
            stats.min_time_to_type = time_ms
        if stats.max_time_to_type is None or time_ms > stats.max_time_to_type:
            stats.max_time_to_type = time_ms

        # Update average time (running average)
        old_avg = stats.avg_time_to_type or time_ms
        stats.avg_time_to_type = (
            (old_avg * (stats.total_attempts - 1) + time_ms) / stats.total_attempts
        )

    stats.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(stats)
    return stats


def get_user_letter_stats(
    db: Session,
    user_id: int,
    limit: int = 100
) -> List[models.UserLetterStats]:
    """Get all letter stats for a user"""
    return db.query(models.UserLetterStats).filter(
        models.UserLetterStats.user_id == user_id
    ).order_by(
        models.UserLetterStats.accuracy_rate.asc()  # Worst first
    ).limit(limit).all()


def get_user_weak_letters(
    db: Session,
    user_id: int,
    min_attempts: int = 10,
    limit: int = 10
) -> List[models.UserLetterStats]:
    """Get user's weakest letters (lowest accuracy with enough attempts)"""
    return db.query(models.UserLetterStats).filter(
        models.UserLetterStats.user_id == user_id,
        models.UserLetterStats.total_attempts >= min_attempts
    ).order_by(
        models.UserLetterStats.accuracy_rate.asc()
    ).limit(limit).all()


def get_or_create_pattern_stats(
    db: Session,
    user_id: int,
    pattern: str
) -> models.UserPatternStats:
    """Get or create pattern stats for a user"""
    stats = db.query(models.UserPatternStats).filter(
        models.UserPatternStats.user_id == user_id,
        models.UserPatternStats.pattern == pattern
    ).first()

    if not stats:
        stats = models.UserPatternStats(
            user_id=user_id,
            pattern=pattern,
            total_attempts=0,
            total_correct=0,
            accuracy_rate=0.0,
            avg_time_ms=0.0
        )
        db.add(stats)
        db.commit()
        db.refresh(stats)

    return stats


def update_pattern_stats(
    db: Session,
    user_id: int,
    pattern: str,
    is_correct: bool,
    time_ms: Optional[float] = None
) -> models.UserPatternStats:
    """Update pattern stats after typing a pattern"""
    stats = get_or_create_pattern_stats(db, user_id, pattern)

    stats.total_attempts += 1
    if is_correct:
        stats.total_correct += 1

    # Update accuracy rate
    stats.accuracy_rate = (stats.total_correct / stats.total_attempts * 100) if stats.total_attempts > 0 else 0

    # Update timing stats
    if time_ms is not None and time_ms > 0:
        old_avg = stats.avg_time_ms or time_ms
        stats.avg_time_ms = (
            (old_avg * (stats.total_attempts - 1) + time_ms) / stats.total_attempts
        )

    stats.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(stats)
    return stats


def get_user_pattern_stats(
    db: Session,
    user_id: int,
    limit: int = 50
) -> List[models.UserPatternStats]:
    """Get all pattern stats for a user"""
    return db.query(models.UserPatternStats).filter(
        models.UserPatternStats.user_id == user_id
    ).order_by(
        models.UserPatternStats.accuracy_rate.asc()
    ).limit(limit).all()


def get_user_weak_patterns(
    db: Session,
    user_id: int,
    min_attempts: int = 5,
    limit: int = 10
) -> List[models.UserPatternStats]:
    """Get user's weakest patterns"""
    return db.query(models.UserPatternStats).filter(
        models.UserPatternStats.user_id == user_id,
        models.UserPatternStats.total_attempts >= min_attempts
    ).order_by(
        models.UserPatternStats.accuracy_rate.asc()
    ).limit(limit).all()


def create_session_analytics(
    db: Session,
    session_id: str,
    wpm_timeline: List[Dict[str, Any]],
    error_positions: List[int],
    keystroke_intervals: List[float],
    slowest_words: List[Dict[str, Any]],
    fastest_words: List[Dict[str, Any]],
    confidence_score: float = 1.0,
    anti_cheat_flags: List[str] = None
) -> models.TypingSessionAnalytics:
    """Create detailed session analytics"""
    import statistics

    # Calculate error heatmap (position -> count)
    error_heatmap = {}
    for pos in error_positions:
        # Group into buckets of 10 characters
        bucket = (pos // 10) * 10
        error_heatmap[str(bucket)] = error_heatmap.get(str(bucket), 0) + 1

    # Calculate keystroke timing stats
    avg_inter_key_time = statistics.mean(keystroke_intervals) if keystroke_intervals else 0
    std_dev_inter_key_time = statistics.stdev(keystroke_intervals) if len(keystroke_intervals) > 1 else 0

    analytics = models.TypingSessionAnalytics(
        session_id=session_id,
        wpm_timeline=wpm_timeline,
        error_positions=error_positions,
        error_heatmap=error_heatmap,
        keystroke_intervals=keystroke_intervals[:500],  # Limit stored intervals
        avg_inter_key_time=avg_inter_key_time,
        std_dev_inter_key_time=std_dev_inter_key_time,
        slowest_words=slowest_words[:10],
        fastest_words=fastest_words[:10],
        confidence_score=confidence_score,
        anti_cheat_flags=anti_cheat_flags or []
    )

    db.add(analytics)
    db.commit()
    db.refresh(analytics)
    return analytics


def get_session_analytics(
    db: Session,
    session_id: str
) -> Optional[models.TypingSessionAnalytics]:
    """Get analytics for a specific session"""
    return db.query(models.TypingSessionAnalytics).filter(
        models.TypingSessionAnalytics.session_id == session_id
    ).first()


def process_typing_analytics(
    db: Session,
    user_id: int,
    session_id: str,
    original_text: str,
    user_input: str,
    keystroke_data: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Process typing session and update all analytics.

    Args:
        db: Database session
        user_id: User ID
        session_id: Game session ID
        original_text: The text the user was supposed to type
        user_input: What the user actually typed
        keystroke_data: List of keystroke events with timing info
            Each entry: {'char': 'a', 'time_ms': 150, 'timestamp': 1234567890}

    Returns:
        Analytics summary dict
    """
    # Track letter stats
    letter_results = {}
    for i, expected_char in enumerate(original_text):
        actual_char = user_input[i] if i < len(user_input) else None
        is_correct = actual_char == expected_char

        # Get timing for this character if available
        time_ms = None
        if i < len(keystroke_data):
            time_ms = keystroke_data[i].get('time_ms')

        update_letter_stats(
            db=db,
            user_id=user_id,
            character=expected_char.lower(),
            is_correct=is_correct,
            time_ms=time_ms,
            actual_typed=actual_char if not is_correct else None
        )

        letter_results[expected_char.lower()] = letter_results.get(expected_char.lower(), {'correct': 0, 'total': 0})
        letter_results[expected_char.lower()]['total'] += 1
        if is_correct:
            letter_results[expected_char.lower()]['correct'] += 1

    # Track pattern stats
    pattern_results = {}
    for pattern in COMMON_PATTERNS:
        # Find all occurrences of pattern in original text
        start = 0
        while True:
            idx = original_text.lower().find(pattern, start)
            if idx == -1:
                break

            # Check if user typed this pattern correctly
            end_idx = idx + len(pattern)
            if end_idx <= len(user_input):
                is_correct = user_input[idx:end_idx].lower() == pattern

                # Calculate time for pattern (sum of individual keystrokes)
                pattern_time = None
                if end_idx <= len(keystroke_data):
                    times = [kd.get('time_ms', 0) for kd in keystroke_data[idx:end_idx] if kd.get('time_ms')]
                    if times:
                        pattern_time = sum(times)

                update_pattern_stats(
                    db=db,
                    user_id=user_id,
                    pattern=pattern,
                    is_correct=is_correct,
                    time_ms=pattern_time
                )

                pattern_results[pattern] = pattern_results.get(pattern, {'correct': 0, 'total': 0})
                pattern_results[pattern]['total'] += 1
                if is_correct:
                    pattern_results[pattern]['correct'] += 1

            start = idx + 1

    # Calculate WPM timeline (every 5 seconds)
    wpm_timeline = []
    if keystroke_data:
        timestamps = [kd.get('timestamp', 0) for kd in keystroke_data]
        if timestamps:
            start_time = timestamps[0]
            current_chars = 0
            interval = 5000  # 5 seconds in ms

            for i, kd in enumerate(keystroke_data):
                current_chars += 1
                elapsed_ms = kd.get('timestamp', 0) - start_time

                if elapsed_ms > 0 and elapsed_ms % interval < 200:  # Within 200ms of interval
                    elapsed_min = elapsed_ms / 60000
                    wpm = int((current_chars / 5) / elapsed_min) if elapsed_min > 0 else 0
                    wpm_timeline.append({
                        'time_sec': int(elapsed_ms / 1000),
                        'wpm': wpm,
                        'chars': current_chars
                    })

    # Find error positions
    error_positions = []
    for i, expected_char in enumerate(original_text):
        if i >= len(user_input) or user_input[i] != expected_char:
            error_positions.append(i)

    # Calculate word speeds
    words = original_text.split()
    word_timings = []
    char_idx = 0

    for word in words:
        word_start_idx = char_idx
        word_end_idx = char_idx + len(word)

        if word_end_idx <= len(keystroke_data):
            word_times = [kd.get('time_ms', 0) for kd in keystroke_data[word_start_idx:word_end_idx]]
            if word_times:
                total_time = sum(word_times)
                word_timings.append({
                    'word': word,
                    'time_ms': total_time,
                    'avg_per_char': total_time / len(word)
                })

        char_idx = word_end_idx + 1  # +1 for space

    # Sort to find slowest/fastest
    word_timings.sort(key=lambda x: x.get('time_ms', 0), reverse=True)
    slowest_words = word_timings[:10]
    fastest_words = list(reversed(word_timings[-10:])) if len(word_timings) >= 10 else []

    # Get keystroke intervals
    keystroke_intervals = [kd.get('time_ms', 0) for kd in keystroke_data if kd.get('time_ms')]

    # Create session analytics
    analytics = create_session_analytics(
        db=db,
        session_id=session_id,
        wpm_timeline=wpm_timeline,
        error_positions=error_positions,
        keystroke_intervals=keystroke_intervals,
        slowest_words=slowest_words,
        fastest_words=fastest_words
    )

    return {
        'letter_results': letter_results,
        'pattern_results': pattern_results,
        'error_count': len(error_positions),
        'wpm_samples': len(wpm_timeline),
        'analytics_id': analytics.id
    }


def get_user_analytics_summary(
    db: Session,
    user_id: int
) -> Dict[str, Any]:
    """Get comprehensive analytics summary for a user"""
    # Get typing stats
    typing_stats = get_or_create_user_stats(db, user_id)

    # Get weak letters
    weak_letters = get_user_weak_letters(db, user_id, min_attempts=10, limit=5)

    # Get weak patterns
    weak_patterns = get_user_weak_patterns(db, user_id, min_attempts=5, limit=5)

    # Get all letter stats for heatmap
    all_letters = get_user_letter_stats(db, user_id, limit=50)

    # Calculate overall letter accuracy
    total_letter_attempts = sum(ls.total_attempts for ls in all_letters)
    total_letter_correct = sum(ls.total_correct for ls in all_letters)
    overall_letter_accuracy = (total_letter_correct / total_letter_attempts * 100) if total_letter_attempts > 0 else 0

    return {
        'typing_stats': {
            'best_wpm': typing_stats.best_wpm,
            'avg_wpm': round(typing_stats.avg_wpm, 1),
            'best_accuracy': round(typing_stats.best_accuracy, 1),
            'avg_accuracy': round(typing_stats.avg_accuracy, 1),
            'total_games': typing_stats.total_games_completed,
            'total_time_minutes': typing_stats.total_time_seconds // 60,
            'total_words_typed': typing_stats.total_words_typed
        },
        'letter_analysis': {
            'overall_accuracy': round(overall_letter_accuracy, 1),
            'total_letters_tracked': len(all_letters),
            'weak_letters': [
                {
                    'character': ls.character,
                    'accuracy': round(ls.accuracy_rate, 1),
                    'attempts': ls.total_attempts,
                    'avg_time_ms': round(ls.avg_time_to_type, 1) if ls.avg_time_to_type else None,
                    'common_mistakes': ls.common_mistakes[:3] if ls.common_mistakes else []
                }
                for ls in weak_letters
            ],
            'letter_heatmap': [
                {
                    'character': ls.character,
                    'accuracy': round(ls.accuracy_rate, 1),
                    'attempts': ls.total_attempts
                }
                for ls in all_letters
            ]
        },
        'pattern_analysis': {
            'weak_patterns': [
                {
                    'pattern': ps.pattern,
                    'accuracy': round(ps.accuracy_rate, 1),
                    'attempts': ps.total_attempts,
                    'avg_time_ms': round(ps.avg_time_ms, 1) if ps.avg_time_ms else None
                }
                for ps in weak_patterns
            ]
        },
        'recommendations': generate_practice_recommendations(weak_letters, weak_patterns)
    }


def generate_practice_recommendations(
    weak_letters: List[models.UserLetterStats],
    weak_patterns: List[models.UserPatternStats]
) -> List[Dict[str, Any]]:
    """Generate personalized practice recommendations"""
    recommendations = []

    # Letter-based recommendations
    for ls in weak_letters[:3]:
        if ls.accuracy_rate < 80:
            recommendations.append({
                'type': 'letter',
                'target': ls.character,
                'accuracy': round(ls.accuracy_rate, 1),
                'suggestion': f"Practice words containing '{ls.character}' - your accuracy is {ls.accuracy_rate:.0f}%",
                'priority': 'high' if ls.accuracy_rate < 60 else 'medium'
            })

    # Pattern-based recommendations
    for ps in weak_patterns[:2]:
        if ps.accuracy_rate < 80:
            recommendations.append({
                'type': 'pattern',
                'target': ps.pattern,
                'accuracy': round(ps.accuracy_rate, 1),
                'suggestion': f"Focus on the '{ps.pattern}' combination - accuracy is {ps.accuracy_rate:.0f}%",
                'priority': 'high' if ps.accuracy_rate < 60 else 'medium'
            })

    # Sort by priority
    priority_order = {'high': 0, 'medium': 1, 'low': 2}
    recommendations.sort(key=lambda x: priority_order.get(x.get('priority', 'low'), 2))

    return recommendations[:5]


# ==================== STREAK CRUD ====================

def get_or_create_user_streak(
    db: Session,
    user_id: int
) -> models.UserTypingStreak:
    """Get or create user typing streak record"""
    streak = db.query(models.UserTypingStreak).filter(
        models.UserTypingStreak.user_id == user_id
    ).first()

    if not streak:
        streak = models.UserTypingStreak(
            user_id=user_id,
            current_streak=0,
            longest_streak=0,
            last_play_date=None,
            freeze_available=True,
            last_freeze_used=None,
            first_game_today=True,
            games_today=0
        )
        db.add(streak)
        db.commit()
        db.refresh(streak)

    return streak


def update_user_streak(
    db: Session,
    user_id: int
) -> Dict[str, Any]:
    """
    Update user's streak after completing a game.
    Returns streak info including any bonuses earned.
    """
    streak = get_or_create_user_streak(db, user_id)
    today = datetime.utcnow().date()

    result = {
        'streak_before': streak.current_streak,
        'streak_after': streak.current_streak,
        'is_first_game_today': False,
        'streak_bonus_xp': 0,
        'streak_extended': False,
        'streak_restored': False,
        'freeze_used': False
    }

    # Check if this is the first game today
    if streak.last_play_date is None or streak.last_play_date < today:
        result['is_first_game_today'] = True
        streak.first_game_today = False  # No longer first game
        streak.games_today = 1

        # Check streak continuity
        if streak.last_play_date is None:
            # First ever game
            streak.current_streak = 1
            result['streak_after'] = 1
            result['streak_extended'] = True
        elif streak.last_play_date == today - timedelta(days=1):
            # Played yesterday - extend streak
            streak.current_streak += 1
            result['streak_after'] = streak.current_streak
            result['streak_extended'] = True
        elif streak.last_play_date == today - timedelta(days=2) and streak.freeze_available:
            # Missed one day but have freeze available
            streak.freeze_available = False
            streak.last_freeze_used = today
            streak.current_streak += 1  # Continue streak
            result['streak_after'] = streak.current_streak
            result['streak_extended'] = True
            result['freeze_used'] = True
            result['streak_restored'] = True
        else:
            # Streak broken
            streak.current_streak = 1
            result['streak_after'] = 1

        # Update longest streak
        if streak.current_streak > streak.longest_streak:
            streak.longest_streak = streak.current_streak

        # Calculate streak bonus XP (10 XP per day in streak, max 100)
        result['streak_bonus_xp'] = min(streak.current_streak * 10, 100)

        streak.last_play_date = today
    else:
        # Already played today, just increment games_today
        streak.games_today += 1
        result['streak_after'] = streak.current_streak

    # Reset freeze availability weekly (on Sunday)
    if today.weekday() == 6 and (
        streak.last_freeze_used is None or
        streak.last_freeze_used < today - timedelta(days=7)
    ):
        streak.freeze_available = True

    streak.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(streak)

    return result


def use_streak_freeze(
    db: Session,
    user_id: int
) -> Dict[str, Any]:
    """Manually use a streak freeze"""
    streak = get_or_create_user_streak(db, user_id)

    if not streak.freeze_available:
        return {
            'success': False,
            'message': 'No streak freeze available. Resets weekly on Sunday.'
        }

    streak.freeze_available = False
    streak.last_freeze_used = datetime.utcnow().date()
    db.commit()

    return {
        'success': True,
        'message': 'Streak freeze activated!'
    }


def get_user_streak_info(
    db: Session,
    user_id: int
) -> Dict[str, Any]:
    """Get user's current streak information"""
    streak = get_or_create_user_streak(db, user_id)
    today = datetime.utcnow().date()

    # Check if streak is at risk
    streak_at_risk = False
    if streak.last_play_date:
        last_play_date = streak.last_play_date.date() if isinstance(streak.last_play_date, datetime) else streak.last_play_date
        if last_play_date < today:
            if last_play_date < today - timedelta(days=1):
                streak_at_risk = True

    # Check if freeze would auto-apply
    last_play_date = streak.last_play_date.date() if streak.last_play_date and isinstance(streak.last_play_date, datetime) else streak.last_play_date
    freeze_will_auto_apply = (
        streak_at_risk and
        streak.freeze_available and
        last_play_date == today - timedelta(days=2)
    )

    return {
        'current_streak': streak.current_streak,
        'longest_streak': streak.longest_streak,
        'last_play_date': streak.last_play_date.isoformat() if streak.last_play_date else None,
        'games_today': streak.games_today,
        'freeze_available': streak.freeze_available,
        'streak_at_risk': streak_at_risk,
        'freeze_will_auto_apply': freeze_will_auto_apply,
        'played_today': streak.last_play_date == today if streak.last_play_date else False
    }


# ==================== DAILY CHALLENGE CRUD ====================

# Challenge types and their configurations
CHALLENGE_TYPES = {
    'games_completed': {
        'name': 'Play Games',
        'description_template': 'Complete {target} typing games',
        'targets': {'easy': 3, 'medium': 5, 'hard': 10},
        'xp_rewards': {'easy': 50, 'medium': 100, 'hard': 200}
    },
    'wpm_achieved': {
        'name': 'Speed Demon',
        'description_template': 'Achieve {target} WPM or higher in a single game',
        'targets': {'easy': 30, 'medium': 50, 'hard': 80},
        'xp_rewards': {'easy': 75, 'medium': 150, 'hard': 300}
    },
    'accuracy_achieved': {
        'name': 'Perfectionist',
        'description_template': 'Achieve {target}% accuracy or higher',
        'targets': {'easy': 90, 'medium': 95, 'hard': 99},
        'xp_rewards': {'easy': 60, 'medium': 120, 'hard': 250}
    },
    'words_typed': {
        'name': 'Wordsmith',
        'description_template': 'Type {target} words total',
        'targets': {'easy': 100, 'medium': 300, 'hard': 500},
        'xp_rewards': {'easy': 50, 'medium': 100, 'hard': 200}
    },
    'combo_achieved': {
        'name': 'Combo Master',
        'description_template': 'Achieve a {target}x combo',
        'targets': {'easy': 25, 'medium': 50, 'hard': 100},
        'xp_rewards': {'easy': 75, 'medium': 150, 'hard': 300}
    }
}


def get_or_create_daily_challenges(
    db: Session,
    challenge_date: Optional[datetime] = None
) -> List[models.TypingDailyChallenge]:
    """Get or create daily challenges for a specific date"""
    if challenge_date is None:
        challenge_date = datetime.utcnow().date()
    elif hasattr(challenge_date, 'date'):
        challenge_date = challenge_date.date()

    # Check if challenges exist for this date
    existing = db.query(models.TypingDailyChallenge).filter(
        models.TypingDailyChallenge.challenge_date == challenge_date,
        models.TypingDailyChallenge.is_active == True
    ).all()

    if existing:
        return existing

    # Create new challenges for the day
    challenges = []
    difficulties = ['easy', 'medium', 'hard']

    # Select 3 random challenge types for the day
    available_types = list(CHALLENGE_TYPES.keys())
    random.shuffle(available_types)
    selected_types = available_types[:3]

    for i, (challenge_type, difficulty) in enumerate(zip(selected_types, difficulties)):
        config = CHALLENGE_TYPES[challenge_type]
        target = config['targets'][difficulty]
        xp_reward = config['xp_rewards'][difficulty]

        challenge = models.TypingDailyChallenge(
            id=str(uuid.uuid4()),
            challenge_date=challenge_date,
            challenge_type=challenge_type,
            target_value=target,
            difficulty=difficulty,
            xp_reward=xp_reward,
            bonus_text=config['description_template'].format(target=target),
            is_active=True
        )
        db.add(challenge)
        challenges.append(challenge)

    db.commit()
    for c in challenges:
        db.refresh(c)

    return challenges


def get_daily_challenges_with_progress(
    db: Session,
    user_id: int,
    challenge_date: Optional[datetime] = None
) -> List[Dict[str, Any]]:
    """Get daily challenges with user's progress"""
    challenges = get_or_create_daily_challenges(db, challenge_date)

    result = []
    for challenge in challenges:
        # Get or create user progress
        progress = db.query(models.UserTypingChallengeProgress).filter(
            models.UserTypingChallengeProgress.user_id == user_id,
            models.UserTypingChallengeProgress.challenge_id == challenge.id
        ).first()

        if not progress:
            progress = models.UserTypingChallengeProgress(
                id=str(uuid.uuid4()),
                user_id=user_id,
                challenge_id=challenge.id,
                current_value=0,
                is_completed=False,
                is_claimed=False
            )
            db.add(progress)
            db.commit()
            db.refresh(progress)

        config = CHALLENGE_TYPES.get(challenge.challenge_type, {})

        result.append({
            'challenge_id': challenge.id,
            'challenge_type': challenge.challenge_type,
            'name': config.get('name', challenge.challenge_type),
            'description': challenge.bonus_text,
            'difficulty': challenge.difficulty,
            'target_value': challenge.target_value,
            'current_value': progress.current_value,
            'progress_percent': min(100, (progress.current_value / challenge.target_value * 100)) if challenge.target_value > 0 else 0,
            'is_completed': progress.is_completed,
            'is_claimed': progress.is_claimed,
            'xp_reward': challenge.xp_reward,
            'completed_at': progress.completed_at.isoformat() if progress.completed_at else None
        })

    return result


def update_challenge_progress(
    db: Session,
    user_id: int,
    challenge_type: str,
    value: int,
    is_increment: bool = True
) -> List[Dict[str, Any]]:
    """
    Update progress for relevant daily challenges.

    Args:
        user_id: User ID
        challenge_type: Type of achievement ('games_completed', 'wpm_achieved', etc.)
        value: The value to update with
        is_increment: If True, add to current value. If False, set if higher (for max-type challenges)

    Returns:
        List of challenges that were completed by this update
    """
    today = datetime.utcnow().date()
    challenges = get_or_create_daily_challenges(db, today)

    completed_challenges = []

    for challenge in challenges:
        if challenge.challenge_type != challenge_type:
            continue

        # Get user progress
        progress = db.query(models.UserTypingChallengeProgress).filter(
            models.UserTypingChallengeProgress.user_id == user_id,
            models.UserTypingChallengeProgress.challenge_id == challenge.id
        ).first()

        if not progress:
            progress = models.UserTypingChallengeProgress(
                id=str(uuid.uuid4()),
                user_id=user_id,
                challenge_id=challenge.id,
                current_value=0,
                is_completed=False,
                is_claimed=False
            )
            db.add(progress)

        # Skip if already completed
        if progress.is_completed:
            continue

        # Update progress
        if is_increment:
            progress.current_value += value
        else:
            # For max-type challenges (like WPM achieved), only update if higher
            if value > progress.current_value:
                progress.current_value = value

        # Check if challenge is now completed
        if progress.current_value >= challenge.target_value:
            progress.is_completed = True
            progress.completed_at = datetime.utcnow()
            completed_challenges.append({
                'challenge_id': challenge.id,
                'challenge_type': challenge.challenge_type,
                'xp_reward': challenge.xp_reward,
                'difficulty': challenge.difficulty
            })

        db.commit()
        db.refresh(progress)

    return completed_challenges


def claim_challenge_reward(
    db: Session,
    user_id: int,
    challenge_id: str
) -> Dict[str, Any]:
    """Claim reward for a completed challenge"""
    progress = db.query(models.UserTypingChallengeProgress).filter(
        models.UserTypingChallengeProgress.user_id == user_id,
        models.UserTypingChallengeProgress.challenge_id == challenge_id
    ).first()

    if not progress:
        return {'success': False, 'message': 'Challenge progress not found'}

    if not progress.is_completed:
        return {'success': False, 'message': 'Challenge not yet completed'}

    if progress.is_claimed:
        return {'success': False, 'message': 'Reward already claimed'}

    # Get challenge to get XP reward
    challenge = db.query(models.TypingDailyChallenge).filter(
        models.TypingDailyChallenge.id == challenge_id
    ).first()

    if not challenge:
        return {'success': False, 'message': 'Challenge not found'}

    # Mark as claimed
    progress.is_claimed = True
    progress.claimed_at = datetime.utcnow()

    # Award XP
    xp_service.award_challenge_xp(
        db=db,
        user_id=user_id,
        xp_amount=challenge.xp_reward,
        challenge_type=challenge.challenge_type
    )

    db.commit()

    return {
        'success': True,
        'xp_awarded': challenge.xp_reward,
        'challenge_type': challenge.challenge_type,
        'difficulty': challenge.difficulty
    }


def process_game_completion_for_challenges(
    db: Session,
    user_id: int,
    wpm: int,
    accuracy: float,
    words_typed: int,
    max_combo: int = 0
) -> List[Dict[str, Any]]:
    """
    Process a completed game and update all relevant daily challenges.
    Call this after a game is completed.

    Returns:
        List of challenges that were completed
    """
    completed = []

    # Games completed (always increment by 1)
    completed.extend(update_challenge_progress(
        db, user_id, 'games_completed', 1, is_increment=True
    ))

    # WPM achieved (set if higher)
    completed.extend(update_challenge_progress(
        db, user_id, 'wpm_achieved', wpm, is_increment=False
    ))

    # Accuracy achieved (set if higher)
    completed.extend(update_challenge_progress(
        db, user_id, 'accuracy_achieved', int(accuracy), is_increment=False
    ))

    # Words typed (increment)
    completed.extend(update_challenge_progress(
        db, user_id, 'words_typed', words_typed, is_increment=True
    ))

    # Combo achieved (set if higher)
    if max_combo > 0:
        completed.extend(update_challenge_progress(
            db, user_id, 'combo_achieved', max_combo, is_increment=False
        ))

    return completed
