# backend/app/plugins/typing_game/models.py
"""
Typing Game database models
Solo typing practice and PVP battles with leaderboards
"""
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, ForeignKey, JSON, Text, Enum as SQLEnum
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

from app.core.database import Base


class GameStatus(str, enum.Enum):
    """Game session status"""
    WAITING = "waiting"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    ABANDONED = "abandoned"


class GameMode(str, enum.Enum):
    """Game modes"""
    PRACTICE = "practice"
    CHALLENGE = "challenge"
    PVP = "pvp"


class GameDifficulty(str, enum.Enum):
    """Text difficulty levels"""
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    EXPERT = "expert"


class MatchStatus(str, enum.Enum):
    """PVP match status"""
    WAITING = "WAITING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


# ==================== TYPING WORD LISTS ====================

class TypingWordList(Base):
    """
    Predefined word lists for typing game
    IT-themed content with difficulty tiers
    """
    __tablename__ = "typing_word_lists"

    id = Column(String(100), primary_key=True)  # "it-basics", "python-code", etc.
    name = Column(String(200), nullable=False)
    description = Column(Text)

    # Difficulty & Theme
    difficulty = Column(String(20), nullable=False, index=True)  # easy, medium, hard, expert
    theme = Column(String(50), nullable=False, index=True)  # general, commands, code, security

    # Content (JSON array of words/phrases)
    words = Column(JSON, nullable=False)  # ["computer", "network", "server", ...]

    # Skills this word list trains
    related_skills = Column(JSON, default=list)  # ["networking", "programming"]

    # Unlock requirements
    unlock_level = Column(Integer, default=1)

    # Meta
    is_active = Column(Boolean, default=True, nullable=False)
    is_featured = Column(Boolean, default=False, nullable=False)
    display_order = Column(Integer, default=0)
    times_played = Column(Integer, default=0)
    avg_wpm = Column(Float, default=0.0)
    avg_accuracy = Column(Float, default=0.0)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<TypingWordList {self.id}: {self.name}>"


# ==================== TYPING GAME SESSIONS ====================

class TypingGameSession(Base):
    """
    Individual typing game sessions
    Tracks performance and awards XP
    """
    __tablename__ = "typing_game_sessions"

    id = Column(String(36), primary_key=True)  # UUID
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    word_list_id = Column(String(100), ForeignKey("typing_word_lists.id"), nullable=True)

    # Session config
    mode = Column(String(20), nullable=False)  # practice, challenge, pvp
    duration = Column(Integer, default=60)  # seconds

    # Generated content
    text_content = Column(Text, nullable=False)
    text_checksum = Column(String(64))  # SHA256 for anti-cheat
    word_count = Column(Integer, default=0)

    # Results
    wpm = Column(Integer, nullable=True)
    raw_wpm = Column(Integer, nullable=True)
    accuracy = Column(Float, nullable=True)  # 0.0 - 100.0
    mistakes = Column(Integer, default=0)
    time_taken = Column(Float, nullable=True)
    characters_typed = Column(Integer, default=0)
    user_input = Column(Text, nullable=True)

    # XP awarded
    total_xp_earned = Column(Integer, default=0)

    # Personal best tracking
    is_personal_best_wpm = Column(Boolean, default=False)
    is_personal_best_accuracy = Column(Boolean, default=False)

    # Status
    status = Column(String(20), default="in_progress")
    is_completed = Column(Boolean, default=False)

    # Timestamps
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    word_list = relationship("TypingWordList")

    def __repr__(self):
        return f"<TypingGameSession {self.id}: user={self.user_id} wpm={self.wpm}>"


# ==================== USER TYPING STATS ====================

class UserTypingStats(Base):
    """
    Aggregate typing statistics per user
    Personal bests, averages, totals
    """
    __tablename__ = "user_typing_stats"

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)

    # Personal Bests
    best_wpm = Column(Integer, default=0)
    best_wpm_word_list = Column(String(100), nullable=True)
    best_wpm_achieved_at = Column(DateTime, nullable=True)
    best_accuracy = Column(Float, default=0.0)
    best_accuracy_achieved_at = Column(DateTime, nullable=True)

    # Totals
    total_games_played = Column(Integer, default=0)
    total_games_completed = Column(Integer, default=0)
    total_words_typed = Column(Integer, default=0)
    total_characters_typed = Column(Integer, default=0)
    total_time_seconds = Column(Integer, default=0)

    # Averages
    avg_wpm = Column(Float, default=0.0)
    avg_accuracy = Column(Float, default=0.0)

    # Milestones
    reached_50_wpm_at = Column(DateTime, nullable=True)
    reached_100_wpm_at = Column(DateTime, nullable=True)
    reached_150_wpm_at = Column(DateTime, nullable=True)

    # Activity
    first_game_at = Column(DateTime, nullable=True)
    last_game_at = Column(DateTime, nullable=True)
    current_streak_days = Column(Integer, default=0)
    longest_streak_days = Column(Integer, default=0)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<UserTypingStats user={self.user_id} best_wpm={self.best_wpm}>"


# ==================== PVP MATCHES ====================

class PVPMatch(Base):
    """
    PVP typing match between two players
    Real-time competitive typing battles
    """
    __tablename__ = "typing_pvp_matches"

    id = Column(String(36), primary_key=True)  # UUID

    # Players
    player1_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    player2_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)

    # Match status
    status = Column(SQLEnum(MatchStatus, name='typing_match_status'), default=MatchStatus.WAITING, nullable=False)

    # Scores
    player1_score = Column(Integer, default=0)
    player2_score = Column(Integer, default=0)
    player1_wpm = Column(Integer, default=0)
    player2_wpm = Column(Integer, default=0)
    player1_accuracy = Column(Float, default=0.0)
    player2_accuracy = Column(Float, default=0.0)

    # Winner
    winner_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Game content
    content = Column(Text, nullable=True)
    checksum = Column(String(64), nullable=True)
    difficulty = Column(String(20), default="medium")
    word_count = Column(Integer, default=50)

    # Round-based gameplay
    total_rounds = Column(Integer, default=3)
    current_round = Column(Integer, default=1)
    round_results = Column(JSON, nullable=True)

    # Matchmaking
    skill_bracket = Column(String(20), nullable=True)
    player1_rating = Column(Integer, default=1000)
    player2_rating = Column(Integer, default=1000)
    rating_change = Column(Integer, default=0)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    player1 = relationship("User", foreign_keys=[player1_id])
    player2 = relationship("User", foreign_keys=[player2_id])
    winner = relationship("User", foreign_keys=[winner_id])

    def __repr__(self):
        return f"<PVPMatch {self.id}: {self.player1_id} vs {self.player2_id} - {self.status.value}>"


# ==================== USER PVP STATS ====================

class UserPVPStats(Base):
    """
    User statistics for PVP battles
    ELO ratings, win/loss records, streaks
    """
    __tablename__ = "user_pvp_stats"

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)

    # ELO Rating
    current_rating = Column(Integer, default=1500)
    peak_rating = Column(Integer, default=1500)
    lowest_rating = Column(Integer, default=1500)
    rating_tier = Column(String(20), default="Intermediate")

    # Match Statistics
    total_matches = Column(Integer, default=0)
    wins = Column(Integer, default=0)
    losses = Column(Integer, default=0)
    ties = Column(Integer, default=0)
    win_rate = Column(Float, default=0.0)

    # Performance Stats
    best_wpm = Column(Integer, default=0)
    avg_wpm = Column(Float, default=0.0)
    best_accuracy = Column(Float, default=0.0)
    avg_accuracy = Column(Float, default=0.0)

    # Streaks
    current_win_streak = Column(Integer, default=0)
    longest_win_streak = Column(Integer, default=0)
    current_loss_streak = Column(Integer, default=0)

    # Activity
    last_match_at = Column(DateTime, nullable=True)
    first_match_at = Column(DateTime, nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User")

    def __repr__(self):
        return f"<UserPVPStats user={self.user_id} rating={self.current_rating}>"


# ==================== TYPING CHALLENGES ====================

class TypingChallenge(Base):
    """
    Typing challenge templates for PVP rounds
    Admin-configurable challenges with progressive difficulty
    """
    __tablename__ = "typing_challenges"

    id = Column(String(36), primary_key=True)

    # Challenge info
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(50), nullable=False)  # BASICS, WEB, PROGRAMMING, etc.
    difficulty = Column(String(20), nullable=False)  # BEGINNER, INTERMEDIATE, etc.

    # Content
    text_content = Column(Text, nullable=False)
    expected_wpm = Column(Integer, default=40)
    time_limit = Column(Integer, default=60)  # seconds

    # Metadata
    tags = Column(JSON, nullable=True)
    related_skills = Column(JSON, nullable=True)

    # Admin controls
    is_active = Column(Boolean, default=True)
    round_order = Column(Integer, default=1)

    # Stats
    times_played = Column(Integer, default=0)
    average_completion_time = Column(Integer, default=0)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<TypingChallenge {self.name} ({self.category})>"


# ==================== LEADERBOARD ====================

class TypingLeaderboard(Base):
    """
    Leaderboard entries for typing game
    """
    __tablename__ = "typing_leaderboard"

    id = Column(String(36), primary_key=True)

    # Leaderboard type
    leaderboard_type = Column(String(50), nullable=False)  # daily, weekly, monthly, all_time
    period = Column(String(50), nullable=True)  # "2024-01", "2024-W01", etc.

    # User info
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    # Stats for this period
    games_played = Column(Integer, default=0)
    best_wpm = Column(Float, default=0.0)
    avg_wpm = Column(Float, default=0.0)
    avg_accuracy = Column(Float, default=0.0)

    # Ranking
    rank = Column(Integer, nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User")
