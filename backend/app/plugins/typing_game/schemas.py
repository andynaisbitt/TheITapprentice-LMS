# backend/app/plugins/typing_game/schemas.py
"""
Typing Game Pydantic schemas for API validation
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class GameModeEnum(str, Enum):
    PRACTICE = "practice"
    CHALLENGE = "challenge"
    PVP = "pvp"


class DifficultyEnum(str, Enum):
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    EXPERT = "expert"


class MatchStatusEnum(str, Enum):
    WAITING = "WAITING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


# ==================== WORD LIST SCHEMAS ====================

class TypingWordListBase(BaseModel):
    name: str = Field(..., max_length=200)
    description: Optional[str] = None
    difficulty: str
    theme: str
    words: List[str]
    related_skills: List[str] = Field(default_factory=list)
    unlock_level: int = 1


class TypingWordListCreate(TypingWordListBase):
    id: str
    display_order: int = 0


class TypingWordListUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    words: Optional[List[str]] = None
    related_skills: Optional[List[str]] = None
    unlock_level: Optional[int] = None
    is_active: Optional[bool] = None
    display_order: Optional[int] = None


class TypingWordListResponse(TypingWordListBase):
    id: str
    is_active: bool
    is_featured: bool = False
    display_order: int
    times_played: int
    avg_wpm: float
    avg_accuracy: float
    created_at: datetime
    updated_at: datetime
    is_unlocked: bool = True
    user_best_wpm: Optional[int] = None
    user_times_played: int = 0

    class Config:
        from_attributes = True


class TypingWordListSummary(BaseModel):
    id: str
    name: str
    difficulty: str
    theme: str
    word_count: int
    unlock_level: int
    is_unlocked: bool
    is_featured: bool


# ==================== GAME SESSION SCHEMAS ====================

class TypingGameStartRequest(BaseModel):
    word_list_id: Optional[str] = None
    mode: str = "practice"
    word_count: int = Field(default=50, ge=10, le=200)


class TypingGameStartResponse(BaseModel):
    session_id: str
    text: str
    checksum: str
    word_list_name: Optional[str] = None
    difficulty: str
    word_count: int
    related_skills: List[str] = []


class TypingGameSubmitRequest(BaseModel):
    session_id: str
    user_input: str
    time_elapsed: int  # seconds
    checksum: str


class AntiCheatData(BaseModel):
    """Anti-cheat data collected during typing session"""
    keystroke_timings: List[float] = Field(default_factory=list, description="Inter-key intervals in ms")
    keystroke_count: int = Field(default=0, ge=0)
    paste_attempts: int = Field(default=0, ge=0)
    focus_lost_count: int = Field(default=0, ge=0)
    total_focus_lost_time: float = Field(default=0.0, ge=0)
    avg_inter_key_time: float = Field(default=0.0, ge=0)
    std_dev_inter_key_time: float = Field(default=0.0, ge=0)
    first_segment_avg: Optional[float] = Field(default=None, ge=0)
    last_segment_avg: Optional[float] = Field(default=None, ge=0)


class TypingGameSubmitRequestV2(BaseModel):
    """Enhanced submission request with anti-cheat data"""
    session_id: str
    user_input: str
    time_elapsed: int = Field(..., ge=0, description="Time elapsed in seconds")
    checksum: str
    max_combo: int = Field(default=0, ge=0, description="Maximum combo achieved")
    anti_cheat: Optional[AntiCheatData] = Field(default=None, description="Anti-cheat telemetry data")


class TypingPerformanceMetrics(BaseModel):
    wpm: int
    raw_wpm: int
    accuracy: float
    error_count: int
    total_characters: int
    time_elapsed: int


class AntiCheatResultResponse(BaseModel):
    """Anti-cheat validation result"""
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    flags: List[str] = Field(default_factory=list)
    is_valid: bool = True


class ChallengeCompletedResponse(BaseModel):
    """A challenge completed during the game"""
    challenge_id: str
    challenge_type: str
    xp_reward: int
    difficulty: str = "medium"

class StreakResultResponse(BaseModel):
    """Streak info returned after game completion"""
    current_streak: int = 0
    streak_extended: bool = False
    streak_bonus_xp: int = 0

class TypingGameResultsResponse(BaseModel):
    session_id: str
    metrics: TypingPerformanceMetrics
    xp_earned: int
    is_personal_best_wpm: bool
    is_personal_best_accuracy: bool
    rank_change: Optional[int] = None
    max_combo: int = 0
    anti_cheat: Optional[AntiCheatResultResponse] = None
    challenges_completed: Optional[List[ChallengeCompletedResponse]] = None
    streak: Optional[StreakResultResponse] = None


class TypingGameSessionResponse(BaseModel):
    id: str
    user_id: int
    word_list_id: Optional[str]
    mode: str
    wpm: Optional[int]
    accuracy: Optional[float]
    mistakes: int
    time_taken: Optional[float]
    is_completed: bool
    started_at: datetime
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True


# ==================== USER STATS SCHEMAS ====================

class UserTypingStatsResponse(BaseModel):
    user_id: int
    best_wpm: int
    best_accuracy: float
    avg_wpm: float
    avg_accuracy: float
    total_games_played: int
    total_games_completed: int
    total_words_typed: int
    total_time_seconds: int
    current_streak_days: int
    longest_streak_days: int
    first_game_at: Optional[datetime]
    last_game_at: Optional[datetime]

    class Config:
        from_attributes = True


class TypingGameHistoryEntry(BaseModel):
    session_id: str
    word_list_name: Optional[str]
    difficulty: str
    wpm: int
    accuracy: float
    time_elapsed: int
    xp_earned: int
    completed_at: datetime


class TypingGameHistoryResponse(BaseModel):
    games: List[TypingGameHistoryEntry]
    total_games: int
    page: int
    page_size: int


# ==================== PVP SCHEMAS ====================

class PVPFindMatchRequest(BaseModel):
    difficulty: str = "medium"


class PVPMatchResponse(BaseModel):
    id: str
    player1_id: int
    player2_id: Optional[int]
    status: str
    difficulty: str
    content: Optional[str]
    word_count: int
    total_rounds: int
    current_round: int
    created_at: datetime
    started_at: Optional[datetime]

    class Config:
        from_attributes = True


class PVPMatchDetailResponse(PVPMatchResponse):
    player1_wpm: int
    player2_wpm: int
    player1_accuracy: float
    player2_accuracy: float
    player1_score: int
    player2_score: int
    winner_id: Optional[int]
    round_results: Optional[List[Dict[str, Any]]]
    completed_at: Optional[datetime]


class PVPRoundSubmitRequest(BaseModel):
    match_id: str
    wpm: float = Field(..., ge=0, le=300)
    accuracy: float = Field(..., ge=0, le=100)
    time_elapsed: int = Field(..., ge=0)
    words_typed: int = Field(..., ge=0)


class PVPRoundResultResponse(BaseModel):
    round_number: int
    winner: str  # "player", "opponent", "tie", "pending"
    player_wpm: float
    opponent_wpm: float
    player_accuracy: float
    opponent_accuracy: float
    match_status: str
    current_score: Dict[str, int]
    xp_earned: Optional[int] = None
    # Next round content (only present if there's another round)
    next_round_content: Optional[str] = None
    next_round_word_count: Optional[int] = None


class UserPVPStatsResponse(BaseModel):
    user_id: int
    current_rating: int
    peak_rating: int
    rating_tier: str
    total_matches: int
    wins: int
    losses: int
    ties: int
    win_rate: float
    best_wpm: int
    avg_wpm: float
    best_accuracy: float
    avg_accuracy: float
    current_win_streak: int
    longest_win_streak: int
    last_match_at: Optional[datetime]

    class Config:
        from_attributes = True


# ==================== LEADERBOARD SCHEMAS ====================

class LeaderboardEntryResponse(BaseModel):
    rank: int
    user_id: int
    username: str
    display_name: Optional[str]
    best_wpm: float
    avg_wpm: float
    avg_accuracy: float
    games_played: int


class LeaderboardResponse(BaseModel):
    leaderboard_type: str
    period: Optional[str]
    entries: List[LeaderboardEntryResponse]
    user_rank: Optional[int] = None
    total_entries: int


# ==================== CHALLENGE SCHEMAS ====================

class TypingChallengeResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    category: str
    difficulty: str
    text_content: str
    expected_wpm: int
    time_limit: int
    tags: List[str] = []
    related_skills: List[str] = []
    is_active: bool
    times_played: int

    class Config:
        from_attributes = True


class TypingChallengeCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    category: str
    difficulty: str
    text_content: str = Field(..., min_length=10)
    expected_wpm: int = Field(default=40, ge=10, le=200)
    time_limit: int = Field(default=60, ge=0, le=600)
    tags: List[str] = Field(default_factory=list)
    related_skills: List[str] = Field(default_factory=list)
    is_active: bool = True
    round_order: int = Field(default=1, ge=1, le=10)


class TypingChallengeUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    difficulty: Optional[str] = None
    text_content: Optional[str] = None
    expected_wpm: Optional[int] = None
    time_limit: Optional[int] = None
    tags: Optional[List[str]] = None
    related_skills: Optional[List[str]] = None
    is_active: Optional[bool] = None
    round_order: Optional[int] = None


# ==================== SENTENCE POOL SCHEMAS ====================

class SentencePoolBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    difficulty: str = Field(..., pattern="^(easy|medium|hard|expert)$")
    category: str = Field(..., min_length=1, max_length=50)
    sentences: List[str] = Field(..., min_length=1)


class SentencePoolCreate(SentencePoolBase):
    min_length: int = Field(default=20, ge=5, le=500)
    max_length: int = Field(default=200, ge=20, le=1000)
    is_active: bool = True
    is_featured: bool = False
    display_order: int = 0
    round_suitable: List[int] = Field(default_factory=lambda: [1, 2, 3])
    difficulty_weight: float = Field(default=1.0, ge=0.1, le=10.0)


class SentencePoolUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = None
    difficulty: Optional[str] = Field(None, pattern="^(easy|medium|hard|expert)$")
    category: Optional[str] = Field(None, min_length=1, max_length=50)
    sentences: Optional[List[str]] = None
    min_length: Optional[int] = Field(None, ge=5, le=500)
    max_length: Optional[int] = Field(None, ge=20, le=1000)
    is_active: Optional[bool] = None
    is_featured: Optional[bool] = None
    display_order: Optional[int] = None
    round_suitable: Optional[List[int]] = None
    difficulty_weight: Optional[float] = Field(None, ge=0.1, le=10.0)


class SentencePoolResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    difficulty: str
    category: str
    sentences: List[str]
    min_length: int
    max_length: int
    avg_word_count: float
    is_active: bool
    is_featured: bool
    display_order: int
    round_suitable: List[int]
    difficulty_weight: float
    times_used: int
    avg_wpm: float
    avg_accuracy: float
    created_at: datetime
    updated_at: datetime
    sentence_count: int = 0

    class Config:
        from_attributes = True

    @classmethod
    def from_orm_with_count(cls, obj):
        """Create response with calculated sentence count"""
        data = {
            "id": obj.id,
            "name": obj.name,
            "description": obj.description,
            "difficulty": obj.difficulty,
            "category": obj.category,
            "sentences": obj.sentences or [],
            "min_length": obj.min_length,
            "max_length": obj.max_length,
            "avg_word_count": obj.avg_word_count,
            "is_active": obj.is_active,
            "is_featured": obj.is_featured,
            "display_order": obj.display_order,
            "round_suitable": obj.round_suitable or [1, 2, 3],
            "difficulty_weight": obj.difficulty_weight,
            "times_used": obj.times_used,
            "avg_wpm": obj.avg_wpm,
            "avg_accuracy": obj.avg_accuracy,
            "created_at": obj.created_at,
            "updated_at": obj.updated_at,
            "sentence_count": len(obj.sentences) if obj.sentences else 0
        }
        return cls(**data)


class SentencePoolSummary(BaseModel):
    id: str
    name: str
    difficulty: str
    category: str
    sentence_count: int
    is_active: bool
    is_featured: bool


class SentencePoolListResponse(BaseModel):
    pools: List[SentencePoolResponse]
    total: int
    page: int
    page_size: int


# ==================== ADMIN SCHEMAS ====================

class TypingGameAnalyticsResponse(BaseModel):
    total_games_played: int
    total_players: int
    average_wpm: float
    average_accuracy: float
    games_last_7_days: int
    top_word_lists: List[Dict[str, Any]]
    pvp_matches_today: int
    active_players_today: int
