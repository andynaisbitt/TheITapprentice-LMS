# backend/app/plugins/quizzes/schemas.py
"""
Quiz System Pydantic Schemas
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Union
from datetime import datetime
from enum import Enum


class QuestionType(str, Enum):
    MULTIPLE_CHOICE = "multiple_choice"
    MULTIPLE_SELECT = "multiple_select"
    TRUE_FALSE = "true_false"
    SHORT_ANSWER = "short_answer"
    CODE = "code"
    FILL_BLANK = "fill_blank"


class QuizDifficulty(str, Enum):
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    EXPERT = "expert"


class QuizStatus(str, Enum):
    DRAFT = "draft"
    PUBLISHED = "published"
    ARCHIVED = "archived"


# ============== Question Schemas ==============

class QuestionOption(BaseModel):
    """Single option for multiple choice questions"""
    id: str
    text: str
    is_correct: bool = False


class QuestionCreate(BaseModel):
    """Schema for creating a quiz question"""
    question_type: QuestionType
    question_text: str
    question_html: Optional[str] = None
    options: List[QuestionOption] = []
    correct_answer: Any  # Type depends on question_type
    explanation: Optional[str] = None
    code_language: Optional[str] = None
    code_template: Optional[str] = None
    points: int = 1
    order_index: int = 0
    image_url: Optional[str] = None


class QuestionUpdate(BaseModel):
    """Schema for updating a quiz question"""
    question_type: Optional[QuestionType] = None
    question_text: Optional[str] = None
    question_html: Optional[str] = None
    options: Optional[List[QuestionOption]] = None
    correct_answer: Optional[Any] = None
    explanation: Optional[str] = None
    code_language: Optional[str] = None
    code_template: Optional[str] = None
    points: Optional[int] = None
    order_index: Optional[int] = None
    image_url: Optional[str] = None


class QuestionResponse(BaseModel):
    """Question response (without correct answer for quiz taking)"""
    id: int
    question_type: QuestionType
    question_text: str
    question_html: Optional[str] = None
    options: List[Dict[str, Any]] = []  # Without is_correct for quiz taking
    code_language: Optional[str] = None
    code_template: Optional[str] = None
    points: int
    order_index: int
    image_url: Optional[str] = None

    class Config:
        from_attributes = True


class QuestionResponseWithAnswer(QuestionResponse):
    """Question response with correct answer (for review)"""
    correct_answer: Any
    explanation: Optional[str] = None


# ============== Quiz Schemas ==============

class QuizCreate(BaseModel):
    """Schema for creating a quiz"""
    id: str = Field(..., min_length=3, max_length=100)
    title: str = Field(..., min_length=3, max_length=200)
    description: Optional[str] = None
    instructions: Optional[str] = None
    category: Optional[str] = None
    tags: List[str] = []
    difficulty: QuizDifficulty = QuizDifficulty.MEDIUM
    time_limit_minutes: Optional[int] = None
    passing_score: int = 70
    max_attempts: int = 0
    question_order: str = "sequential"
    show_answers_after: bool = True
    allow_review: bool = True
    xp_reward: int = 50
    xp_perfect: int = 100
    course_id: Optional[str] = None
    module_id: Optional[str] = None
    status: QuizStatus = QuizStatus.DRAFT
    is_featured: bool = False
    questions: List[QuestionCreate] = []


class QuizUpdate(BaseModel):
    """Schema for updating a quiz"""
    title: Optional[str] = None
    description: Optional[str] = None
    instructions: Optional[str] = None
    category: Optional[str] = None
    tags: Optional[List[str]] = None
    difficulty: Optional[QuizDifficulty] = None
    time_limit_minutes: Optional[int] = None
    passing_score: Optional[int] = None
    max_attempts: Optional[int] = None
    question_order: Optional[str] = None
    show_answers_after: Optional[bool] = None
    allow_review: Optional[bool] = None
    xp_reward: Optional[int] = None
    xp_perfect: Optional[int] = None
    course_id: Optional[str] = None
    module_id: Optional[str] = None
    status: Optional[QuizStatus] = None
    is_featured: Optional[bool] = None


class QuizSummary(BaseModel):
    """Quiz summary for listings"""
    id: str
    title: str
    description: Optional[str] = None
    category: Optional[str] = None
    difficulty: QuizDifficulty
    time_limit_minutes: Optional[int] = None
    passing_score: int
    question_count: int = 0
    xp_reward: int
    status: QuizStatus
    is_featured: bool
    total_attempts: int
    avg_score: float
    pass_rate: float
    created_at: datetime

    class Config:
        from_attributes = True


class QuizResponse(BaseModel):
    """Full quiz response (for quiz taking)"""
    id: str
    title: str
    description: Optional[str] = None
    instructions: Optional[str] = None
    category: Optional[str] = None
    tags: List[str] = []
    difficulty: QuizDifficulty
    time_limit_minutes: Optional[int] = None
    passing_score: int
    max_attempts: int
    question_order: str
    show_answers_after: bool
    allow_review: bool
    xp_reward: int
    xp_perfect: int
    question_count: int = 0
    questions: List[QuestionResponse] = []
    total_attempts: int
    avg_score: float
    created_at: datetime

    class Config:
        from_attributes = True


class QuizAdminResponse(QuizResponse):
    """Full quiz response for admin (includes correct answers)"""
    status: QuizStatus
    is_featured: bool
    course_id: Optional[str] = None
    module_id: Optional[str] = None
    created_by: Optional[int] = None
    pass_rate: float
    questions: List[QuestionResponseWithAnswer] = []
    updated_at: datetime
    published_at: Optional[datetime] = None


# ============== Attempt Schemas ==============

class QuizAttemptStart(BaseModel):
    """Start a quiz attempt"""
    quiz_id: str


class QuizAnswerSubmit(BaseModel):
    """Submit answer for a single question"""
    question_id: int
    answer: Any  # Type depends on question type


class QuizAttemptSubmit(BaseModel):
    """Submit all answers for a quiz attempt"""
    answers: Dict[str, Any]  # question_id -> answer


class QuestionResult(BaseModel):
    """Result for a single question"""
    question_id: int
    correct: bool
    points_earned: int
    user_answer: Any
    correct_answer: Optional[Any] = None  # Only if show_answers_after
    explanation: Optional[str] = None


class QuizAttemptResponse(BaseModel):
    """Quiz attempt response"""
    id: int
    quiz_id: str
    user_id: int
    attempt_number: int
    score: int
    max_score: int
    percentage: float
    passed: bool
    time_taken_seconds: Optional[int] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    is_complete: bool
    xp_awarded: int

    class Config:
        from_attributes = True


class QuizAttemptResult(QuizAttemptResponse):
    """Quiz attempt result with detailed question results"""
    question_results: List[QuestionResult] = []
    quiz_title: str
    show_answers: bool = True


class UserQuizStats(BaseModel):
    """User's quiz statistics"""
    total_attempts: int
    quizzes_passed: int
    quizzes_failed: int
    average_score: float
    best_score: float
    total_xp_earned: int
    recent_attempts: List[QuizAttemptResponse] = []


# ============== Leaderboard Schemas ==============

class QuizLeaderboardEntry(BaseModel):
    """Entry in quiz leaderboard"""
    rank: int
    user_id: int
    username: str
    display_name: Optional[str] = None
    best_score: float
    attempts: int
    best_time: Optional[int] = None  # seconds


class QuizLeaderboard(BaseModel):
    """Quiz leaderboard response"""
    quiz_id: str
    quiz_title: str
    entries: List[QuizLeaderboardEntry]
    total_participants: int
