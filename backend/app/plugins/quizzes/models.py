# backend/app/plugins/quizzes/models.py
"""
Quiz System Models
Standalone quizzes with multiple question types, attempts tracking, and XP rewards.
"""
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, DateTime,
    ForeignKey, Enum as SQLEnum, JSON, Float
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base
import enum


class QuestionType(str, enum.Enum):
    """Types of quiz questions"""
    MULTIPLE_CHOICE = "multiple_choice"      # Single correct answer
    MULTIPLE_SELECT = "multiple_select"      # Multiple correct answers
    TRUE_FALSE = "true_false"                # True/False question
    SHORT_ANSWER = "short_answer"            # Text input
    CODE = "code"                            # Code writing/completion
    FILL_BLANK = "fill_blank"                # Fill in the blank


class QuizDifficulty(str, enum.Enum):
    """Quiz difficulty levels"""
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    EXPERT = "expert"


class QuizStatus(str, enum.Enum):
    """Quiz publication status"""
    DRAFT = "draft"
    PUBLISHED = "published"
    ARCHIVED = "archived"


class Quiz(Base):
    """
    Quiz definition - standalone quiz or course-integrated
    """
    __tablename__ = "quizzes"

    id = Column(String(100), primary_key=True)  # e.g., "python-basics-quiz"

    # Basic info
    title = Column(String(200), nullable=False, index=True)
    description = Column(Text, nullable=True)
    instructions = Column(Text, nullable=True)  # Pre-quiz instructions

    # Categorization
    category = Column(String(100), nullable=True, index=True)
    tags = Column(JSON, default=list)
    difficulty = Column(SQLEnum(QuizDifficulty), default=QuizDifficulty.MEDIUM, nullable=False)

    # Quiz settings
    time_limit_minutes = Column(Integer, nullable=True)  # Null = no time limit
    passing_score = Column(Integer, default=70)  # Percentage needed to pass
    max_attempts = Column(Integer, default=0)  # 0 = unlimited attempts
    question_order = Column(String(20), default="sequential")  # sequential, random
    show_answers_after = Column(Boolean, default=True)  # Show correct answers after completion
    allow_review = Column(Boolean, default=True)  # Allow reviewing answers

    # XP rewards
    xp_reward = Column(Integer, default=50)  # XP for passing
    xp_perfect = Column(Integer, default=100)  # XP for perfect score

    # Course integration (optional)
    course_id = Column(String(100), ForeignKey("courses.id", ondelete="SET NULL"), nullable=True, index=True)
    module_id = Column(String(100), nullable=True)  # Which module this quiz belongs to

    # Status
    status = Column(SQLEnum(QuizStatus), default=QuizStatus.DRAFT, nullable=False, index=True)
    is_featured = Column(Boolean, default=False)

    # Stats
    total_attempts = Column(Integer, default=0)
    avg_score = Column(Float, default=0.0)
    pass_rate = Column(Float, default=0.0)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    published_at = Column(DateTime(timezone=True), nullable=True)

    # Creator
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # Relationships
    questions = relationship("QuizQuestion", back_populates="quiz", cascade="all, delete-orphan", order_by="QuizQuestion.order_index")
    attempts = relationship("QuizAttempt", back_populates="quiz", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Quiz {self.id}: {self.title}>"


class QuizQuestion(Base):
    """
    Individual quiz question with multiple answer options
    """
    __tablename__ = "quiz_questions"

    id = Column(Integer, primary_key=True, index=True)
    quiz_id = Column(String(100), ForeignKey("quizzes.id", ondelete="CASCADE"), nullable=False, index=True)

    # Question content
    question_type = Column(SQLEnum(QuestionType), nullable=False)
    question_text = Column(Text, nullable=False)
    question_html = Column(Text, nullable=True)  # Optional HTML formatting

    # Answer options (for multiple choice, etc.)
    # Format: [{"id": "a", "text": "Option A", "is_correct": false}, ...]
    options = Column(JSON, default=list)

    # Correct answer(s)
    # For multiple_choice: "a"
    # For multiple_select: ["a", "c"]
    # For true_false: true/false
    # For short_answer: "expected text" or ["acceptable", "answers"]
    # For code: { "expected_output": "...", "test_cases": [...] }
    correct_answer = Column(JSON, nullable=False)

    # Explanation shown after answering
    explanation = Column(Text, nullable=True)

    # Code-specific fields
    code_language = Column(String(50), nullable=True)  # python, javascript, etc.
    code_template = Column(Text, nullable=True)  # Starting code for user

    # Points
    points = Column(Integer, default=1)

    # Ordering
    order_index = Column(Integer, default=0)

    # Media
    image_url = Column(String(500), nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    quiz = relationship("Quiz", back_populates="questions")

    def __repr__(self):
        return f"<QuizQuestion {self.id}: {self.question_text[:50]}>"


class QuizAttempt(Base):
    """
    User's attempt at a quiz - tracks answers and score
    """
    __tablename__ = "quiz_attempts"

    id = Column(Integer, primary_key=True, index=True)
    quiz_id = Column(String(100), ForeignKey("quizzes.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    # Attempt number for this user/quiz combination
    attempt_number = Column(Integer, default=1)

    # Scoring
    score = Column(Integer, default=0)  # Points earned
    max_score = Column(Integer, default=0)  # Total possible points
    percentage = Column(Float, default=0.0)  # Score percentage
    passed = Column(Boolean, default=False)

    # Answers submitted
    # Format: { "question_id": "user_answer", ... }
    answers = Column(JSON, default=dict)

    # Detailed results per question
    # Format: { "question_id": {"correct": true/false, "points_earned": 1}, ... }
    question_results = Column(JSON, default=dict)

    # Timing
    time_taken_seconds = Column(Integer, nullable=True)
    started_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Status
    is_complete = Column(Boolean, default=False, index=True)

    # XP awarded (only for first passing attempt)
    xp_awarded = Column(Integer, default=0)

    # Relationships
    quiz = relationship("Quiz", back_populates="attempts")

    def __repr__(self):
        return f"<QuizAttempt user={self.user_id} quiz={self.quiz_id} score={self.percentage}%>"
