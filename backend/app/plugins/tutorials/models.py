# backend/app/plugins/tutorials/models.py
"""
Tutorial database models for FastReactCMS LMS Edition
Interactive step-by-step learning guides with progress tracking
"""
from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, JSON, Text
from sqlalchemy.orm import relationship
from datetime import datetime

from app.core.database import Base


class TutorialCategory(Base):
    """Tutorial categories for organization"""
    __tablename__ = "tutorial_categories"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    icon = Column(String(50), nullable=True)  # Lucide icon name
    color = Column(String(7), nullable=True)  # Hex color (#3776ab)
    display_order = Column(Integer, default=0)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    tutorials = relationship("Tutorial", back_populates="category")


class Tutorial(Base):
    """Interactive tutorials with step-by-step content"""
    __tablename__ = "tutorials"

    id = Column(Integer, primary_key=True, index=True)

    # Basic info
    title = Column(String(255), nullable=False, index=True)
    slug = Column(String(255), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)

    # Content
    difficulty = Column(String(20), default="beginner")  # beginner, intermediate, advanced
    estimated_time_minutes = Column(Integer, nullable=True)

    # Organization
    category_id = Column(Integer, ForeignKey("tutorial_categories.id", ondelete="SET NULL"), nullable=True, index=True)

    # Media
    thumbnail_url = Column(String(500), nullable=True)

    # Author
    author_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    # Status
    is_published = Column(Boolean, default=False, index=True)
    is_featured = Column(Boolean, default=False)

    # Stats
    view_count = Column(Integer, default=0)
    completion_count = Column(Integer, default=0)

    # Gamification
    xp_reward = Column(Integer, default=50)
    related_skills = Column(JSON, default=list)  # ["Python", "Git", "Docker"]

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    published_at = Column(DateTime, nullable=True)

    # Relationships
    author = relationship("User", foreign_keys=[author_id])
    category = relationship("TutorialCategory", back_populates="tutorials")
    steps = relationship("TutorialStep", back_populates="tutorial", cascade="all, delete-orphan", order_by="TutorialStep.step_order")
    progress_records = relationship("TutorialProgress", back_populates="tutorial", cascade="all, delete-orphan")


class TutorialStep(Base):
    """
    Individual steps within a tutorial - ENHANCED WITH CONTENT BLOCKS

    Supports multiple content types beyond just code:
    - Text/markdown content
    - Code examples with syntax highlighting
    - Images with captions
    - Videos (embedded or uploaded)
    - Diagrams and terminal outputs
    - Inline quizzes for knowledge checks
    - Rich content blocks (like courses)
    """
    __tablename__ = "tutorial_steps"

    id = Column(Integer, primary_key=True, index=True)
    tutorial_id = Column(Integer, ForeignKey("tutorials.id", ondelete="CASCADE"), nullable=False, index=True)

    # Step info
    step_order = Column(Integer, nullable=False)
    title = Column(String(255), nullable=False)

    # Step type - what kind of learning activity is this?
    # theory: Reading/learning content
    # practice: Hands-on exercise
    # quiz: Knowledge check
    # demonstration: Watch and learn
    # exercise: Apply what you learned
    step_type = Column(String(20), default="theory")  # theory, practice, quiz, demonstration, exercise

    # Main content (markdown)
    content = Column(Text, nullable=True)

    # CONTENT BLOCKS - Flexible array of content blocks (like courses)
    # Each block: { "type": "text|heading|code|image|video|callout|quiz", "content": {...}, "order": 0 }
    # Example:
    # [
    #   { "type": "text", "content": { "text": "Welcome to..." }, "order": 0 },
    #   { "type": "code", "content": { "code": "print('Hello')", "language": "python" }, "order": 1 },
    #   { "type": "image", "content": { "url": "...", "caption": "..." }, "order": 2 }
    # ]
    content_blocks = Column(JSON, default=list)

    # Primary media for this step (legacy support + quick access)
    # none: No media, just text content
    # code: Code snippet
    # image: Image/diagram
    # video: Video content
    # diagram: Technical diagram
    # terminal: Terminal/CLI output
    media_type = Column(String(20), default="none")  # none, code, image, video, diagram, terminal
    media_content = Column(Text, nullable=True)  # URL, code, or embedded content
    media_language = Column(String(50), nullable=True)  # For code: python, javascript, etc.
    media_caption = Column(String(500), nullable=True)  # Alt text or caption

    # Code example (legacy - kept for backward compatibility)
    code_example = Column(Text, nullable=True)
    code_language = Column(String(50), nullable=True)

    # Enhanced hints - array of hint objects
    # [{ "content": "Try...", "type": "text|code|link", "reveal_after_attempts": 1 }]
    # Falls back to simple strings for backward compatibility
    hints = Column(JSON, default=list)

    # Optional inline quiz/knowledge check
    # { "question": "...", "type": "multiple_choice|true_false|short_answer",
    #   "options": [...], "correct_answer": ..., "explanation": "..." }
    quiz_question = Column(JSON, nullable=True)

    # What should the user do/accomplish in this step?
    expected_action = Column(Text, nullable=True)

    # Time estimate for this step
    estimated_minutes = Column(Integer, default=5)

    # XP reward for completing this step (0 = use default from config)
    xp_reward = Column(Integer, default=0)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    tutorial = relationship("Tutorial", back_populates="steps")


class TutorialProgress(Base):
    """Track user progress through tutorials"""
    __tablename__ = "tutorial_progress"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    tutorial_id = Column(Integer, ForeignKey("tutorials.id", ondelete="CASCADE"), nullable=False, index=True)

    # Progress tracking
    current_step_id = Column(Integer, ForeignKey("tutorial_steps.id", ondelete="SET NULL"), nullable=True)
    completed_step_ids = Column(JSON, default=list)  # List of completed step IDs

    # Status
    status = Column(String(20), default="in_progress")  # in_progress, completed

    # Stats
    time_spent_minutes = Column(Integer, default=0)

    # Completion
    completed_at = Column(DateTime, nullable=True)

    # Timestamps
    started_at = Column(DateTime, default=datetime.utcnow)
    last_accessed_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User")
    tutorial = relationship("Tutorial", back_populates="progress_records")

    # Unique constraint: one progress record per user per tutorial
    __table_args__ = (
        {'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4'},
    )
