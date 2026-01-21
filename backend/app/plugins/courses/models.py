# backend/app/plugins/courses/models.py
"""
Course System Models - WITH CONTENT BLOCK SYSTEM
Adapted from ITAppBetaV1 for BlogCMS plugin architecture
Supports flexible content creation via admin panel with 10 block types:
Text, Quiz, Video, Code, Images, Heading, Callout, Timeline, Interactive, Divider
"""
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, DateTime,
    ForeignKey, Enum as SQLEnum, JSON, Numeric
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base
import enum


class CourseLevel(str, enum.Enum):
    """Course difficulty levels - matches frontend and PostgreSQL enum"""
    # Use lowercase names to match PostgreSQL enum values
    beginner = "beginner"
    intermediate = "intermediate"
    advanced = "advanced"


class CourseStatus(str, enum.Enum):
    """Course publication status"""
    # Use lowercase names to match PostgreSQL enum values
    draft = "draft"
    published = "published"
    archived = "archived"


class SectionType(str, enum.Enum):
    """Types of learning sections - matches frontend and PostgreSQL"""
    # Use lowercase names to match PostgreSQL enum values
    theory = "theory"
    practice = "practice"
    quiz = "quiz"
    challenge = "challenge"
    video = "video"
    exercise = "exercise"


class SectionStatus(str, enum.Enum):
    """Section availability status - matches frontend and PostgreSQL"""
    # Use lowercase names to match PostgreSQL enum values
    locked = "locked"
    available = "available"
    in_progress = "in-progress"
    completed = "completed"


class ContentBlockType(str, enum.Enum):
    """Types of content blocks that can be added to sections"""
    TEXT = "text"                   # Rich text/markdown content
    HEADING = "heading"             # Section heading
    QUIZ = "quiz"                   # Quiz with multiple questions
    VIDEO = "video"                 # Embedded or uploaded video
    CODE = "code"                   # Code snippet with syntax highlighting
    IMAGE = "image"                 # Image with optional caption
    CALLOUT = "callout"             # Info/warning/tip box
    TIMELINE = "timeline"           # Timeline visualization
    INTERACTIVE = "interactive"     # Custom interactive component
    DIVIDER = "divider"             # Visual separator


class QuestionType(str, enum.Enum):
    """Types of quiz questions"""
    MULTIPLE_CHOICE = "multiple_choice"      # Single correct answer
    MULTIPLE_SELECT = "multiple_select"      # Multiple correct answers
    TRUE_FALSE = "true_false"                # True/False question
    SHORT_ANSWER = "short_answer"            # Text input
    CODE_CHALLENGE = "code_challenge"        # Code writing/completion
    FILL_BLANK = "fill_blank"                # Fill in the blank


class EnrollmentStatus(str, enum.Enum):
    """Student enrollment status"""
    ACTIVE = "active"
    COMPLETED = "completed"
    DROPPED = "dropped"


# ============================================================================
# CERTIFICATE MODEL
# ============================================================================

class Certificate(Base):
    """
    Course completion certificate - generated when a user completes a course
    """
    __tablename__ = "certificates"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    course_id = Column(String(100), ForeignKey("courses.id", ondelete="CASCADE"), nullable=False, index=True)
    enrollment_id = Column(Integer, ForeignKey("course_enrollments.id", ondelete="CASCADE"), nullable=False, index=True)

    # Certificate details
    title = Column(String(300), nullable=False)  # "Certificate of Completion: Python Fundamentals"
    description = Column(Text, nullable=True)  # "Successfully completed all modules..."
    verification_code = Column(String(50), unique=True, nullable=False, index=True)  # "CERT-ABC123XYZ"

    # Skills acquired from the course
    skills_acquired = Column(JSON, default=list)  # ["Python", "Git", "API Development"]

    # Recipient information (cached for certificate display)
    recipient_name = Column(String(200), nullable=True)  # User's name at time of completion
    instructor_name = Column(String(200), nullable=True)  # Instructor's name

    # Course info at time of completion (for historical accuracy)
    course_title = Column(String(200), nullable=False)
    course_level = Column(String(50), nullable=True)
    total_modules = Column(Integer, default=0)
    total_sections = Column(Integer, default=0)

    # Timestamps
    issued_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

    def __repr__(self):
        return f"<Certificate {self.verification_code}: {self.title}>"


# ============================================================================
# CORE MODELS
# ============================================================================

class Course(Base):
    """
    Main course model - matches frontend Course interface
    Example: "IT Basics for Beginners", "Python Development Course"
    """
    __tablename__ = "courses"

    id = Column(String(100), primary_key=True)  # e.g., "python-fundamentals"

    # Basic info
    title = Column(String(200), nullable=False, index=True)
    description = Column(Text, nullable=False)
    short_description = Column(String(500), nullable=True)

    # Media
    image = Column(String(500), nullable=True)  # thumbnail_url
    preview_video_url = Column(String(500), nullable=True)

    # Skills Integration - which skills get XP when course is completed
    related_skills = Column(JSON, default=lambda: ["problem-solving"])
    xp_reward = Column(Integer, nullable=True)  # Manual XP override (null = auto-calculate)

    # Categorization
    level = Column(SQLEnum(CourseLevel), nullable=False, index=True)
    category = Column(String(100), nullable=True, index=True)  # Optional category name
    skills = Column(JSON, default=list)  # ["Python", "Git", "Docker"]
    tags = Column(JSON, default=list)  # Additional tags

    # Course details
    duration = Column(String(50), nullable=True)  # "4 weeks", "6 weeks"
    estimated_hours = Column(Integer, default=0)
    requirements = Column(JSON, default=list)  # Prerequisites as strings
    objectives = Column(JSON, default=list)  # Learning objectives

    # Instructor
    instructor_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    instructor_name = Column(String(100), nullable=True)  # Cached for performance

    # Status & visibility
    status = Column(SQLEnum(CourseStatus), default=CourseStatus.draft, nullable=False, index=True)
    is_featured = Column(Boolean, default=False, index=True)
    is_premium = Column(Boolean, default=False, nullable=False)

    # Pricing
    price = Column(Numeric(10, 2), default=0.00)
    currency = Column(String(3), default="USD")

    # Stats
    enrollment_count = Column(Integer, default=0)
    completion_count = Column(Integer, default=0)
    difficulty_rating = Column(Integer, default=1)  # 1-5

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    published_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    modules = relationship("CourseModule", back_populates="course", cascade="all, delete-orphan", order_by="CourseModule.order_index")
    enrollments = relationship("CourseEnrollment", back_populates="course", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Course {self.id}: {self.title}>"


class CourseModule(Base):
    """
    Course module model - matches frontend CourseModule interface
    Example: "Python Fundamentals", "Web Development Basics"
    """
    __tablename__ = "course_modules"

    id = Column(String(100), primary_key=True)  # e.g., "python-fundamentals"
    course_id = Column(String(100), ForeignKey("courses.id", ondelete="CASCADE"), nullable=False, index=True)

    # Basic info
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    duration = Column(String(50), nullable=True)  # "1 week", "2 days"
    estimated_minutes = Column(Integer, default=0)

    # Ordering & prerequisites
    order_index = Column(Integer, nullable=False)  # Display order within course
    prerequisites = Column(JSON, default=list)  # List of module IDs that must be completed first

    # Component mapping (optional - for custom React components if needed)
    component = Column(String(200), nullable=True)  # Custom React component path

    # Difficulty
    difficulty_level = Column(Integer, default=1)  # 1-5

    # Status (for individual module availability)
    status = Column(SQLEnum(SectionStatus), default=SectionStatus.available, nullable=False)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    course = relationship("Course", back_populates="modules")
    sections = relationship("ModuleSection", back_populates="module", cascade="all, delete-orphan", order_by="ModuleSection.order_index")

    def __repr__(self):
        return f"<CourseModule {self.id}: {self.title}>"


class ModuleSection(Base):
    """
    Learning sections within a module - NOW WITH CONTENT BLOCKS!
    Sections are made up of flexible content blocks (text, quiz, video, etc.)
    Example: "Introduction to Python", "Variables and Data Types", "Quiz"
    """
    __tablename__ = "module_sections"

    id = Column(String(100), primary_key=True)  # e.g., "intro", "variables", "quiz"
    module_id = Column(String(100), ForeignKey("course_modules.id", ondelete="CASCADE"), nullable=False, index=True)

    # Basic info
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    time_estimate = Column(String(20), nullable=True)  # "5 min", "10 min"

    # Section type
    type = Column(SQLEnum(SectionType), default=SectionType.theory, nullable=False)

    # CONTENT BLOCKS - Array of content block objects
    # Each block has: { type, content, order }
    # Example:
    # [
    #   { "type": "heading", "content": { "text": "Introduction", "level": 2 }, "order": 0 },
    #   { "type": "text", "content": { "text": "Welcome to...", "markdown": true }, "order": 1 },
    #   { "type": "quiz", "content": { "questions": [...] }, "order": 2 }
    # ]
    content_blocks = Column(JSON, default=list, nullable=False)

    # Ordering
    order_index = Column(Integer, nullable=False)

    # Points for gamification
    points = Column(Integer, default=10)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    module = relationship("CourseModule", back_populates="sections")

    def __repr__(self):
        return f"<ModuleSection {self.id}: {self.title}>"


# ============================================================================
# ENROLLMENT & PROGRESS MODELS
# ============================================================================

class CourseEnrollment(Base):
    """
    Student enrollment in a course - tracks overall progress
    Matches frontend CourseProgress interface
    """
    __tablename__ = "course_enrollments"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    course_id = Column(String(100), ForeignKey("courses.id", ondelete="CASCADE"), nullable=False, index=True)

    # Progress tracking
    progress = Column(Integer, default=0)  # 0-100 percentage
    current_module_id = Column(String(100), nullable=True)  # Current module being studied
    completed_modules = Column(JSON, default=list)  # List of completed module IDs

    # Status
    status = Column(SQLEnum(EnrollmentStatus), default=EnrollmentStatus.ACTIVE, nullable=False, index=True)
    is_complete = Column(Boolean, default=False, index=True)

    # Bookmarks & notes
    bookmarks = Column(JSON, default=list)  # Bookmarked module IDs
    notes = Column(JSON, default=dict)  # module_id -> note text mapping

    # Stats
    time_spent = Column(Integer, default=0)  # Total minutes spent
    achievements = Column(JSON, default=list)  # List of achievement IDs earned

    # Timestamps
    enrolled_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    last_accessed = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    course = relationship("Course", back_populates="enrollments")
    module_progress = relationship("ModuleProgress", back_populates="enrollment", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<CourseEnrollment user={self.user_id} course={self.course_id} progress={self.progress}%>"


class ModuleProgress(Base):
    """
    Progress within a specific module - matches frontend ModuleProgress
    """
    __tablename__ = "module_progress"

    id = Column(Integer, primary_key=True, index=True)
    enrollment_id = Column(Integer, ForeignKey("course_enrollments.id", ondelete="CASCADE"), nullable=False, index=True)
    module_id = Column(String(100), nullable=False, index=True)

    # Completion
    completed = Column(Boolean, default=False, index=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Progress details
    time_spent = Column(Integer, default=0)  # Minutes
    last_position = Column(String(100), nullable=True)  # Last section ID
    completed_sections = Column(JSON, default=list)  # List of completed section IDs

    # Quiz scores (section_id -> score mapping)
    quiz_scores = Column(JSON, default=dict)
    attempts = Column(Integer, default=0)

    # Bookmarks & notes
    bookmarked = Column(Boolean, default=False)
    notes = Column(Text, nullable=True)

    # Timestamps
    started_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_accessed = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    enrollment = relationship("CourseEnrollment", back_populates="module_progress")

    def __repr__(self):
        return f"<ModuleProgress enrollment={self.enrollment_id} module={self.module_id} completed={self.completed}>"
