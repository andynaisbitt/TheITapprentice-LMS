# backend/app/plugins/courses/schemas.py
"""
Course API Schemas - WITH CONTENT BLOCK SYSTEM
Validates content blocks for rich course content creation
Adapted from ITAppBetaV1 for BlogCMS plugin architecture
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Union
from datetime import datetime
from enum import Enum


# ============================================================================
# ENUMS - Match Frontend & Database
# ============================================================================

class CourseLevelEnum(str, Enum):
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"


class CourseStatusEnum(str, Enum):
    DRAFT = "draft"
    PUBLISHED = "published"
    ARCHIVED = "archived"


class SectionTypeEnum(str, Enum):
    THEORY = "theory"
    PRACTICE = "practice"
    QUIZ = "quiz"
    CHALLENGE = "challenge"
    VIDEO = "video"
    EXERCISE = "exercise"


class SectionStatusEnum(str, Enum):
    LOCKED = "locked"
    AVAILABLE = "available"
    IN_PROGRESS = "in-progress"
    COMPLETED = "completed"


class ContentBlockTypeEnum(str, Enum):
    """Content block types"""
    TEXT = "text"
    HEADING = "heading"
    QUIZ = "quiz"
    VIDEO = "video"
    CODE = "code"
    IMAGE = "image"
    CALLOUT = "callout"
    TIMELINE = "timeline"
    INTERACTIVE = "interactive"
    DIVIDER = "divider"


class QuestionTypeEnum(str, Enum):
    """Quiz question types"""
    MULTIPLE_CHOICE = "multiple_choice"
    MULTIPLE_SELECT = "multiple_select"
    TRUE_FALSE = "true_false"
    SHORT_ANSWER = "short_answer"
    CODE_CHALLENGE = "code_challenge"
    FILL_BLANK = "fill_blank"


# ============================================================================
# CONTENT BLOCK SCHEMAS
# ============================================================================

class TextBlockContent(BaseModel):
    """Text block content"""
    text: str
    markdown: bool = True


class HeadingBlockContent(BaseModel):
    """Heading block content"""
    text: str
    level: int = Field(default=2, ge=1, le=6)  # h1-h6


class QuizQuestion(BaseModel):
    """Single quiz question"""
    id: str
    type: QuestionTypeEnum
    question: str
    options: Optional[List[str]] = None  # For multiple choice/select
    correct_answer: Any = None  # int (index), bool, str, or List[int]
    explanation: Optional[str] = None
    points: int = 1
    code_template: Optional[str] = None  # For code challenges
    test_cases: Optional[List[Dict[str, Any]]] = None  # For code challenges


class QuizBlockContent(BaseModel):
    """Quiz block content"""
    title: Optional[str] = None
    questions: List[QuizQuestion]
    passing_score: int = Field(default=70, ge=0, le=100)
    allow_retakes: bool = True
    shuffle_questions: bool = False
    shuffle_options: bool = False


class VideoBlockContent(BaseModel):
    """Video block content"""
    url: str
    title: Optional[str] = None
    duration: Optional[str] = None  # "10:30"
    provider: str = "youtube"  # youtube, vimeo, uploaded
    thumbnail: Optional[str] = None


class CodeBlockContent(BaseModel):
    """Code block content"""
    code: str
    language: str = "python"
    title: Optional[str] = None
    runnable: bool = False
    show_line_numbers: bool = True
    highlight_lines: Optional[List[int]] = None


class ImageBlockContent(BaseModel):
    """Image block content"""
    url: str
    alt: str
    caption: Optional[str] = None
    width: str = "full"  # full, medium, small


class CalloutBlockContent(BaseModel):
    """Callout block content"""
    text: str
    style: str = "info"  # info, warning, danger, success, tip
    title: Optional[str] = None


class TimelineItem(BaseModel):
    """Timeline item"""
    year: str
    event: str
    description: Optional[str] = None


class TimelineBlockContent(BaseModel):
    """Timeline block content"""
    items: List[TimelineItem]


class InteractiveBlockContent(BaseModel):
    """Interactive block content (custom React component)"""
    component: str  # Component name
    props: Dict[str, Any] = {}


class DividerBlockContent(BaseModel):
    """Divider block content"""
    style: str = "solid"  # solid, dashed, thick


# ============================================================================
# CONTENT BLOCK UNION SCHEMAS (for API validation)
# ============================================================================

class ContentBlockBase(BaseModel):
    """Base content block"""
    type: ContentBlockTypeEnum
    order: int
    content: Dict[str, Any]


class TextBlock(BaseModel):
    """Text content block"""
    type: ContentBlockTypeEnum = ContentBlockTypeEnum.TEXT
    order: int
    content: TextBlockContent


class HeadingBlock(BaseModel):
    """Heading content block"""
    type: ContentBlockTypeEnum = ContentBlockTypeEnum.HEADING
    order: int
    content: HeadingBlockContent


class QuizBlock(BaseModel):
    """Quiz content block"""
    type: ContentBlockTypeEnum = ContentBlockTypeEnum.QUIZ
    order: int
    content: QuizBlockContent


class VideoBlock(BaseModel):
    """Video content block"""
    type: ContentBlockTypeEnum = ContentBlockTypeEnum.VIDEO
    order: int
    content: VideoBlockContent


class CodeBlock(BaseModel):
    """Code content block"""
    type: ContentBlockTypeEnum = ContentBlockTypeEnum.CODE
    order: int
    content: CodeBlockContent


class ImageBlock(BaseModel):
    """Image content block"""
    type: ContentBlockTypeEnum = ContentBlockTypeEnum.IMAGE
    order: int
    content: ImageBlockContent


class CalloutBlock(BaseModel):
    """Callout content block"""
    type: ContentBlockTypeEnum = ContentBlockTypeEnum.CALLOUT
    order: int
    content: CalloutBlockContent


class TimelineBlock(BaseModel):
    """Timeline content block"""
    type: ContentBlockTypeEnum = ContentBlockTypeEnum.TIMELINE
    order: int
    content: TimelineBlockContent


class InteractiveBlock(BaseModel):
    """Interactive content block"""
    type: ContentBlockTypeEnum = ContentBlockTypeEnum.INTERACTIVE
    order: int
    content: InteractiveBlockContent


class DividerBlock(BaseModel):
    """Divider content block"""
    type: ContentBlockTypeEnum = ContentBlockTypeEnum.DIVIDER
    order: int
    content: DividerBlockContent


# Union type for any content block
ContentBlock = Union[
    TextBlock, HeadingBlock, QuizBlock, VideoBlock, CodeBlock,
    ImageBlock, CalloutBlock, TimelineBlock, InteractiveBlock, DividerBlock
]


# ============================================================================
# SECTION SCHEMAS (UPDATED WITH CONTENT BLOCKS)
# ============================================================================

class ModuleSectionBase(BaseModel):
    """Base schema for module sections"""
    id: str
    title: str
    description: Optional[str] = None
    time_estimate: Optional[str] = None  # "5 min"
    type: SectionTypeEnum
    content_blocks: List[Dict[str, Any]] = []  # Array of content blocks
    order_index: int
    points: int = 10


class ModuleSectionCreate(BaseModel):
    """Create new section with content blocks"""
    id: str
    title: str
    description: Optional[str] = None
    time_estimate: Optional[str] = None
    type: SectionTypeEnum = SectionTypeEnum.THEORY
    content_blocks: List[Dict[str, Any]] = []
    order_index: int
    points: int = 10


class ModuleSectionUpdate(BaseModel):
    """Update section"""
    title: Optional[str] = None
    description: Optional[str] = None
    time_estimate: Optional[str] = None
    type: Optional[SectionTypeEnum] = None
    content_blocks: Optional[List[Dict[str, Any]]] = None
    order_index: Optional[int] = None
    points: Optional[int] = None


class ModuleSectionResponse(ModuleSectionBase):
    """Section response with timestamps"""
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# MODULE SCHEMAS
# ============================================================================

class CourseModuleBase(BaseModel):
    """Base schema for course modules"""
    id: str  # "python-fundamentals"
    title: str
    description: Optional[str] = None
    duration: Optional[str] = None  # "1 week"
    estimated_minutes: int = 0
    component: Optional[str] = None  # Optional custom component
    order_index: int
    prerequisites: List[str] = []
    difficulty_level: int = 1


class CourseModuleCreate(BaseModel):
    """Create new module"""
    id: str
    title: str
    description: Optional[str] = None
    duration: Optional[str] = None
    estimated_minutes: int = 0
    component: Optional[str] = None
    order_index: int
    prerequisites: List[str] = []
    difficulty_level: int = 1


class CourseModuleUpdate(BaseModel):
    """Update module"""
    title: Optional[str] = None
    description: Optional[str] = None
    duration: Optional[str] = None
    estimated_minutes: Optional[int] = None
    component: Optional[str] = None
    order_index: Optional[int] = None
    prerequisites: Optional[List[str]] = None
    difficulty_level: Optional[int] = None


class CourseModuleResponse(CourseModuleBase):
    """Module response with sections"""
    status: SectionStatusEnum
    sections: List[ModuleSectionResponse] = []
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# COURSE SCHEMAS
# ============================================================================

class CourseBase(BaseModel):
    """Base schema for courses"""
    id: str  # "python-fundamentals"
    title: str
    description: str
    short_description: Optional[str] = None
    image: Optional[str] = None
    level: CourseLevelEnum
    duration: Optional[str] = None  # "4 weeks"
    skills: List[str] = []
    category: Optional[str] = None
    tags: List[str] = []
    requirements: List[str] = []
    objectives: List[str] = []
    is_premium: bool = False
    price: float = 0.00
    related_skills: List[str] = Field(default=["problem-solving"])
    xp_reward: Optional[int] = None  # Manual XP override (null = auto-calculate)


class CourseCreate(BaseModel):
    """Create new course"""
    id: str
    title: str
    description: str
    short_description: Optional[str] = None
    image: Optional[str] = None
    level: CourseLevelEnum
    duration: Optional[str] = None
    skills: List[str] = []
    category: Optional[str] = None
    tags: List[str] = []
    requirements: List[str] = []
    objectives: List[str] = []
    instructor_id: int
    is_premium: bool = False
    price: float = 0.00
    related_skills: List[str] = Field(default=["problem-solving"])
    xp_reward: Optional[int] = None


class CourseUpdate(BaseModel):
    """Update course"""
    title: Optional[str] = None
    description: Optional[str] = None
    short_description: Optional[str] = None
    image: Optional[str] = None
    level: Optional[CourseLevelEnum] = None
    duration: Optional[str] = None
    skills: Optional[List[str]] = None
    category: Optional[str] = None
    tags: Optional[List[str]] = None
    requirements: Optional[List[str]] = None
    objectives: Optional[List[str]] = None
    is_premium: Optional[bool] = None
    price: Optional[float] = None
    related_skills: Optional[List[str]] = None
    xp_reward: Optional[int] = None


class CourseListResponse(CourseBase):
    """Course list item (without modules) - for browsing"""
    instructor_name: Optional[str] = None
    enrollment_count: int = 0
    difficulty_rating: int = 1
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


class PaginatedCoursesResponse(BaseModel):
    """Paginated courses response"""
    courses: List[CourseListResponse]
    total: int
    page: int
    page_size: int


class CourseDetailResponse(CourseBase):
    """Full course details with modules"""
    instructor_name: Optional[str] = None
    instructor_id: int
    estimated_hours: int = 0
    enrollment_count: int = 0
    completion_count: int = 0
    difficulty_rating: int = 1
    status: str
    is_featured: bool = False
    preview_video_url: Optional[str] = None
    modules: List[CourseModuleResponse] = []
    created_at: datetime
    updated_at: datetime
    published_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ============================================================================
# ENROLLMENT & PROGRESS SCHEMAS
# ============================================================================

class EnrollmentCreate(BaseModel):
    """Enroll in a course"""
    course_id: str


class ModuleProgressUpdate(BaseModel):
    """Update module progress"""
    completed: Optional[bool] = None
    time_spent: int = 0
    last_position: Optional[str] = None
    completed_sections: List[str] = []
    quiz_scores: Dict[str, float] = {}
    notes: Optional[str] = None


class CourseProgressResponse(BaseModel):
    """Course progress response"""
    course_id: str
    title: str
    level: str
    progress: int  # 0-100
    completed_modules: List[str] = []
    current_module: Optional[str] = None
    last_accessed: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    total_modules: int
    is_complete: bool
    bookmarks: Optional[List[str]] = []
    notes: Optional[Dict[str, str]] = {}
    time_spent: Optional[int] = 0
    achievements: Optional[List[str]] = []

    class Config:
        from_attributes = True


# ============================================================================
# BULK OPERATIONS (For Admin)
# ============================================================================

class BulkCourseCreate(BaseModel):
    """Create course with all modules and sections at once"""
    course: CourseCreate
    modules: List[CourseModuleCreate]
    sections: Dict[str, List[ModuleSectionCreate]]  # module_id -> sections


class CoursePublishRequest(BaseModel):
    """Publish or unpublish a course"""
    status: str = Field(..., pattern="^(draft|published|archived)$")


# ============================================================================
# CERTIFICATE SCHEMAS
# ============================================================================

class CertificateBase(BaseModel):
    """Base certificate schema"""
    title: str
    description: Optional[str] = None
    verification_code: str
    skills_acquired: List[str] = []
    recipient_name: Optional[str] = None
    instructor_name: Optional[str] = None
    course_title: str
    course_level: Optional[str] = None


class CertificateResponse(CertificateBase):
    """Certificate response schema"""
    id: int
    user_id: int
    course_id: str
    enrollment_id: int
    total_modules: int
    total_sections: int
    issued_at: datetime

    class Config:
        from_attributes = True


class CertificateCompact(BaseModel):
    """Compact certificate for completion response"""
    title: str
    description: str
    verification_code: str
    skills_acquired: List[str] = []


class ModuleProgressResponse(BaseModel):
    """Response after updating module progress"""
    message: str = "Progress updated"
    completed: bool
    completed_sections: List[str]
    time_spent: int
    module_completed: bool = False
    course_complete: bool = False
    progress: int = 0
    certificate: Optional[CertificateCompact] = None
    certificate_id: Optional[int] = None


# ============================================================================
# CONTENT BLOCK HELPER SCHEMAS (for admin panel)
# ============================================================================

class ContentBlockTemplate(BaseModel):
    """Template for creating new blocks in admin panel"""
    type: ContentBlockTypeEnum
    label: str
    description: str
    default_content: Dict[str, Any]


# Pre-defined block templates for the admin panel
CONTENT_BLOCK_TEMPLATES = [
    ContentBlockTemplate(
        type=ContentBlockTypeEnum.TEXT,
        label="Text",
        description="Rich text content with markdown support",
        default_content={"text": "Enter your text here...", "markdown": True}
    ),
    ContentBlockTemplate(
        type=ContentBlockTypeEnum.HEADING,
        label="Heading",
        description="Section heading",
        default_content={"text": "Heading Text", "level": 2}
    ),
    ContentBlockTemplate(
        type=ContentBlockTypeEnum.QUIZ,
        label="Quiz",
        description="Multiple questions with answers",
        default_content={
            "title": "Check Your Understanding",
            "questions": [],
            "passing_score": 70,
            "allow_retakes": True
        }
    ),
    ContentBlockTemplate(
        type=ContentBlockTypeEnum.VIDEO,
        label="Video",
        description="Embedded video content",
        default_content={"url": "", "provider": "youtube"}
    ),
    ContentBlockTemplate(
        type=ContentBlockTypeEnum.CODE,
        label="Code",
        description="Code snippet with syntax highlighting",
        default_content={
            "code": "# Your code here",
            "language": "python",
            "show_line_numbers": True
        }
    ),
    ContentBlockTemplate(
        type=ContentBlockTypeEnum.IMAGE,
        label="Image",
        description="Image with caption",
        default_content={"url": "", "alt": "", "width": "full"}
    ),
    ContentBlockTemplate(
        type=ContentBlockTypeEnum.CALLOUT,
        label="Callout",
        description="Highlighted info box",
        default_content={"text": "", "style": "info", "title": "Note"}
    ),
]
