# backend/app/plugins/courses/__init__.py
"""
Courses Plugin - LMS Course System with Content Blocks
Adapted from ITAppBetaV1 for BlogCMS
"""
from .models import (
    Course,
    CourseModule,
    ModuleSection,
    CourseEnrollment,
    ModuleProgress,
    CourseLevel,
    CourseStatus,
    SectionType,
    SectionStatus,
    ContentBlockType,
    QuestionType,
    EnrollmentStatus,
)

__all__ = [
    "Course",
    "CourseModule",
    "ModuleSection",
    "CourseEnrollment",
    "ModuleProgress",
    "CourseLevel",
    "CourseStatus",
    "SectionType",
    "SectionStatus",
    "ContentBlockType",
    "QuestionType",
    "EnrollmentStatus",
]
