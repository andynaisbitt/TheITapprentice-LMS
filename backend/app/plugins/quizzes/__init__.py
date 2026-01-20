# backend/app/plugins/quizzes/__init__.py
"""
Quiz Plugin - Standalone quiz system for LMS
Supports multiple question types, attempts tracking, and course integration.
"""

from .models import Quiz, QuizQuestion, QuizAttempt, QuestionType
from .routes import router

__all__ = [
    "Quiz",
    "QuizQuestion",
    "QuizAttempt",
    "QuestionType",
    "router",
]
