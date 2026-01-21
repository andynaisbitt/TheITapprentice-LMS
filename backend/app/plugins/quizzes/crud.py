# backend/app/plugins/quizzes/crud.py
"""
Quiz System CRUD Operations
"""
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, text
from typing import Optional, List, Dict, Any
from datetime import datetime
import random

from .models import Quiz, QuizQuestion, QuizAttempt, QuizStatus
from .schemas import (
    QuizCreate, QuizUpdate, QuestionCreate, QuestionUpdate,
    QuestionOption
)
from app.users.models import User


# ============== Quiz CRUD ==============

def get_quiz(db: Session, quiz_id: str) -> Optional[Quiz]:
    """Get a quiz by ID"""
    return db.query(Quiz).filter(Quiz.id == quiz_id).first()


def get_quizzes(
    db: Session,
    skip: int = 0,
    limit: int = 20,
    category: Optional[str] = None,
    difficulty: Optional[str] = None,
    status: Optional[QuizStatus] = None,
    search: Optional[str] = None,
    course_id: Optional[str] = None,
    featured_only: bool = False,
) -> List[Quiz]:
    """Get list of quizzes with filters"""
    query = db.query(Quiz)

    if category:
        query = query.filter(Quiz.category == category)
    if difficulty:
        query = query.filter(Quiz.difficulty == difficulty)
    if status:
        # Use text() with .value for PostgreSQL enum compatibility
        query = query.filter(Quiz.status == text(f"'{status.value}'::quizstatus"))
    if course_id:
        query = query.filter(Quiz.course_id == course_id)
    if featured_only:
        query = query.filter(Quiz.is_featured == True)
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (Quiz.title.ilike(search_term)) |
            (Quiz.description.ilike(search_term))
        )

    return query.order_by(desc(Quiz.created_at)).offset(skip).limit(limit).all()


def get_published_quizzes(
    db: Session,
    skip: int = 0,
    limit: int = 20,
    category: Optional[str] = None,
    difficulty: Optional[str] = None,
) -> List[Quiz]:
    """Get published quizzes for public browsing"""
    return get_quizzes(
        db,
        skip=skip,
        limit=limit,
        category=category,
        difficulty=difficulty,
        status=QuizStatus.PUBLISHED,
    )


def create_quiz(db: Session, quiz_data: QuizCreate, created_by: int) -> Quiz:
    """Create a new quiz with questions"""
    # Create quiz
    quiz = Quiz(
        id=quiz_data.id,
        title=quiz_data.title,
        description=quiz_data.description,
        instructions=quiz_data.instructions,
        category=quiz_data.category,
        tags=quiz_data.tags,
        difficulty=quiz_data.difficulty,
        time_limit_minutes=quiz_data.time_limit_minutes,
        passing_score=quiz_data.passing_score,
        max_attempts=quiz_data.max_attempts,
        question_order=quiz_data.question_order,
        show_answers_after=quiz_data.show_answers_after,
        allow_review=quiz_data.allow_review,
        xp_reward=quiz_data.xp_reward,
        xp_perfect=quiz_data.xp_perfect,
        course_id=quiz_data.course_id,
        module_id=quiz_data.module_id,
        status=quiz_data.status,
        is_featured=quiz_data.is_featured,
        created_by=created_by,
    )
    db.add(quiz)
    db.flush()

    # Create questions
    for idx, question_data in enumerate(quiz_data.questions):
        question = create_question(db, quiz.id, question_data, idx)

    db.commit()
    db.refresh(quiz)
    return quiz


def update_quiz(db: Session, quiz_id: str, quiz_data: QuizUpdate) -> Optional[Quiz]:
    """Update a quiz"""
    quiz = get_quiz(db, quiz_id)
    if not quiz:
        return None

    update_data = quiz_data.model_dump(exclude_unset=True)

    # Handle status change to published
    if update_data.get("status") == QuizStatus.PUBLISHED and quiz.status != QuizStatus.PUBLISHED:
        update_data["published_at"] = datetime.utcnow()

    for field, value in update_data.items():
        setattr(quiz, field, value)

    db.commit()
    db.refresh(quiz)
    return quiz


def delete_quiz(db: Session, quiz_id: str) -> bool:
    """Delete a quiz and all related data"""
    quiz = get_quiz(db, quiz_id)
    if not quiz:
        return False

    db.delete(quiz)
    db.commit()
    return True


# ============== Question CRUD ==============

def get_question(db: Session, question_id: int) -> Optional[QuizQuestion]:
    """Get a question by ID"""
    return db.query(QuizQuestion).filter(QuizQuestion.id == question_id).first()


def get_quiz_questions(db: Session, quiz_id: str, randomize: bool = False) -> List[QuizQuestion]:
    """Get all questions for a quiz"""
    query = db.query(QuizQuestion).filter(QuizQuestion.quiz_id == quiz_id)

    if randomize:
        questions = query.all()
        random.shuffle(questions)
        return questions
    else:
        return query.order_by(QuizQuestion.order_index).all()


def create_question(
    db: Session,
    quiz_id: str,
    question_data: QuestionCreate,
    order_index: Optional[int] = None
) -> QuizQuestion:
    """Create a new question"""
    # Convert options to dict format
    options = [opt.model_dump() if isinstance(opt, QuestionOption) else opt for opt in question_data.options]

    question = QuizQuestion(
        quiz_id=quiz_id,
        question_type=question_data.question_type,
        question_text=question_data.question_text,
        question_html=question_data.question_html,
        options=options,
        correct_answer=question_data.correct_answer,
        explanation=question_data.explanation,
        code_language=question_data.code_language,
        code_template=question_data.code_template,
        points=question_data.points,
        order_index=order_index if order_index is not None else question_data.order_index,
        image_url=question_data.image_url,
    )
    db.add(question)
    db.flush()
    return question


def update_question(db: Session, question_id: int, question_data: QuestionUpdate) -> Optional[QuizQuestion]:
    """Update a question"""
    question = get_question(db, question_id)
    if not question:
        return None

    update_data = question_data.model_dump(exclude_unset=True)

    # Handle options conversion
    if "options" in update_data and update_data["options"]:
        update_data["options"] = [
            opt.model_dump() if isinstance(opt, QuestionOption) else opt
            for opt in update_data["options"]
        ]

    for field, value in update_data.items():
        setattr(question, field, value)

    db.commit()
    db.refresh(question)
    return question


def delete_question(db: Session, question_id: int) -> bool:
    """Delete a question"""
    question = get_question(db, question_id)
    if not question:
        return False

    db.delete(question)
    db.commit()
    return True


def reorder_questions(db: Session, quiz_id: str, question_order: List[int]) -> bool:
    """Reorder questions in a quiz"""
    questions = get_quiz_questions(db, quiz_id)
    question_map = {q.id: q for q in questions}

    for idx, question_id in enumerate(question_order):
        if question_id in question_map:
            question_map[question_id].order_index = idx

    db.commit()
    return True


# ============== Attempt CRUD ==============

def get_attempt(db: Session, attempt_id: int) -> Optional[QuizAttempt]:
    """Get an attempt by ID"""
    return db.query(QuizAttempt).filter(QuizAttempt.id == attempt_id).first()


def get_user_attempts(
    db: Session,
    user_id: int,
    quiz_id: Optional[str] = None,
    limit: int = 20
) -> List[QuizAttempt]:
    """Get user's quiz attempts"""
    query = db.query(QuizAttempt).filter(QuizAttempt.user_id == user_id)

    if quiz_id:
        query = query.filter(QuizAttempt.quiz_id == quiz_id)

    return query.order_by(desc(QuizAttempt.started_at)).limit(limit).all()


def get_user_quiz_attempt_count(db: Session, user_id: int, quiz_id: str) -> int:
    """Get number of attempts a user has made on a quiz"""
    return db.query(QuizAttempt).filter(
        QuizAttempt.user_id == user_id,
        QuizAttempt.quiz_id == quiz_id,
        QuizAttempt.is_complete == True
    ).count()


def get_user_best_attempt(db: Session, user_id: int, quiz_id: str) -> Optional[QuizAttempt]:
    """Get user's best attempt on a quiz"""
    return db.query(QuizAttempt).filter(
        QuizAttempt.user_id == user_id,
        QuizAttempt.quiz_id == quiz_id,
        QuizAttempt.is_complete == True
    ).order_by(desc(QuizAttempt.percentage)).first()


def start_attempt(db: Session, user_id: int, quiz_id: str) -> QuizAttempt:
    """Start a new quiz attempt"""
    # Get attempt number
    attempt_count = get_user_quiz_attempt_count(db, user_id, quiz_id)

    # Calculate max score
    quiz = get_quiz(db, quiz_id)
    max_score = sum(q.points for q in quiz.questions) if quiz else 0

    attempt = QuizAttempt(
        quiz_id=quiz_id,
        user_id=user_id,
        attempt_number=attempt_count + 1,
        max_score=max_score,
    )
    db.add(attempt)
    db.commit()
    db.refresh(attempt)
    return attempt


def submit_attempt(
    db: Session,
    attempt_id: int,
    answers: Dict[str, Any],
) -> QuizAttempt:
    """Submit answers and calculate score for an attempt"""
    attempt = get_attempt(db, attempt_id)
    if not attempt:
        return None

    quiz = get_quiz(db, attempt.quiz_id)
    if not quiz:
        return None

    # Calculate score
    score = 0
    question_results = {}

    for question in quiz.questions:
        q_id = str(question.id)
        user_answer = answers.get(q_id)
        is_correct = check_answer(question, user_answer)
        points_earned = question.points if is_correct else 0
        score += points_earned

        question_results[q_id] = {
            "correct": is_correct,
            "points_earned": points_earned,
        }

    # Update attempt
    attempt.answers = answers
    attempt.question_results = question_results
    attempt.score = score
    attempt.percentage = (score / attempt.max_score * 100) if attempt.max_score > 0 else 0
    attempt.passed = attempt.percentage >= quiz.passing_score
    attempt.is_complete = True
    attempt.completed_at = datetime.utcnow()

    # Calculate time taken
    if attempt.started_at:
        time_diff = attempt.completed_at - attempt.started_at
        attempt.time_taken_seconds = int(time_diff.total_seconds())

    db.commit()

    # Update quiz stats
    update_quiz_stats(db, quiz.id)

    db.refresh(attempt)
    return attempt


def check_answer(question: QuizQuestion, user_answer: Any) -> bool:
    """Check if user's answer is correct"""
    if user_answer is None:
        return False

    correct = question.correct_answer

    if question.question_type.value == "multiple_choice":
        return str(user_answer).lower() == str(correct).lower()

    elif question.question_type.value == "multiple_select":
        if not isinstance(user_answer, list):
            return False
        user_set = set(str(a).lower() for a in user_answer)
        correct_set = set(str(c).lower() for c in correct)
        return user_set == correct_set

    elif question.question_type.value == "true_false":
        return str(user_answer).lower() == str(correct).lower()

    elif question.question_type.value == "short_answer":
        user_lower = str(user_answer).lower().strip()
        if isinstance(correct, list):
            return user_lower in [str(c).lower().strip() for c in correct]
        return user_lower == str(correct).lower().strip()

    elif question.question_type.value == "fill_blank":
        return str(user_answer).lower().strip() == str(correct).lower().strip()

    elif question.question_type.value == "code":
        # Code questions need special handling - basic comparison for now
        return str(user_answer).strip() == str(correct.get("expected_output", "")).strip()

    return False


def update_quiz_stats(db: Session, quiz_id: str) -> None:
    """Update quiz statistics after an attempt"""
    quiz = get_quiz(db, quiz_id)
    if not quiz:
        return

    # Get all completed attempts
    attempts = db.query(QuizAttempt).filter(
        QuizAttempt.quiz_id == quiz_id,
        QuizAttempt.is_complete == True
    ).all()

    if attempts:
        quiz.total_attempts = len(attempts)
        quiz.avg_score = sum(a.percentage for a in attempts) / len(attempts)
        passed_count = sum(1 for a in attempts if a.passed)
        quiz.pass_rate = (passed_count / len(attempts)) * 100

    db.commit()


# ============== Leaderboard ==============

def get_quiz_leaderboard(
    db: Session,
    quiz_id: str,
    limit: int = 10
) -> List[Dict]:
    """Get leaderboard for a specific quiz"""
    # Get best attempt per user
    subquery = db.query(
        QuizAttempt.user_id,
        func.max(QuizAttempt.percentage).label("best_score"),
        func.min(QuizAttempt.time_taken_seconds).label("best_time"),
        func.count(QuizAttempt.id).label("attempts")
    ).filter(
        QuizAttempt.quiz_id == quiz_id,
        QuizAttempt.is_complete == True
    ).group_by(QuizAttempt.user_id).subquery()

    results = db.query(
        User.id,
        User.username,
        User.display_name,
        subquery.c.best_score,
        subquery.c.best_time,
        subquery.c.attempts
    ).join(
        subquery, User.id == subquery.c.user_id
    ).order_by(
        desc(subquery.c.best_score),
        subquery.c.best_time
    ).limit(limit).all()

    return [
        {
            "rank": idx + 1,
            "user_id": r[0],
            "username": r[1],
            "display_name": r[2],
            "best_score": r[3],
            "best_time": r[4],
            "attempts": r[5]
        }
        for idx, r in enumerate(results)
    ]


# ============== User Stats ==============

def get_user_quiz_stats(db: Session, user_id: int) -> Dict:
    """Get user's overall quiz statistics"""
    attempts = db.query(QuizAttempt).filter(
        QuizAttempt.user_id == user_id,
        QuizAttempt.is_complete == True
    ).all()

    if not attempts:
        return {
            "total_attempts": 0,
            "quizzes_passed": 0,
            "quizzes_failed": 0,
            "average_score": 0.0,
            "best_score": 0.0,
            "total_xp_earned": 0,
        }

    passed = sum(1 for a in attempts if a.passed)
    scores = [a.percentage for a in attempts]

    return {
        "total_attempts": len(attempts),
        "quizzes_passed": passed,
        "quizzes_failed": len(attempts) - passed,
        "average_score": sum(scores) / len(scores),
        "best_score": max(scores),
        "total_xp_earned": sum(a.xp_awarded for a in attempts),
    }
