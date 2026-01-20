# backend/app/plugins/quizzes/routes.py
"""
Quiz System API Routes
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.auth.dependencies import get_current_user, get_current_admin_user
from app.users.models import User
from app.plugins.shared.xp_service import xp_service
from app.plugins.shared.achievement_service import achievement_service

from . import crud
from .models import QuizStatus
from .schemas import (
    QuizCreate, QuizUpdate, QuizSummary, QuizResponse, QuizAdminResponse,
    QuestionCreate, QuestionUpdate, QuestionResponse, QuestionResponseWithAnswer,
    QuizAttemptStart, QuizAttemptSubmit, QuizAttemptResponse, QuizAttemptResult,
    QuestionResult, UserQuizStats, QuizLeaderboard, QuizLeaderboardEntry
)

router = APIRouter(prefix="/quizzes", tags=["quizzes"])


# ============== Public Quiz Routes ==============

@router.get("/", response_model=List[QuizSummary])
async def list_quizzes(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    category: Optional[str] = None,
    difficulty: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List all published quizzes"""
    quizzes = crud.get_published_quizzes(
        db, skip=skip, limit=limit,
        category=category, difficulty=difficulty
    )

    return [
        QuizSummary(
            id=q.id,
            title=q.title,
            description=q.description,
            category=q.category,
            difficulty=q.difficulty,
            time_limit_minutes=q.time_limit_minutes,
            passing_score=q.passing_score,
            question_count=len(q.questions),
            xp_reward=q.xp_reward,
            status=q.status,
            is_featured=q.is_featured,
            total_attempts=q.total_attempts,
            avg_score=q.avg_score,
            pass_rate=q.pass_rate,
            created_at=q.created_at,
        )
        for q in quizzes
    ]


@router.get("/featured", response_model=List[QuizSummary])
async def get_featured_quizzes(
    limit: int = Query(6, ge=1, le=20),
    db: Session = Depends(get_db)
):
    """Get featured quizzes"""
    quizzes = crud.get_quizzes(
        db, limit=limit,
        status=QuizStatus.PUBLISHED,
        featured_only=True
    )

    return [
        QuizSummary(
            id=q.id,
            title=q.title,
            description=q.description,
            category=q.category,
            difficulty=q.difficulty,
            time_limit_minutes=q.time_limit_minutes,
            passing_score=q.passing_score,
            question_count=len(q.questions),
            xp_reward=q.xp_reward,
            status=q.status,
            is_featured=q.is_featured,
            total_attempts=q.total_attempts,
            avg_score=q.avg_score,
            pass_rate=q.pass_rate,
            created_at=q.created_at,
        )
        for q in quizzes
    ]


@router.get("/{quiz_id}", response_model=QuizResponse)
async def get_quiz(
    quiz_id: str,
    db: Session = Depends(get_db)
):
    """Get quiz details (without correct answers)"""
    quiz = crud.get_quiz(db, quiz_id)
    if not quiz:
        raise HTTPException(status_code=404, detail="Quiz not found")

    if quiz.status != QuizStatus.PUBLISHED:
        raise HTTPException(status_code=404, detail="Quiz not found")

    # Get questions without correct answers
    questions = crud.get_quiz_questions(
        db, quiz_id,
        randomize=(quiz.question_order == "random")
    )

    return QuizResponse(
        id=quiz.id,
        title=quiz.title,
        description=quiz.description,
        instructions=quiz.instructions,
        category=quiz.category,
        tags=quiz.tags,
        difficulty=quiz.difficulty,
        time_limit_minutes=quiz.time_limit_minutes,
        passing_score=quiz.passing_score,
        max_attempts=quiz.max_attempts,
        question_order=quiz.question_order,
        show_answers_after=quiz.show_answers_after,
        allow_review=quiz.allow_review,
        xp_reward=quiz.xp_reward,
        xp_perfect=quiz.xp_perfect,
        question_count=len(questions),
        questions=[
            QuestionResponse(
                id=q.id,
                question_type=q.question_type,
                question_text=q.question_text,
                question_html=q.question_html,
                options=[{k: v for k, v in opt.items() if k != "is_correct"} for opt in q.options],
                code_language=q.code_language,
                code_template=q.code_template,
                points=q.points,
                order_index=q.order_index,
                image_url=q.image_url,
            )
            for q in questions
        ],
        total_attempts=quiz.total_attempts,
        avg_score=quiz.avg_score,
        created_at=quiz.created_at,
    )


@router.get("/{quiz_id}/leaderboard", response_model=QuizLeaderboard)
async def get_quiz_leaderboard(
    quiz_id: str,
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """Get quiz leaderboard"""
    quiz = crud.get_quiz(db, quiz_id)
    if not quiz:
        raise HTTPException(status_code=404, detail="Quiz not found")

    entries = crud.get_quiz_leaderboard(db, quiz_id, limit=limit)

    return QuizLeaderboard(
        quiz_id=quiz.id,
        quiz_title=quiz.title,
        entries=[
            QuizLeaderboardEntry(**entry)
            for entry in entries
        ],
        total_participants=quiz.total_attempts,
    )


# ============== Quiz Attempt Routes ==============

@router.post("/{quiz_id}/start", response_model=QuizAttemptResponse)
async def start_quiz_attempt(
    quiz_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Start a quiz attempt"""
    quiz = crud.get_quiz(db, quiz_id)
    if not quiz:
        raise HTTPException(status_code=404, detail="Quiz not found")

    if quiz.status != QuizStatus.PUBLISHED:
        raise HTTPException(status_code=400, detail="Quiz is not available")

    # Check max attempts
    if quiz.max_attempts > 0:
        attempt_count = crud.get_user_quiz_attempt_count(db, current_user.id, quiz_id)
        if attempt_count >= quiz.max_attempts:
            raise HTTPException(
                status_code=400,
                detail=f"Maximum attempts ({quiz.max_attempts}) reached"
            )

    attempt = crud.start_attempt(db, current_user.id, quiz_id)
    return QuizAttemptResponse.model_validate(attempt)


@router.post("/{quiz_id}/submit", response_model=QuizAttemptResult)
async def submit_quiz_attempt(
    quiz_id: str,
    submission: QuizAttemptSubmit,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Submit quiz answers"""
    quiz = crud.get_quiz(db, quiz_id)
    if not quiz:
        raise HTTPException(status_code=404, detail="Quiz not found")

    # Get user's current incomplete attempt
    attempts = crud.get_user_attempts(db, current_user.id, quiz_id, limit=1)
    if not attempts or attempts[0].is_complete:
        raise HTTPException(status_code=400, detail="No active attempt found. Start a new attempt first.")

    attempt = attempts[0]

    # Submit and grade
    attempt = crud.submit_attempt(db, attempt.id, submission.answers)

    # Award XP if this is first passing attempt
    xp_awarded = 0
    if attempt.passed:
        best_previous = crud.get_user_best_attempt(db, current_user.id, quiz_id)
        if not best_previous or best_previous.id == attempt.id:
            # First passing attempt or this is the best
            if attempt.percentage >= 100:
                xp_awarded = quiz.xp_perfect
            else:
                xp_awarded = quiz.xp_reward

            if xp_awarded > 0:
                xp_service.award_xp(
                    db, current_user.id,
                    "tutorial_complete",  # Use existing action type
                    multiplier=xp_awarded / 100,  # Scale to desired XP
                    reason=f"Passed quiz: {quiz.title}"
                )
                attempt.xp_awarded = xp_awarded
                db.commit()

            # Check for quiz achievements
            achievement_service.check_and_unlock_achievements(
                db, current_user.id, "quiz_complete",
                {"quiz_id": quiz_id, "score": attempt.percentage, "passed": True}
            )

    # Build detailed results
    question_results = []
    for question in quiz.questions:
        q_id = str(question.id)
        result = attempt.question_results.get(q_id, {})
        question_results.append(
            QuestionResult(
                question_id=question.id,
                correct=result.get("correct", False),
                points_earned=result.get("points_earned", 0),
                user_answer=attempt.answers.get(q_id),
                correct_answer=question.correct_answer if quiz.show_answers_after else None,
                explanation=question.explanation if quiz.show_answers_after else None,
            )
        )

    return QuizAttemptResult(
        id=attempt.id,
        quiz_id=attempt.quiz_id,
        user_id=attempt.user_id,
        attempt_number=attempt.attempt_number,
        score=attempt.score,
        max_score=attempt.max_score,
        percentage=attempt.percentage,
        passed=attempt.passed,
        time_taken_seconds=attempt.time_taken_seconds,
        started_at=attempt.started_at,
        completed_at=attempt.completed_at,
        is_complete=attempt.is_complete,
        xp_awarded=attempt.xp_awarded,
        question_results=question_results,
        quiz_title=quiz.title,
        show_answers=quiz.show_answers_after,
    )


@router.get("/attempts/me", response_model=List[QuizAttemptResponse])
async def get_my_attempts(
    quiz_id: Optional[str] = None,
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get current user's quiz attempts"""
    attempts = crud.get_user_attempts(db, current_user.id, quiz_id, limit)
    return [QuizAttemptResponse.model_validate(a) for a in attempts]


@router.get("/stats/me", response_model=UserQuizStats)
async def get_my_quiz_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get current user's quiz statistics"""
    stats = crud.get_user_quiz_stats(db, current_user.id)
    recent = crud.get_user_attempts(db, current_user.id, limit=5)

    return UserQuizStats(
        **stats,
        recent_attempts=[QuizAttemptResponse.model_validate(a) for a in recent]
    )


# ============== Admin Quiz Routes ==============

@router.get("/admin/all", response_model=List[QuizAdminResponse])
async def admin_list_all_quizzes(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    status: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Admin: List all quizzes including drafts"""
    status_filter = QuizStatus(status) if status else None
    quizzes = crud.get_quizzes(
        db, skip=skip, limit=limit,
        status=status_filter, search=search
    )

    results = []
    for quiz in quizzes:
        questions = crud.get_quiz_questions(db, quiz.id)
        results.append(
            QuizAdminResponse(
                id=quiz.id,
                title=quiz.title,
                description=quiz.description,
                instructions=quiz.instructions,
                category=quiz.category,
                tags=quiz.tags,
                difficulty=quiz.difficulty,
                time_limit_minutes=quiz.time_limit_minutes,
                passing_score=quiz.passing_score,
                max_attempts=quiz.max_attempts,
                question_order=quiz.question_order,
                show_answers_after=quiz.show_answers_after,
                allow_review=quiz.allow_review,
                xp_reward=quiz.xp_reward,
                xp_perfect=quiz.xp_perfect,
                question_count=len(questions),
                questions=[
                    QuestionResponseWithAnswer(
                        id=q.id,
                        question_type=q.question_type,
                        question_text=q.question_text,
                        question_html=q.question_html,
                        options=q.options,
                        correct_answer=q.correct_answer,
                        explanation=q.explanation,
                        code_language=q.code_language,
                        code_template=q.code_template,
                        points=q.points,
                        order_index=q.order_index,
                        image_url=q.image_url,
                    )
                    for q in questions
                ],
                total_attempts=quiz.total_attempts,
                avg_score=quiz.avg_score,
                status=quiz.status,
                is_featured=quiz.is_featured,
                course_id=quiz.course_id,
                module_id=quiz.module_id,
                created_by=quiz.created_by,
                pass_rate=quiz.pass_rate,
                created_at=quiz.created_at,
                updated_at=quiz.updated_at,
                published_at=quiz.published_at,
            )
        )

    return results


@router.get("/admin/{quiz_id}", response_model=QuizAdminResponse)
async def admin_get_quiz(
    quiz_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Admin: Get quiz with correct answers"""
    quiz = crud.get_quiz(db, quiz_id)
    if not quiz:
        raise HTTPException(status_code=404, detail="Quiz not found")

    questions = crud.get_quiz_questions(db, quiz_id)

    return QuizAdminResponse(
        id=quiz.id,
        title=quiz.title,
        description=quiz.description,
        instructions=quiz.instructions,
        category=quiz.category,
        tags=quiz.tags,
        difficulty=quiz.difficulty,
        time_limit_minutes=quiz.time_limit_minutes,
        passing_score=quiz.passing_score,
        max_attempts=quiz.max_attempts,
        question_order=quiz.question_order,
        show_answers_after=quiz.show_answers_after,
        allow_review=quiz.allow_review,
        xp_reward=quiz.xp_reward,
        xp_perfect=quiz.xp_perfect,
        question_count=len(questions),
        questions=[
            QuestionResponseWithAnswer(
                id=q.id,
                question_type=q.question_type,
                question_text=q.question_text,
                question_html=q.question_html,
                options=q.options,
                correct_answer=q.correct_answer,
                explanation=q.explanation,
                code_language=q.code_language,
                code_template=q.code_template,
                points=q.points,
                order_index=q.order_index,
                image_url=q.image_url,
            )
            for q in questions
        ],
        total_attempts=quiz.total_attempts,
        avg_score=quiz.avg_score,
        status=quiz.status,
        is_featured=quiz.is_featured,
        course_id=quiz.course_id,
        module_id=quiz.module_id,
        created_by=quiz.created_by,
        pass_rate=quiz.pass_rate,
        created_at=quiz.created_at,
        updated_at=quiz.updated_at,
        published_at=quiz.published_at,
    )


@router.post("/admin", response_model=QuizAdminResponse)
async def admin_create_quiz(
    quiz_data: QuizCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Admin: Create a new quiz"""
    # Check if ID already exists
    existing = crud.get_quiz(db, quiz_data.id)
    if existing:
        raise HTTPException(status_code=400, detail="Quiz ID already exists")

    quiz = crud.create_quiz(db, quiz_data, current_user.id)
    return await admin_get_quiz(quiz.id, db, current_user)


@router.put("/admin/{quiz_id}", response_model=QuizAdminResponse)
async def admin_update_quiz(
    quiz_id: str,
    quiz_data: QuizUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Admin: Update a quiz"""
    quiz = crud.update_quiz(db, quiz_id, quiz_data)
    if not quiz:
        raise HTTPException(status_code=404, detail="Quiz not found")

    return await admin_get_quiz(quiz_id, db, current_user)


@router.delete("/admin/{quiz_id}")
async def admin_delete_quiz(
    quiz_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Admin: Delete a quiz"""
    success = crud.delete_quiz(db, quiz_id)
    if not success:
        raise HTTPException(status_code=404, detail="Quiz not found")

    return {"success": True, "message": "Quiz deleted"}


# ============== Admin Question Routes ==============

@router.post("/admin/{quiz_id}/questions", response_model=QuestionResponseWithAnswer)
async def admin_add_question(
    quiz_id: str,
    question_data: QuestionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Admin: Add a question to a quiz"""
    quiz = crud.get_quiz(db, quiz_id)
    if not quiz:
        raise HTTPException(status_code=404, detail="Quiz not found")

    # Get next order index
    existing_questions = crud.get_quiz_questions(db, quiz_id)
    order_index = len(existing_questions)

    question = crud.create_question(db, quiz_id, question_data, order_index)
    db.commit()

    return QuestionResponseWithAnswer(
        id=question.id,
        question_type=question.question_type,
        question_text=question.question_text,
        question_html=question.question_html,
        options=question.options,
        correct_answer=question.correct_answer,
        explanation=question.explanation,
        code_language=question.code_language,
        code_template=question.code_template,
        points=question.points,
        order_index=question.order_index,
        image_url=question.image_url,
    )


@router.put("/admin/questions/{question_id}", response_model=QuestionResponseWithAnswer)
async def admin_update_question(
    question_id: int,
    question_data: QuestionUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Admin: Update a question"""
    question = crud.update_question(db, question_id, question_data)
    if not question:
        raise HTTPException(status_code=404, detail="Question not found")

    return QuestionResponseWithAnswer(
        id=question.id,
        question_type=question.question_type,
        question_text=question.question_text,
        question_html=question.question_html,
        options=question.options,
        correct_answer=question.correct_answer,
        explanation=question.explanation,
        code_language=question.code_language,
        code_template=question.code_template,
        points=question.points,
        order_index=question.order_index,
        image_url=question.image_url,
    )


@router.delete("/admin/questions/{question_id}")
async def admin_delete_question(
    question_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Admin: Delete a question"""
    success = crud.delete_question(db, question_id)
    if not success:
        raise HTTPException(status_code=404, detail="Question not found")

    return {"success": True, "message": "Question deleted"}


@router.post("/admin/{quiz_id}/questions/reorder")
async def admin_reorder_questions(
    quiz_id: str,
    question_order: List[int],
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Admin: Reorder questions in a quiz"""
    quiz = crud.get_quiz(db, quiz_id)
    if not quiz:
        raise HTTPException(status_code=404, detail="Quiz not found")

    success = crud.reorder_questions(db, quiz_id, question_order)
    return {"success": success}
