"""v2.1 Add quizzes plugin tables

Revision ID: v2_1_add_quizzes_plugin_tables
Revises: v2_0_enhance_tutorial_steps
Create Date: 2026-01-20

This migration adds the standalone Quiz system:
- quizzes: Quiz definitions with settings
- quiz_questions: Question bank with multiple types
- quiz_attempts: User attempt tracking with scoring
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "v2_1_add_quizzes_plugin_tables"
down_revision: Union[str, None] = "v2_0_enhance_tutorial_steps"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add quizzes plugin tables"""

    # Create quizzes table
    op.create_table(
        "quizzes",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("instructions", sa.Text(), nullable=True),
        sa.Column("category", sa.String(length=100), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=True, server_default="[]"),
        sa.Column(
            "difficulty",
            sa.Enum("easy", "medium", "hard", "expert", name="quizdifficulty"),
            nullable=False,
            server_default="medium",
        ),
        sa.Column("time_limit_minutes", sa.Integer(), nullable=True),
        sa.Column("passing_score", sa.Integer(), nullable=False, server_default="70"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("question_order", sa.String(length=20), nullable=False, server_default="sequential"),
        sa.Column("show_answers_after", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("allow_review", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("xp_reward", sa.Integer(), nullable=False, server_default="50"),
        sa.Column("xp_perfect", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("course_id", sa.String(length=100), nullable=True),
        sa.Column("module_id", sa.String(length=100), nullable=True),
        sa.Column(
            "status",
            sa.Enum("draft", "published", "archived", name="quizstatus"),
            nullable=False,
            server_default="draft",
        ),
        sa.Column("is_featured", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("total_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("avg_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("pass_rate", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["course_id"], ["courses.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_quizzes_title", "quizzes", ["title"])
    op.create_index("ix_quizzes_category", "quizzes", ["category"])
    op.create_index("ix_quizzes_status", "quizzes", ["status"])
    op.create_index("ix_quizzes_course_id", "quizzes", ["course_id"])

    # Create quiz_questions table
    op.create_table(
        "quiz_questions",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("quiz_id", sa.String(length=100), nullable=False),
        sa.Column(
            "question_type",
            sa.Enum(
                "multiple_choice", "multiple_select", "true_false",
                "short_answer", "code", "fill_blank",
                name="questiontype"
            ),
            nullable=False,
        ),
        sa.Column("question_text", sa.Text(), nullable=False),
        sa.Column("question_html", sa.Text(), nullable=True),
        sa.Column("options", sa.JSON(), nullable=True, server_default="[]"),
        sa.Column("correct_answer", sa.JSON(), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=True),
        sa.Column("code_language", sa.String(length=50), nullable=True),
        sa.Column("code_template", sa.Text(), nullable=True),
        sa.Column("points", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("order_index", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("image_url", sa.String(length=500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["quiz_id"], ["quizzes.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_quiz_questions_id", "quiz_questions", ["id"])
    op.create_index("ix_quiz_questions_quiz_id", "quiz_questions", ["quiz_id"])

    # Create quiz_attempts table
    op.create_table(
        "quiz_attempts",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("quiz_id", sa.String(length=100), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("percentage", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("passed", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("answers", sa.JSON(), nullable=True, server_default="{}"),
        sa.Column("question_results", sa.JSON(), nullable=True, server_default="{}"),
        sa.Column("time_taken_seconds", sa.Integer(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_complete", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("xp_awarded", sa.Integer(), nullable=False, server_default="0"),
        sa.ForeignKeyConstraint(["quiz_id"], ["quizzes.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_quiz_attempts_id", "quiz_attempts", ["id"])
    op.create_index("ix_quiz_attempts_quiz_id", "quiz_attempts", ["quiz_id"])
    op.create_index("ix_quiz_attempts_user_id", "quiz_attempts", ["user_id"])
    op.create_index("ix_quiz_attempts_is_complete", "quiz_attempts", ["is_complete"])


def downgrade() -> None:
    """Remove quizzes plugin tables"""

    # Drop tables in reverse order
    op.drop_index("ix_quiz_attempts_is_complete", table_name="quiz_attempts")
    op.drop_index("ix_quiz_attempts_user_id", table_name="quiz_attempts")
    op.drop_index("ix_quiz_attempts_quiz_id", table_name="quiz_attempts")
    op.drop_index("ix_quiz_attempts_id", table_name="quiz_attempts")
    op.drop_table("quiz_attempts")

    op.drop_index("ix_quiz_questions_quiz_id", table_name="quiz_questions")
    op.drop_index("ix_quiz_questions_id", table_name="quiz_questions")
    op.drop_table("quiz_questions")

    op.drop_index("ix_quizzes_course_id", table_name="quizzes")
    op.drop_index("ix_quizzes_status", table_name="quizzes")
    op.drop_index("ix_quizzes_category", table_name="quizzes")
    op.drop_index("ix_quizzes_title", table_name="quizzes")
    op.drop_table("quizzes")

    # Drop enums
    sa.Enum(name="questiontype").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="quizstatus").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="quizdifficulty").drop(op.get_bind(), checkfirst=True)
