"""v1_8_add_courses_plugin_tables

Revision ID: 231994203e37
Revises: 066a6f56bd8d
Create Date: 2026-01-15 08:22:57.460399

This migration adds the Courses LMS plugin with content block system:
- courses: Main course table
- course_modules: Course modules/chapters
- module_sections: Sections within modules (with content_blocks JSON field)
- course_enrollments: User enrollment tracking
- module_progress: Progress tracking per module
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "231994203e37"
down_revision: Union[str, None] = "066a6f56bd8d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add courses plugin tables"""

    # Create courses table
    op.create_table(
        "courses",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("short_description", sa.String(length=500), nullable=True),
        sa.Column("image", sa.String(length=500), nullable=True),
        sa.Column("preview_video_url", sa.String(length=500), nullable=True),
        sa.Column("related_skills", sa.JSON(), nullable=True),
        sa.Column("xp_reward", sa.Integer(), nullable=True),
        sa.Column(
            "level",
            sa.Enum("beginner", "intermediate", "advanced", name="courselevel"),
            nullable=False,
        ),
        sa.Column("category", sa.String(length=100), nullable=True),
        sa.Column("skills", sa.JSON(), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=True),
        sa.Column("duration", sa.String(length=50), nullable=True),
        sa.Column("estimated_hours", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("requirements", sa.JSON(), nullable=True),
        sa.Column("objectives", sa.JSON(), nullable=True),
        sa.Column("instructor_id", sa.Integer(), nullable=False),
        sa.Column("instructor_name", sa.String(length=100), nullable=True),
        sa.Column(
            "status",
            sa.Enum("draft", "published", "archived", name="coursestatus"),
            nullable=False,
            server_default="draft",
        ),
        sa.Column("is_featured", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("is_premium", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("price", sa.Numeric(precision=10, scale=2), nullable=True, server_default="0.00"),
        sa.Column("currency", sa.String(length=3), nullable=True, server_default="USD"),
        sa.Column("enrollment_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("completion_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("difficulty_rating", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["instructor_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_courses_title", "courses", ["title"])
    op.create_index("ix_courses_level", "courses", ["level"])
    op.create_index("ix_courses_category", "courses", ["category"])
    op.create_index("ix_courses_instructor_id", "courses", ["instructor_id"])
    op.create_index("ix_courses_status", "courses", ["status"])
    op.create_index("ix_courses_is_featured", "courses", ["is_featured"])
    op.create_index("ix_courses_created_at", "courses", ["created_at"])

    # Create course_modules table
    op.create_table(
        "course_modules",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("course_id", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("duration", sa.String(length=50), nullable=True),
        sa.Column("estimated_minutes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("order_index", sa.Integer(), nullable=False),
        sa.Column("prerequisites", sa.JSON(), nullable=True),
        sa.Column("component", sa.String(length=200), nullable=True),
        sa.Column("difficulty_level", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "status",
            sa.Enum("locked", "available", "in-progress", "completed", name="sectionstatus"),
            nullable=False,
            server_default="available",
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["course_id"], ["courses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_course_modules_course_id", "course_modules", ["course_id"])

    # Create module_sections table
    op.create_table(
        "module_sections",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("module_id", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("time_estimate", sa.String(length=20), nullable=True),
        sa.Column(
            "type",
            sa.Enum("theory", "practice", "quiz", "challenge", "video", "exercise", name="sectiontype"),
            nullable=False,
            server_default="theory",
        ),
        sa.Column("content_blocks", sa.JSON(), nullable=False),
        sa.Column("order_index", sa.Integer(), nullable=False),
        sa.Column("points", sa.Integer(), nullable=False, server_default="10"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["module_id"], ["course_modules.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_module_sections_module_id", "module_sections", ["module_id"])

    # Create course_enrollments table
    op.create_table(
        "course_enrollments",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("course_id", sa.String(length=100), nullable=False),
        sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("current_module_id", sa.String(length=100), nullable=True),
        sa.Column("completed_modules", sa.JSON(), nullable=True),
        sa.Column(
            "status",
            sa.Enum("active", "completed", "dropped", name="enrollmentstatus"),
            nullable=False,
            server_default="active",
        ),
        sa.Column("is_complete", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("bookmarks", sa.JSON(), nullable=True),
        sa.Column("notes", sa.JSON(), nullable=True),
        sa.Column("time_spent", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("achievements", sa.JSON(), nullable=True),
        sa.Column("enrolled_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_accessed", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["course_id"], ["courses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_course_enrollments_id", "course_enrollments", ["id"])
    op.create_index("ix_course_enrollments_user_id", "course_enrollments", ["user_id"])
    op.create_index("ix_course_enrollments_course_id", "course_enrollments", ["course_id"])
    op.create_index("ix_course_enrollments_status", "course_enrollments", ["status"])
    op.create_index("ix_course_enrollments_is_complete", "course_enrollments", ["is_complete"])

    # Create module_progress table
    op.create_table(
        "module_progress",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("enrollment_id", sa.Integer(), nullable=False),
        sa.Column("module_id", sa.String(length=100), nullable=False),
        sa.Column("completed", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("time_spent", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_position", sa.String(length=100), nullable=True),
        sa.Column("completed_sections", sa.JSON(), nullable=True),
        sa.Column("quiz_scores", sa.JSON(), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("bookmarked", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_accessed", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.ForeignKeyConstraint(["enrollment_id"], ["course_enrollments.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_module_progress_id", "module_progress", ["id"])
    op.create_index("ix_module_progress_enrollment_id", "module_progress", ["enrollment_id"])
    op.create_index("ix_module_progress_module_id", "module_progress", ["module_id"])
    op.create_index("ix_module_progress_completed", "module_progress", ["completed"])


def downgrade() -> None:
    """Remove courses plugin tables"""

    # Drop tables in reverse order
    op.drop_index("ix_module_progress_completed", table_name="module_progress")
    op.drop_index("ix_module_progress_module_id", table_name="module_progress")
    op.drop_index("ix_module_progress_enrollment_id", table_name="module_progress")
    op.drop_index("ix_module_progress_id", table_name="module_progress")
    op.drop_table("module_progress")

    op.drop_index("ix_course_enrollments_is_complete", table_name="course_enrollments")
    op.drop_index("ix_course_enrollments_status", table_name="course_enrollments")
    op.drop_index("ix_course_enrollments_course_id", table_name="course_enrollments")
    op.drop_index("ix_course_enrollments_user_id", table_name="course_enrollments")
    op.drop_index("ix_course_enrollments_id", table_name="course_enrollments")
    op.drop_table("course_enrollments")

    op.drop_index("ix_module_sections_module_id", table_name="module_sections")
    op.drop_table("module_sections")

    op.drop_index("ix_course_modules_course_id", table_name="course_modules")
    op.drop_table("course_modules")

    op.drop_index("ix_courses_created_at", table_name="courses")
    op.drop_index("ix_courses_is_featured", table_name="courses")
    op.drop_index("ix_courses_status", table_name="courses")
    op.drop_index("ix_courses_instructor_id", table_name="courses")
    op.drop_index("ix_courses_category", table_name="courses")
    op.drop_index("ix_courses_level", table_name="courses")
    op.drop_index("ix_courses_title", table_name="courses")
    op.drop_table("courses")

    # Drop enums
    sa.Enum(name="enrollmentstatus").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="sectiontype").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="sectionstatus").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="coursestatus").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="courselevel").drop(op.get_bind(), checkfirst=True)
