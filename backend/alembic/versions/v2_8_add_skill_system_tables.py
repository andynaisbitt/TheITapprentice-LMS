"""v2.8 Add skill system tables

Revision ID: v2_8_skills
Revises: v2_7_typing_analytics
Create Date: 2026-01-26

This migration adds the OSRS-style skill progression system:
- skills: 12 IT skills (Networking, Security, Programming, etc.)
- user_skills: Per-user skill XP and level tracking
- skill_xp_logs: Audit trail of all XP gains
- Add related_skills column to quizzes table
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "v2_8_skills"
down_revision: Union[str, None] = "v2_7_typing_analytics"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add skill system tables"""

    # Create skill category enum
    skill_category_enum = sa.Enum("technical", "soft", name="skillcategory")
    skill_category_enum.create(op.get_bind(), checkfirst=True)

    # Create skills table (12 IT skills)
    op.create_table(
        "skills",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("slug", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("icon", sa.String(length=10), nullable=True),  # Emoji icon
        sa.Column(
            "category",
            skill_category_enum,
            nullable=False,
            server_default="technical",
        ),
        sa.Column("display_order", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
        sa.UniqueConstraint("slug"),
    )
    op.create_index("ix_skills_slug", "skills", ["slug"])
    op.create_index("ix_skills_category", "skills", ["category"])
    op.create_index("ix_skills_is_active", "skills", ["is_active"])

    # Create user_skills table (tracks each user's progress per skill)
    op.create_table(
        "user_skills",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("skill_id", sa.Integer(), nullable=False),
        sa.Column("current_xp", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("current_level", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("total_activities_completed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=True),
        # Milestone timestamps (OSRS style)
        sa.Column("level_10_achieved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("level_30_achieved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("level_50_achieved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("level_75_achieved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("level_99_achieved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["skill_id"], ["skills.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "skill_id", name="uq_user_skill"),
    )
    op.create_index("ix_user_skills_user_id", "user_skills", ["user_id"])
    op.create_index("ix_user_skills_skill_id", "user_skills", ["skill_id"])
    op.create_index("ix_user_skills_current_level", "user_skills", ["current_level"])
    op.create_index("ix_user_skills_current_xp", "user_skills", ["current_xp"])

    # Create skill_xp_logs table (audit trail of all XP gains)
    op.create_table(
        "skill_xp_logs",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("skill_id", sa.Integer(), nullable=False),
        sa.Column("xp_gained", sa.Integer(), nullable=False),
        sa.Column("source_type", sa.String(length=50), nullable=False),  # quiz, tutorial, course, typing_game, etc.
        sa.Column("source_id", sa.String(length=100), nullable=True),  # ID of content that awarded XP
        sa.Column("source_metadata", sa.JSON(), nullable=True),  # Additional context (score, difficulty, etc.)
        sa.Column("level_before", sa.Integer(), nullable=False),
        sa.Column("level_after", sa.Integer(), nullable=False),
        sa.Column("earned_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["skill_id"], ["skills.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_skill_xp_logs_user_id", "skill_xp_logs", ["user_id"])
    op.create_index("ix_skill_xp_logs_skill_id", "skill_xp_logs", ["skill_id"])
    op.create_index("ix_skill_xp_logs_source_type", "skill_xp_logs", ["source_type"])
    op.create_index("ix_skill_xp_logs_earned_at", "skill_xp_logs", ["earned_at"])

    # Add related_skills column to quizzes table (quizzes didn't have this yet)
    op.add_column(
        "quizzes",
        sa.Column("related_skills", sa.JSON(), nullable=True, server_default='["problem-solving"]'),
    )


def downgrade() -> None:
    """Remove skill system tables"""

    # Remove related_skills from quizzes
    op.drop_column("quizzes", "related_skills")

    # Drop skill_xp_logs
    op.drop_index("ix_skill_xp_logs_earned_at", table_name="skill_xp_logs")
    op.drop_index("ix_skill_xp_logs_source_type", table_name="skill_xp_logs")
    op.drop_index("ix_skill_xp_logs_skill_id", table_name="skill_xp_logs")
    op.drop_index("ix_skill_xp_logs_user_id", table_name="skill_xp_logs")
    op.drop_table("skill_xp_logs")

    # Drop user_skills
    op.drop_index("ix_user_skills_current_xp", table_name="user_skills")
    op.drop_index("ix_user_skills_current_level", table_name="user_skills")
    op.drop_index("ix_user_skills_skill_id", table_name="user_skills")
    op.drop_index("ix_user_skills_user_id", table_name="user_skills")
    op.drop_table("user_skills")

    # Drop skills
    op.drop_index("ix_skills_is_active", table_name="skills")
    op.drop_index("ix_skills_category", table_name="skills")
    op.drop_index("ix_skills_slug", table_name="skills")
    op.drop_table("skills")

    # Drop enums
    sa.Enum(name="skillcategory").drop(op.get_bind(), checkfirst=True)
