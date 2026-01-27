"""v2.9 Add related_skills to quizzes

Revision ID: v2_9_quiz_skills
Revises: v2_8_skills
Create Date: 2026-01-27

Adds related_skills column to quizzes table for skill XP awards.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "v2_9_quiz_skills"
down_revision: Union[str, None] = "v2_8_skills"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add related_skills column to quizzes"""
    op.add_column(
        "quizzes",
        sa.Column("related_skills", sa.JSON(), nullable=True, server_default="[]")
    )


def downgrade() -> None:
    """Remove related_skills column from quizzes"""
    op.drop_column("quizzes", "related_skills")
