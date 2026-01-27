"""v2.10 Add missing columns to existing tables

Revision ID: v2_10_missing_cols
Revises: v2_9_quiz_skills
Create Date: 2026-01-27

Adds columns that were defined in models but missing from the database
because earlier migrations were stamped (tables already existed without
these columns).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "v2_10_missing_cols"
down_revision: Union[str, None] = "v2_9_quiz_skills"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _add_column_if_not_exists(table: str, column_name: str, column: sa.Column):
    """Safely add a column, skipping if it already exists."""
    from sqlalchemy import inspect
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [c["name"] for c in inspector.get_columns(table)]
    if column_name not in columns:
        op.add_column(table, column)


def upgrade() -> None:
    # typing_game_sessions - missing columns from v2.7 model updates
    _add_column_if_not_exists(
        "typing_game_sessions", "max_combo",
        sa.Column("max_combo", sa.Integer(), server_default="0")
    )
    _add_column_if_not_exists(
        "typing_game_sessions", "anti_cheat_confidence",
        sa.Column("anti_cheat_confidence", sa.Float(), server_default="1.0")
    )
    _add_column_if_not_exists(
        "typing_game_sessions", "anti_cheat_flags",
        sa.Column("anti_cheat_flags", sa.JSON(), server_default="[]")
    )
    _add_column_if_not_exists(
        "typing_game_sessions", "anti_cheat_flagged_for_review",
        sa.Column("anti_cheat_flagged_for_review", sa.Boolean(), server_default="false")
    )

    # quizzes - missing related_skills from v2.9
    _add_column_if_not_exists(
        "quizzes", "related_skills",
        sa.Column("related_skills", sa.ARRAY(sa.String()), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("quizzes", "related_skills")
    op.drop_column("typing_game_sessions", "anti_cheat_flagged_for_review")
    op.drop_column("typing_game_sessions", "anti_cheat_flags")
    op.drop_column("typing_game_sessions", "anti_cheat_confidence")
    op.drop_column("typing_game_sessions", "max_combo")
