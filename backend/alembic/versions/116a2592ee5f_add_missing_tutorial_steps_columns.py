"""add_missing_tutorial_steps_columns

The tutorial_steps table was created with only basic columns.
The model has since been extended with step_type, content_blocks,
media fields, quiz_question, expected_action, estimated_minutes,
and xp_reward. This migration adds the missing columns.

Revision ID: 116a2592ee5f
Revises: dbbb8aac75fe
Create Date: 2026-01-28 09:32:05.054741

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "116a2592ee5f"
down_revision: Union[str, None] = "dbbb8aac75fe"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Columns to add: (name, type, kwargs)
COLUMNS = [
    ("step_type", sa.String(20), {"server_default": "theory"}),
    ("content_blocks", sa.JSON(), {"server_default": "[]"}),
    ("media_type", sa.String(20), {"server_default": "none"}),
    ("media_content", sa.Text(), {"nullable": True}),
    ("media_language", sa.String(50), {"nullable": True}),
    ("media_caption", sa.String(500), {"nullable": True}),
    ("quiz_question", sa.JSON(), {"nullable": True}),
    ("expected_action", sa.Text(), {"nullable": True}),
    ("estimated_minutes", sa.Integer(), {"server_default": "5"}),
    ("xp_reward", sa.Integer(), {"server_default": "0"}),
]


def upgrade() -> None:
    for col_name, col_type, kwargs in COLUMNS:
        op.execute(
            f"""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'tutorial_steps' AND column_name = '{col_name}'
                ) THEN
                    ALTER TABLE tutorial_steps ADD COLUMN {col_name} {_pg_type(col_type, kwargs)};
                END IF;
            END
            $$;
            """
        )


def downgrade() -> None:
    for col_name, _, _ in reversed(COLUMNS):
        op.execute(
            f"""
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'tutorial_steps' AND column_name = '{col_name}'
                ) THEN
                    ALTER TABLE tutorial_steps DROP COLUMN {col_name};
                END IF;
            END
            $$;
            """
        )


def _pg_type(sa_type, kwargs):
    """Convert SA type + kwargs to a PostgreSQL column definition."""
    type_map = {
        "String": lambda t: f"VARCHAR({t.length})" if t.length else "VARCHAR",
        "Text": lambda _: "TEXT",
        "Integer": lambda _: "INTEGER",
        "JSON": lambda _: "JSONB",
    }
    type_name = type(sa_type).__name__
    pg = type_map.get(type_name, lambda _: "TEXT")(sa_type)

    parts = [pg]
    if kwargs.get("nullable") is False:
        parts.append("NOT NULL")
    if "server_default" in kwargs:
        default = kwargs["server_default"]
        # Wrap non-numeric defaults in quotes
        if default.replace(".", "").lstrip("-").isdigit() or default in ("[]", "null"):
            parts.append(f"DEFAULT '{default}'")
        else:
            parts.append(f"DEFAULT '{default}'")
    return " ".join(parts)
