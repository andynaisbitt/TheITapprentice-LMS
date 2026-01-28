"""fix_quiz_enum_case_mismatch

The quiz models use values_callable which sends lowercase enum values
(e.g. 'published') but the PostgreSQL enum types were created with
uppercase labels (e.g. 'PUBLISHED'). PostgreSQL enums are case-sensitive,
causing queries to fail with InvalidTextRepresentation.

This migration renames the enum labels to lowercase to match the code.

Revision ID: dbbb8aac75fe
Revises: v2_10_missing_cols
Create Date: 2026-01-28 08:41:08.452239

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "dbbb8aac75fe"
down_revision: Union[str, None] = "v2_10_missing_cols"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Map of enum type name -> (old_value, new_value) pairs
ENUM_RENAMES = {
    "quizstatus": [
        ("DRAFT", "draft"),
        ("PUBLISHED", "published"),
        ("ARCHIVED", "archived"),
    ],
    "questiontype": [
        ("MULTIPLE_CHOICE", "multiple_choice"),
        ("MULTIPLE_SELECT", "multiple_select"),
        ("TRUE_FALSE", "true_false"),
        ("SHORT_ANSWER", "short_answer"),
        ("CODE", "code"),
        ("FILL_BLANK", "fill_blank"),
    ],
    "quizdifficulty": [
        ("EASY", "easy"),
        ("MEDIUM", "medium"),
        ("HARD", "hard"),
        ("EXPERT", "expert"),
    ],
}


def upgrade() -> None:
    for enum_type, renames in ENUM_RENAMES.items():
        for old_val, new_val in renames:
            # Check if the old (uppercase) value exists before renaming
            # This makes the migration idempotent (safe to run on DBs already fixed)
            op.execute(
                f"""
                DO $$
                BEGIN
                    IF EXISTS (
                        SELECT 1 FROM pg_enum
                        WHERE enumtypid = (SELECT oid FROM pg_type WHERE typname = '{enum_type}')
                        AND enumlabel = '{old_val}'
                    ) THEN
                        ALTER TYPE {enum_type} RENAME VALUE '{old_val}' TO '{new_val}';
                    END IF;
                END
                $$;
                """
            )


def downgrade() -> None:
    for enum_type, renames in ENUM_RENAMES.items():
        for old_val, new_val in renames:
            op.execute(
                f"""
                DO $$
                BEGIN
                    IF EXISTS (
                        SELECT 1 FROM pg_enum
                        WHERE enumtypid = (SELECT oid FROM pg_type WHERE typname = '{enum_type}')
                        AND enumlabel = '{new_val}'
                    ) THEN
                        ALTER TYPE {enum_type} RENAME VALUE '{new_val}' TO '{old_val}';
                    END IF;
                END
                $$;
                """
            )
