"""merge_heads

Revision ID: 5f6e55b7e175
Revises: 6f7e8d9c0a1b, f8b6be7f8a0c
Create Date: 2025-12-11 02:14:09.960063

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "5f6e55b7e175"
down_revision: Union[str, None] = ("6f7e8d9c0a1b", "f8b6be7f8a0c")
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
