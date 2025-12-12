"""remove_stats_defaults_allow_disable

Revision ID: 486b10205e55
Revises: 08038c92d6b9
Create Date: 2025-12-08 01:57:06.813406

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "486b10205e55"
down_revision: Union[str, None] = "08038c92d6b9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Remove server defaults from stats fields so they can be fully disabled
    op.alter_column('site_settings', 'stats_free', server_default=None)

    # Update any existing rows that have "100% Free" to NULL/empty string
    # This allows users to completely disable stats
    op.execute("UPDATE site_settings SET stats_free = NULL WHERE stats_free = '100% Free'")


def downgrade() -> None:
    # Restore the default if needed
    op.alter_column('site_settings', 'stats_free', server_default='100% Free')
