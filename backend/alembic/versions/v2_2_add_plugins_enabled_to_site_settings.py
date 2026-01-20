"""v2.2 Add plugins_enabled column to site_settings

Revision ID: v2_2_add_plugins_enabled_to_site_settings
Revises: v2_1_add_quizzes_plugin_tables
Create Date: 2026-01-20

This migration adds the plugins_enabled JSON column to site_settings
to allow dynamic plugin management via admin panel.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "v2_2_plugins_enabled"
down_revision: Union[str, None] = "v2_1_quizzes"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add plugins_enabled JSON column to site_settings"""
    op.add_column(
        'site_settings',
        sa.Column('plugins_enabled', sa.JSON(), nullable=True)
    )


def downgrade() -> None:
    """Remove plugins_enabled column from site_settings"""
    op.drop_column('site_settings', 'plugins_enabled')
