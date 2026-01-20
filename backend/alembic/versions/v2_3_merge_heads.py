"""v2.3 Merge migration heads

Revision ID: v2_3_merge_heads
Revises: v1_10_achievements, v2_2_add_plugins_enabled_to_site_settings
Create Date: 2026-01-20

This migration merges two parallel migration branches:
- v1_10_achievements (XP and achievements system)
- v2_2_add_plugins_enabled_to_site_settings (Quiz system + plugin management)
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "v2_3_merge_heads"
down_revision: Union[str, Sequence[str]] = ("v1_10_achievements", "v2_2_add_plugins_enabled_to_site_settings")
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Merge migration - no schema changes needed"""
    pass


def downgrade() -> None:
    """Merge migration - no schema changes needed"""
    pass
