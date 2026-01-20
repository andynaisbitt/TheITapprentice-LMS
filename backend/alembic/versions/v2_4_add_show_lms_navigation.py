"""Add show_lms_navigation to site_settings

Revision ID: v2_4_lms_nav
Revises: v2_3_merge_heads
Create Date: 2026-01-20

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'v2_4_lms_nav'
down_revision = 'v2_3_merge_heads'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add show_lms_navigation column to site_settings
    op.add_column(
        'site_settings',
        sa.Column('show_lms_navigation', sa.Boolean(), nullable=False, server_default='true')
    )


def downgrade() -> None:
    op.drop_column('site_settings', 'show_lms_navigation')
