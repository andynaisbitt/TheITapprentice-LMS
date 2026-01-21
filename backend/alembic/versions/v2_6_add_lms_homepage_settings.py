"""Add LMS homepage visibility settings

Revision ID: v2_6_add_lms_homepage_settings
Revises: v2_5_add_daily_challenges
Create Date: 2026-01-21

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'v2_6_add_lms_homepage_settings'
down_revision = 'v2_5_add_daily_challenges'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add LMS homepage section visibility columns to site_settings
    op.add_column('site_settings', sa.Column('show_featured_courses', sa.Boolean(), nullable=False, server_default='true'))
    op.add_column('site_settings', sa.Column('show_typing_challenge', sa.Boolean(), nullable=False, server_default='true'))
    op.add_column('site_settings', sa.Column('show_quick_quiz', sa.Boolean(), nullable=False, server_default='true'))
    op.add_column('site_settings', sa.Column('show_tutorial_paths', sa.Boolean(), nullable=False, server_default='true'))
    op.add_column('site_settings', sa.Column('show_leaderboard_preview', sa.Boolean(), nullable=False, server_default='true'))
    op.add_column('site_settings', sa.Column('show_daily_challenge_banner', sa.Boolean(), nullable=False, server_default='true'))
    op.add_column('site_settings', sa.Column('show_homepage_stats', sa.Boolean(), nullable=False, server_default='true'))


def downgrade() -> None:
    op.drop_column('site_settings', 'show_homepage_stats')
    op.drop_column('site_settings', 'show_daily_challenge_banner')
    op.drop_column('site_settings', 'show_leaderboard_preview')
    op.drop_column('site_settings', 'show_tutorial_paths')
    op.drop_column('site_settings', 'show_quick_quiz')
    op.drop_column('site_settings', 'show_typing_challenge')
    op.drop_column('site_settings', 'show_featured_courses')
