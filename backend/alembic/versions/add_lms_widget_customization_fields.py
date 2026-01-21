"""Add LMS widget customization fields to site_settings

Revision ID: a8e2f3c4d5b6
Revises: 1157aee21645
Create Date: 2026-01-21

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a8e2f3c4d5b6'
down_revision = '1157aee21645'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # LMS Widget Customization - Featured Courses
    op.add_column('site_settings', sa.Column('featured_courses_title', sa.String(200), nullable=False, server_default='Featured Courses'))
    op.add_column('site_settings', sa.Column('featured_courses_subtitle', sa.String(500), nullable=True))
    op.add_column('site_settings', sa.Column('featured_courses_limit', sa.Integer(), nullable=False, server_default='4'))

    # LMS Widget Customization - Typing Challenge
    op.add_column('site_settings', sa.Column('typing_challenge_title', sa.String(200), nullable=False, server_default='Test Your Typing Speed'))
    op.add_column('site_settings', sa.Column('typing_challenge_show_stats', sa.Boolean(), nullable=False, server_default='true'))
    op.add_column('site_settings', sa.Column('typing_challenge_show_pvp', sa.Boolean(), nullable=False, server_default='true'))

    # LMS Widget Customization - Quick Quiz
    op.add_column('site_settings', sa.Column('quick_quiz_title', sa.String(200), nullable=False, server_default='Quick Quiz'))
    op.add_column('site_settings', sa.Column('quick_quiz_subtitle', sa.String(500), nullable=True))
    op.add_column('site_settings', sa.Column('quick_quiz_limit', sa.Integer(), nullable=False, server_default='4'))

    # LMS Widget Customization - Tutorial Paths
    op.add_column('site_settings', sa.Column('tutorial_paths_title', sa.String(200), nullable=False, server_default='Learning Paths'))
    op.add_column('site_settings', sa.Column('tutorial_paths_subtitle', sa.String(500), nullable=True))
    op.add_column('site_settings', sa.Column('tutorial_paths_categories_limit', sa.Integer(), nullable=False, server_default='4'))

    # LMS Widget Customization - Leaderboard
    op.add_column('site_settings', sa.Column('leaderboard_title', sa.String(200), nullable=False, server_default='Top Learners'))
    op.add_column('site_settings', sa.Column('leaderboard_limit', sa.Integer(), nullable=False, server_default='5'))
    op.add_column('site_settings', sa.Column('leaderboard_show_streak', sa.Boolean(), nullable=False, server_default='true'))

    # LMS Widget Customization - Daily Challenges
    op.add_column('site_settings', sa.Column('daily_challenge_guest_message', sa.String(500), nullable=True))
    op.add_column('site_settings', sa.Column('daily_challenge_show_streak', sa.Boolean(), nullable=False, server_default='true'))

    # LMS Widget Customization - Homepage Stats
    op.add_column('site_settings', sa.Column('homepage_stats_title', sa.String(200), nullable=False, server_default='Community Progress'))
    op.add_column('site_settings', sa.Column('homepage_stats_show_active_today', sa.Boolean(), nullable=False, server_default='true'))

    # Homepage Section Titles (for carousel, categories, recent posts)
    op.add_column('site_settings', sa.Column('carousel_title', sa.String(200), nullable=False, server_default='Featured Articles'))
    op.add_column('site_settings', sa.Column('carousel_subtitle', sa.String(500), nullable=True))
    op.add_column('site_settings', sa.Column('categories_title', sa.String(200), nullable=False, server_default='Explore by Category'))
    op.add_column('site_settings', sa.Column('categories_subtitle', sa.String(500), nullable=True))
    op.add_column('site_settings', sa.Column('recent_posts_title', sa.String(200), nullable=False, server_default='Latest Posts'))
    op.add_column('site_settings', sa.Column('recent_posts_subtitle', sa.String(500), nullable=True))

    # Homepage Section Order (JSON array)
    op.add_column('site_settings', sa.Column('homepage_section_order', sa.JSON(), nullable=True))


def downgrade() -> None:
    # LMS Widget Customization - Featured Courses
    op.drop_column('site_settings', 'featured_courses_title')
    op.drop_column('site_settings', 'featured_courses_subtitle')
    op.drop_column('site_settings', 'featured_courses_limit')

    # LMS Widget Customization - Typing Challenge
    op.drop_column('site_settings', 'typing_challenge_title')
    op.drop_column('site_settings', 'typing_challenge_show_stats')
    op.drop_column('site_settings', 'typing_challenge_show_pvp')

    # LMS Widget Customization - Quick Quiz
    op.drop_column('site_settings', 'quick_quiz_title')
    op.drop_column('site_settings', 'quick_quiz_subtitle')
    op.drop_column('site_settings', 'quick_quiz_limit')

    # LMS Widget Customization - Tutorial Paths
    op.drop_column('site_settings', 'tutorial_paths_title')
    op.drop_column('site_settings', 'tutorial_paths_subtitle')
    op.drop_column('site_settings', 'tutorial_paths_categories_limit')

    # LMS Widget Customization - Leaderboard
    op.drop_column('site_settings', 'leaderboard_title')
    op.drop_column('site_settings', 'leaderboard_limit')
    op.drop_column('site_settings', 'leaderboard_show_streak')

    # LMS Widget Customization - Daily Challenges
    op.drop_column('site_settings', 'daily_challenge_guest_message')
    op.drop_column('site_settings', 'daily_challenge_show_streak')

    # LMS Widget Customization - Homepage Stats
    op.drop_column('site_settings', 'homepage_stats_title')
    op.drop_column('site_settings', 'homepage_stats_show_active_today')

    # Homepage Section Titles
    op.drop_column('site_settings', 'carousel_title')
    op.drop_column('site_settings', 'carousel_subtitle')
    op.drop_column('site_settings', 'categories_title')
    op.drop_column('site_settings', 'categories_subtitle')
    op.drop_column('site_settings', 'recent_posts_title')
    op.drop_column('site_settings', 'recent_posts_subtitle')

    # Homepage Section Order
    op.drop_column('site_settings', 'homepage_section_order')
