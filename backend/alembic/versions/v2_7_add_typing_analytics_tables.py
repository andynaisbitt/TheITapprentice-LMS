"""Add typing game analytics, streaks, and daily challenges tables

Revision ID: v2_7_typing_analytics
Revises: a8e2f3c4d5b6
Create Date: 2026-01-25

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'v2_7_typing_analytics'
down_revision = 'a8e2f3c4d5b6'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # User Letter Stats - Per-character accuracy tracking
    op.create_table(
        'user_letter_stats',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('character', sa.String(5), nullable=False),
        sa.Column('total_attempts', sa.Integer(), default=0, nullable=False),
        sa.Column('total_correct', sa.Integer(), default=0, nullable=False),
        sa.Column('total_incorrect', sa.Integer(), default=0, nullable=False),
        sa.Column('accuracy_rate', sa.Float(), default=0.0, nullable=False),
        sa.Column('avg_time_to_type', sa.Float(), default=0.0, nullable=False),
        sa.Column('min_time_to_type', sa.Float(), nullable=True),
        sa.Column('max_time_to_type', sa.Float(), nullable=True),
        sa.Column('context_stats', sa.JSON(), default=dict, nullable=True),
        sa.Column('common_mistakes', sa.JSON(), default=list, nullable=True),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'character', name='uq_user_letter')
    )
    op.create_index('ix_user_letter_stats_user_id', 'user_letter_stats', ['user_id'])
    op.create_index('ix_user_letter_stats_character', 'user_letter_stats', ['character'])

    # User Pattern Stats - Digraph/trigraph tracking
    op.create_table(
        'user_pattern_stats',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('pattern', sa.String(10), nullable=False),
        sa.Column('total_attempts', sa.Integer(), default=0, nullable=False),
        sa.Column('total_correct', sa.Integer(), default=0, nullable=False),
        sa.Column('accuracy_rate', sa.Float(), default=0.0, nullable=False),
        sa.Column('avg_time_ms', sa.Float(), default=0.0, nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'pattern', name='uq_user_pattern')
    )
    op.create_index('ix_user_pattern_stats_user_id', 'user_pattern_stats', ['user_id'])
    op.create_index('ix_user_pattern_stats_pattern', 'user_pattern_stats', ['pattern'])

    # Typing Session Analytics - Detailed per-session data
    op.create_table(
        'typing_session_analytics',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('session_id', sa.String(36), nullable=False),
        sa.Column('wpm_timeline', sa.JSON(), default=list, nullable=True),
        sa.Column('error_positions', sa.JSON(), default=list, nullable=True),
        sa.Column('error_heatmap', sa.JSON(), default=dict, nullable=True),
        sa.Column('keystroke_intervals', sa.JSON(), default=list, nullable=True),
        sa.Column('avg_inter_key_time', sa.Float(), default=0.0, nullable=False),
        sa.Column('std_dev_inter_key_time', sa.Float(), default=0.0, nullable=False),
        sa.Column('slowest_words', sa.JSON(), default=list, nullable=True),
        sa.Column('fastest_words', sa.JSON(), default=list, nullable=True),
        sa.Column('confidence_score', sa.Float(), default=1.0, nullable=False),
        sa.Column('anti_cheat_flags', sa.JSON(), default=list, nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['session_id'], ['typing_game_sessions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('session_id', name='uq_session_analytics')
    )

    # User Typing Streaks
    op.create_table(
        'user_typing_streaks',
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('current_streak', sa.Integer(), default=0, nullable=False),
        sa.Column('longest_streak', sa.Integer(), default=0, nullable=False),
        sa.Column('last_play_date', sa.Date(), nullable=True),
        sa.Column('freeze_available', sa.Boolean(), default=True, nullable=False),
        sa.Column('last_freeze_used', sa.Date(), nullable=True),
        sa.Column('first_game_today', sa.Boolean(), default=True, nullable=False),
        sa.Column('games_today', sa.Integer(), default=0, nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('user_id')
    )

    # Typing Daily Challenges
    op.create_table(
        'typing_daily_challenges',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('challenge_date', sa.Date(), nullable=False),
        sa.Column('challenge_type', sa.String(50), nullable=False),
        sa.Column('target_value', sa.Integer(), nullable=False),
        sa.Column('difficulty', sa.String(20), nullable=False),
        sa.Column('xp_reward', sa.Integer(), nullable=False),
        sa.Column('bonus_text', sa.String(200), nullable=True),
        sa.Column('is_active', sa.Boolean(), default=True, nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_typing_daily_challenges_date', 'typing_daily_challenges', ['challenge_date'])

    # User Typing Challenge Progress
    op.create_table(
        'user_typing_challenge_progress',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('challenge_id', sa.String(36), nullable=False),
        sa.Column('current_value', sa.Integer(), default=0, nullable=False),
        sa.Column('is_completed', sa.Boolean(), default=False, nullable=False),
        sa.Column('is_claimed', sa.Boolean(), default=False, nullable=False),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('claimed_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['challenge_id'], ['typing_daily_challenges.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'challenge_id', name='uq_user_challenge')
    )
    op.create_index('ix_user_challenge_progress_user', 'user_typing_challenge_progress', ['user_id'])

    # Add new columns to typing_game_sessions if they don't exist
    # Note: These may already exist from earlier changes, so we use batch_alter_table with try/except pattern
    try:
        op.add_column('typing_game_sessions', sa.Column('max_combo', sa.Integer(), default=0, nullable=True))
    except Exception:
        pass  # Column may already exist

    try:
        op.add_column('typing_game_sessions', sa.Column('anti_cheat_confidence', sa.Float(), default=1.0, nullable=True))
    except Exception:
        pass

    try:
        op.add_column('typing_game_sessions', sa.Column('anti_cheat_flags', sa.JSON(), default=list, nullable=True))
    except Exception:
        pass

    try:
        op.add_column('typing_game_sessions', sa.Column('anti_cheat_flagged_for_review', sa.Boolean(), default=False, nullable=True))
    except Exception:
        pass


def downgrade() -> None:
    # Drop tables in reverse order
    op.drop_table('user_typing_challenge_progress')
    op.drop_table('typing_daily_challenges')
    op.drop_table('user_typing_streaks')
    op.drop_table('typing_session_analytics')
    op.drop_table('user_pattern_stats')
    op.drop_table('user_letter_stats')

    # Remove columns from typing_game_sessions
    try:
        op.drop_column('typing_game_sessions', 'max_combo')
        op.drop_column('typing_game_sessions', 'anti_cheat_confidence')
        op.drop_column('typing_game_sessions', 'anti_cheat_flags')
        op.drop_column('typing_game_sessions', 'anti_cheat_flagged_for_review')
    except Exception:
        pass
