"""v1.10 Add achievements and XP tracking tables

Revision ID: v1_10_achievements
Revises: v1_9_typing_game
Create Date: 2026-01-15 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from datetime import datetime

# revision identifiers, used by Alembic.
revision = 'v1_10_achievements'
down_revision = 'v1_9_typing_game'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create achievements table
    op.create_table(
        'achievements',
        sa.Column('id', sa.String(100), primary_key=True),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('description', sa.Text, nullable=False),
        sa.Column('icon', sa.String(100), default='trophy'),
        sa.Column('category', sa.String(50), nullable=False, index=True),
        sa.Column('rarity', sa.String(50), default='common'),
        sa.Column('xp_reward', sa.Integer, default=50),
        sa.Column('unlock_condition', sa.JSON, nullable=False),
        sa.Column('is_hidden', sa.Boolean, default=False),
        sa.Column('is_active', sa.Boolean, default=True),
        sa.Column('sort_order', sa.Integer, default=0),
        sa.Column('created_at', sa.DateTime, default=datetime.utcnow),
        sa.Column('updated_at', sa.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow),
    )

    # Create user_achievements table
    op.create_table(
        'user_achievements',
        sa.Column('id', sa.Integer, primary_key=True, index=True),
        sa.Column('user_id', sa.Integer, sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('achievement_id', sa.String(100), sa.ForeignKey('achievements.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('unlocked_at', sa.DateTime, nullable=True),
        sa.Column('progress', sa.Integer, default=0),
        sa.Column('progress_max', sa.Integer, default=1),
        sa.Column('unlock_context', sa.JSON, nullable=True),
        sa.UniqueConstraint('user_id', 'achievement_id', name='uq_user_achievement')
    )

    # Create user_activities table
    op.create_table(
        'user_activities',
        sa.Column('id', sa.Integer, primary_key=True, index=True),
        sa.Column('user_id', sa.Integer, sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('activity_type', sa.String(50), nullable=False, index=True),
        sa.Column('reference_type', sa.String(50), nullable=True),
        sa.Column('reference_id', sa.String(100), nullable=True),
        sa.Column('title', sa.String(300), nullable=True),
        sa.Column('metadata', sa.JSON, nullable=True),
        sa.Column('xp_earned', sa.Integer, default=0),
        sa.Column('created_at', sa.DateTime, default=datetime.utcnow, index=True),
    )

    # Create xp_transactions table
    op.create_table(
        'xp_transactions',
        sa.Column('id', sa.Integer, primary_key=True, index=True),
        sa.Column('user_id', sa.Integer, sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('amount', sa.Integer, nullable=False),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('reason', sa.String(500), nullable=True),
        sa.Column('balance_before', sa.Integer, nullable=False),
        sa.Column('balance_after', sa.Integer, nullable=False),
        sa.Column('level_before', sa.Integer, nullable=False),
        sa.Column('level_after', sa.Integer, nullable=False),
        sa.Column('created_at', sa.DateTime, default=datetime.utcnow, index=True),
    )

    # Create level_config table
    op.create_table(
        'level_config',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('level', sa.Integer, unique=True, nullable=False),
        sa.Column('xp_required', sa.Integer, nullable=False),
        sa.Column('title', sa.String(100), nullable=True),
        sa.Column('badge_color', sa.String(50), nullable=True),
        sa.Column('perks', sa.JSON, nullable=True),
        sa.Column('created_at', sa.DateTime, default=datetime.utcnow),
        sa.Column('updated_at', sa.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow),
    )

    # Seed default achievements
    op.execute("""
        INSERT INTO achievements (id, name, description, icon, category, rarity, xp_reward, unlock_condition, sort_order) VALUES
        -- Tutorial achievements
        ('first_tutorial', 'First Steps', 'Complete your first tutorial', 'book-open', 'tutorials', 'common', 50, '{"type": "count", "action": "tutorial_complete", "count": 1}', 1),
        ('tutorial_explorer', 'Tutorial Explorer', 'Complete 5 tutorials', 'compass', 'tutorials', 'uncommon', 100, '{"type": "count", "action": "tutorial_complete", "count": 5}', 2),
        ('tutorial_master', 'Tutorial Master', 'Complete 25 tutorials', 'graduation-cap', 'tutorials', 'rare', 250, '{"type": "count", "action": "tutorial_complete", "count": 25}', 3),
        ('tutorial_legend', 'Tutorial Legend', 'Complete 100 tutorials', 'crown', 'tutorials', 'legendary', 1000, '{"type": "count", "action": "tutorial_complete", "count": 100}', 4),

        -- Typing achievements
        ('first_game', 'Keyboard Warrior', 'Complete your first typing game', 'keyboard', 'typing', 'common', 50, '{"type": "count", "action": "typing_game_complete", "count": 1}', 10),
        ('speed_demon_50', 'Speed Demon', 'Reach 50 WPM in a typing game', 'zap', 'typing', 'common', 75, '{"type": "value", "metric": "wpm", "operator": ">=", "value": 50}', 11),
        ('speed_demon_80', 'Lightning Fingers', 'Reach 80 WPM in a typing game', 'zap', 'typing', 'uncommon', 150, '{"type": "value", "metric": "wpm", "operator": ">=", "value": 80}', 12),
        ('speed_demon_100', 'Typing Prodigy', 'Reach 100 WPM in a typing game', 'flame', 'typing', 'rare', 300, '{"type": "value", "metric": "wpm", "operator": ">=", "value": 100}', 13),
        ('perfect_accuracy', 'Perfectionist', 'Complete a game with 100% accuracy', 'target', 'typing', 'uncommon', 100, '{"type": "value", "metric": "accuracy", "operator": ">=", "value": 100}', 14),
        ('typing_marathon', 'Marathon Typist', 'Complete 50 typing games', 'trophy', 'typing', 'rare', 200, '{"type": "count", "action": "typing_game_complete", "count": 50}', 15),

        -- Streak achievements
        ('streak_3', 'Getting Started', 'Maintain a 3-day streak', 'flame', 'streak', 'common', 30, '{"type": "streak", "days": 3}', 20),
        ('streak_7', 'Weekly Warrior', 'Maintain a 7-day streak', 'flame', 'streak', 'uncommon', 75, '{"type": "streak", "days": 7}', 21),
        ('streak_30', 'Monthly Master', 'Maintain a 30-day streak', 'flame', 'streak', 'rare', 250, '{"type": "streak", "days": 30}', 22),
        ('streak_100', 'Century Club', 'Maintain a 100-day streak', 'medal', 'streak', 'epic', 500, '{"type": "streak", "days": 100}', 23),
        ('streak_365', 'Year of Dedication', 'Maintain a 365-day streak', 'crown', 'streak', 'legendary', 2000, '{"type": "streak", "days": 365}', 24),

        -- Special achievements
        ('early_adopter', 'Early Adopter', 'Join during the beta period', 'sparkles', 'special', 'epic', 100, '{"type": "special", "trigger": "manual"}', 100),
        ('level_10', 'Rising Star', 'Reach level 10', 'star', 'special', 'uncommon', 100, '{"type": "value", "metric": "level", "operator": ">=", "value": 10}', 101),
        ('level_25', 'Seasoned Learner', 'Reach level 25', 'award', 'special', 'rare', 250, '{"type": "value", "metric": "level", "operator": ">=", "value": 25}', 102),
        ('level_50', 'Knowledge Seeker', 'Reach level 50', 'medal', 'special', 'epic', 500, '{"type": "value", "metric": "level", "operator": ">=", "value": 50}', 103)
    """)

    # Seed default level configurations
    op.execute("""
        INSERT INTO level_config (level, xp_required, title, badge_color) VALUES
        (1, 0, 'Newcomer', 'gray'),
        (5, 500, 'Beginner', 'green'),
        (10, 1500, 'Learner', 'blue'),
        (15, 3500, 'Student', 'indigo'),
        (20, 6500, 'Apprentice', 'purple'),
        (25, 10500, 'Journeyman', 'pink'),
        (30, 16000, 'Adept', 'orange'),
        (40, 30000, 'Expert', 'red'),
        (50, 50000, 'Master', 'yellow'),
        (75, 100000, 'Grandmaster', 'amber'),
        (100, 200000, 'Legend', 'gold')
    """)


def downgrade() -> None:
    op.drop_table('level_config')
    op.drop_table('xp_transactions')
    op.drop_table('user_activities')
    op.drop_table('user_achievements')
    op.drop_table('achievements')
