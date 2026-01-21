"""v2.5 Add daily challenges system

Revision ID: v2_5_daily_challenges
Revises: v2_4_lms_nav
Create Date: 2026-01-21 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from datetime import datetime
import uuid

# revision identifiers, used by Alembic.
revision = 'v2_5_daily_challenges'
down_revision = 'v2_4_lms_nav'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create daily_challenge_templates table
    op.create_table(
        'daily_challenge_templates',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text, nullable=True),
        sa.Column('challenge_type', sa.String(50), nullable=False, index=True),
        sa.Column('difficulty', sa.String(20), nullable=False, index=True),
        sa.Column('target_count', sa.Integer, nullable=False, default=1),
        sa.Column('base_xp_reward', sa.Integer, nullable=False, default=50),
        sa.Column('icon', sa.String(50), default='target'),
        sa.Column('is_active', sa.Boolean, default=True, index=True),
        sa.Column('created_at', sa.DateTime, default=datetime.utcnow),
        sa.Column('updated_at', sa.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow),
    )

    # Create daily_challenges table
    op.create_table(
        'daily_challenges',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('template_id', sa.String(36), sa.ForeignKey('daily_challenge_templates.id', ondelete='SET NULL'), nullable=True),
        sa.Column('challenge_date', sa.DateTime, nullable=False, index=True),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text, nullable=True),
        sa.Column('challenge_type', sa.String(50), nullable=False),
        sa.Column('difficulty', sa.String(20), nullable=False),
        sa.Column('target_count', sa.Integer, nullable=False),
        sa.Column('xp_reward', sa.Integer, nullable=False),
        sa.Column('icon', sa.String(50), default='target'),
        sa.Column('created_at', sa.DateTime, default=datetime.utcnow),
        sa.UniqueConstraint('template_id', 'challenge_date', name='uq_template_date')
    )

    # Create user_challenge_progress table
    op.create_table(
        'user_challenge_progress',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('user_id', sa.Integer, sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('challenge_id', sa.String(36), sa.ForeignKey('daily_challenges.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('current_progress', sa.Integer, default=0),
        sa.Column('is_completed', sa.Boolean, default=False, index=True),
        sa.Column('is_claimed', sa.Boolean, default=False),
        sa.Column('completed_at', sa.DateTime, nullable=True),
        sa.Column('claimed_at', sa.DateTime, nullable=True),
        sa.Column('xp_earned', sa.Integer, default=0),
        sa.Column('streak_bonus_percent', sa.Integer, default=0),
        sa.Column('created_at', sa.DateTime, default=datetime.utcnow),
        sa.Column('updated_at', sa.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow),
        sa.UniqueConstraint('user_id', 'challenge_id', name='uq_user_challenge')
    )

    # Create user_challenge_streaks table
    op.create_table(
        'user_challenge_streaks',
        sa.Column('id', sa.Integer, primary_key=True, index=True),
        sa.Column('user_id', sa.Integer, sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, unique=True, index=True),
        sa.Column('current_streak', sa.Integer, default=0),
        sa.Column('longest_streak', sa.Integer, default=0),
        sa.Column('last_completion_date', sa.DateTime, nullable=True),
        sa.Column('freeze_tokens', sa.Integer, default=2),
        sa.Column('freeze_tokens_used', sa.Integer, default=0),
        sa.Column('last_freeze_used', sa.DateTime, nullable=True),
        sa.Column('streak_protected_until', sa.DateTime, nullable=True),
        sa.Column('created_at', sa.DateTime, default=datetime.utcnow),
        sa.Column('updated_at', sa.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow),
    )

    # Seed default challenge templates
    # Generate UUIDs for the templates
    templates = [
        # EASY challenges (25-50 XP)
        (str(uuid.uuid4()), 'Complete a Quiz', 'Test your knowledge by completing any quiz', 'quiz', 'easy', 1, 30, 'brain'),
        (str(uuid.uuid4()), 'Finish a Tutorial Step', 'Make progress by completing a tutorial step', 'tutorial', 'easy', 1, 25, 'book-open'),
        (str(uuid.uuid4()), 'Play a Typing Game', 'Practice your typing with a quick game', 'typing_game', 'easy', 1, 25, 'keyboard'),
        (str(uuid.uuid4()), 'Earn 50 XP', 'Earn XP from any learning activity', 'xp_earn', 'easy', 50, 30, 'zap'),

        # MEDIUM challenges (50-100 XP)
        (str(uuid.uuid4()), 'Complete 2 Quizzes', 'Demonstrate your knowledge across multiple topics', 'quiz', 'medium', 2, 60, 'brain'),
        (str(uuid.uuid4()), 'Finish a Tutorial', 'Complete an entire tutorial from start to finish', 'tutorial', 'medium', 1, 75, 'graduation-cap'),
        (str(uuid.uuid4()), 'Complete 3 Typing Games', 'Build your typing speed with multiple sessions', 'typing_game', 'medium', 3, 60, 'keyboard'),
        (str(uuid.uuid4()), 'Reach 50 WPM', 'Achieve a typing speed of at least 50 WPM', 'typing_wpm', 'medium', 50, 75, 'zap'),
        (str(uuid.uuid4()), 'Earn 150 XP', 'Earn XP through various learning activities', 'xp_earn', 'medium', 150, 60, 'trophy'),
        (str(uuid.uuid4()), 'Complete a Course Lesson', 'Make progress in any course', 'course_section', 'medium', 1, 65, 'book'),

        # HARD challenges (100-200 XP)
        (str(uuid.uuid4()), 'Complete 3 Quizzes', 'Master multiple subjects with quiz completions', 'quiz', 'hard', 3, 120, 'brain'),
        (str(uuid.uuid4()), 'Finish 2 Tutorials', 'Complete multiple tutorials in a single day', 'tutorial', 'hard', 2, 150, 'graduation-cap'),
        (str(uuid.uuid4()), 'Complete 5 Typing Games', 'Intensive typing practice session', 'typing_game', 'hard', 5, 120, 'keyboard'),
        (str(uuid.uuid4()), 'Reach 80 WPM', 'Achieve advanced typing speed', 'typing_wpm', 'hard', 80, 150, 'flame'),
        (str(uuid.uuid4()), 'Earn 300 XP', 'Major learning accomplishment', 'xp_earn', 'hard', 300, 120, 'crown'),
        (str(uuid.uuid4()), 'Complete 3 Course Lessons', 'Make significant course progress', 'course_section', 'hard', 3, 130, 'book'),
    ]

    for template in templates:
        op.execute(f"""
            INSERT INTO daily_challenge_templates
            (id, title, description, challenge_type, difficulty, target_count, base_xp_reward, icon, is_active)
            VALUES ('{template[0]}', '{template[1]}', '{template[2]}', '{template[3]}', '{template[4]}',
                    {template[5]}, {template[6]}, '{template[7]}', true)
        """)


def downgrade() -> None:
    op.drop_table('user_challenge_streaks')
    op.drop_table('user_challenge_progress')
    op.drop_table('daily_challenges')
    op.drop_table('daily_challenge_templates')
