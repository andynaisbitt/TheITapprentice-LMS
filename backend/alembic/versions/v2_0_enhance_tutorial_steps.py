"""v2.0 Enhance tutorial steps with content blocks and media support

Revision ID: v2_0_enhance_tutorial_steps
Revises: 066a6f56bd8d
Create Date: 2026-01-20

This migration adds new columns to tutorial_steps table to support:
- Multiple content types beyond just code
- Content blocks (like courses)
- Media support (images, videos, diagrams)
- Step types (theory, practice, quiz, etc.)
- Inline quizzes for knowledge checks
- Enhanced hints with type information
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'v2_0_enhance_tutorial_steps'
down_revision = '066a6f56bd8d'
branch_labels = None
depends_on = None


def upgrade():
    # Add new columns to tutorial_steps table

    # Step type classification
    op.add_column('tutorial_steps', sa.Column('step_type', sa.String(20), nullable=True, server_default='theory'))

    # Content blocks (JSON array for flexible content)
    op.add_column('tutorial_steps', sa.Column('content_blocks', sa.JSON(), nullable=True, server_default='[]'))

    # Media support
    op.add_column('tutorial_steps', sa.Column('media_type', sa.String(20), nullable=True, server_default='none'))
    op.add_column('tutorial_steps', sa.Column('media_content', sa.Text(), nullable=True))
    op.add_column('tutorial_steps', sa.Column('media_language', sa.String(50), nullable=True))
    op.add_column('tutorial_steps', sa.Column('media_caption', sa.String(500), nullable=True))

    # Quiz question (JSON for inline knowledge checks)
    op.add_column('tutorial_steps', sa.Column('quiz_question', sa.JSON(), nullable=True))

    # Expected action description
    op.add_column('tutorial_steps', sa.Column('expected_action', sa.Text(), nullable=True))

    # Time estimate per step
    op.add_column('tutorial_steps', sa.Column('estimated_minutes', sa.Integer(), nullable=True, server_default='5'))

    # XP reward per step (0 = use default)
    op.add_column('tutorial_steps', sa.Column('xp_reward', sa.Integer(), nullable=True, server_default='0'))

    # Set default values for existing rows
    op.execute("UPDATE tutorial_steps SET step_type = 'theory' WHERE step_type IS NULL")
    op.execute("UPDATE tutorial_steps SET media_type = 'none' WHERE media_type IS NULL")
    op.execute("UPDATE tutorial_steps SET estimated_minutes = 5 WHERE estimated_minutes IS NULL")
    op.execute("UPDATE tutorial_steps SET xp_reward = 0 WHERE xp_reward IS NULL")

    # Migrate existing code_example to media fields for backward compatibility
    op.execute("""
        UPDATE tutorial_steps
        SET media_type = 'code',
            media_content = code_example,
            media_language = code_language
        WHERE code_example IS NOT NULL AND code_example != ''
    """)


def downgrade():
    # Remove all the new columns
    op.drop_column('tutorial_steps', 'xp_reward')
    op.drop_column('tutorial_steps', 'estimated_minutes')
    op.drop_column('tutorial_steps', 'expected_action')
    op.drop_column('tutorial_steps', 'quiz_question')
    op.drop_column('tutorial_steps', 'media_caption')
    op.drop_column('tutorial_steps', 'media_language')
    op.drop_column('tutorial_steps', 'media_content')
    op.drop_column('tutorial_steps', 'media_type')
    op.drop_column('tutorial_steps', 'content_blocks')
    op.drop_column('tutorial_steps', 'step_type')
